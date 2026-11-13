"""Invented-only worker fixtures; all ClickHouse access is replaced by SQLite."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'api'))
import conversations
import parsing
import research
from sanitise import HoldError, Policy, Sanitizer, canonical
from test_research_poc import policy_data


class Interrupted(BaseException):
    pass


class FixtureStore:
    """Run worker SELECTs locally, with ReplacingMergeTree keys emulated on insert."""
    KEYS = {
        'records': 'id', 'research_members': 'revision_id,source_seq,record_id',
        'research_processing': 'revision_id,record_id',
        'research_events': 'revision_id,source_seq,event_index,event_id',
        'research_identity_records': 'revision_id,source_seq,record_id',
        'research_response_ids': 'revision_id,response_ref,record_id',
        'research_request_ids': 'revision_id,request_id,record_id',
        'research_conversation_labels_v2': 'revision_id,run_id,response_ref',
        'research_attempts': 'revision_id,record_id,retry_epoch,attempt',
    }

    def __init__(self):
        self.sql = sqlite3.connect(':memory:')
        self.sql.row_factory = sqlite3.Row
        self.tables = set()
        self.checkpoints = {}
        self.fail_table = None
        self.fail_checkpoint = False
        self.queries = []
        self.insert('research_processing', [{'revision_id': '', 'record_id': '', 'pipeline_id': '',
                    'observation_ref': '', 'status': 'pending', 'failure_class': '', 'event_count': 0,
                    'attempt_count': 0, 'retry_epoch': 0, 'updated_at': '', 'version': 0}])
        self.sql.execute('DELETE FROM research_processing')

    def insert(self, table, rows):
        for row in rows:
            if table not in self.tables:
                columns = ','.join(key + (' INTEGER' if isinstance(value, int) else ' TEXT')
                                   for key, value in row.items())
                self.sql.execute('CREATE TABLE ' + table + '(' + columns + ',PRIMARY KEY(' + self.KEYS[table] + '))')
                self.tables.add(table)
            self.sql.execute('INSERT OR REPLACE INTO ' + table + '(' + ','.join(row) + ') VALUES(' +
                             ','.join('?' for _ in row) + ')', tuple(row.values()))
        if rows and table == self.fail_table:
            self.fail_table = None
            raise Interrupted()  # write acknowledged, checkpoint not advanced

    def rows(self, query):
        self.queries.append(query)
        if 'research_identity_records FINAL' in query:
            assert 'LIMIT 1' in query and '(source_seq,record_id)>' in query
        if 'research_response_ids FINAL' in query:
            assert 'response_ref=' in query and 'revision_id=' in query and 'LIMIT 2' in query
        if 'research_conversation_labels_v2 FINAL' in query:
            assert 'response_ref=' in query and 'revision_id=' in query and 'run_id=' in query and 'LIMIT 1' in query
        if 'research_request_ids FINAL' in query:
            assert 'request_id=' in query and 'revision_id=' in query and 'LIMIT 3' in query
        tables = re.findall(r'(?:FROM|JOIN) ([a-z_][a-z0-9_]*)', query)
        if any(table not in self.tables for table in tables):
            return []
        query = query.split(' SETTINGS ')[0].replace(' FINAL', '').replace(' PREWHERE ', ' WHERE ')
        return [dict(row) for row in self.sql.execute(query)]

    def checkpoint(self, key, value=None):
        if value is not None:
            self.checkpoints[key] = json.loads(json.dumps(value))
            if self.fail_checkpoint:
                self.fail_checkpoint = False
                raise Interrupted()
        return json.loads(json.dumps(self.checkpoints.get(key)))


def response(identifier, previous=None, session=None):
    body = {'id': identifier, 'object': 'response', 'output': [
        {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': 'Invented reply.'}]}]}
    if previous:
        body['previous_response_id'] = previous
    if session:
        body['session_id'] = session
    return {'type': 'response', 'user_id': 1, 'body': json.dumps(body)}


def variant(identifier, text, previous=None, session=None):
    """Same provider response ID, different invented content: a second observation."""
    body = {'id': identifier, 'object': 'response', 'output': [
        {'type': 'message', 'role': 'assistant', 'content': [{'type': 'output_text', 'text': text}]}]}
    if previous:
        body['previous_response_id'] = previous
    if session:
        body['session_id'] = session
    return {'type': 'response', 'user_id': 1, 'body': json.dumps(body)}


class ConversationIdentityTests(unittest.TestCase):
    def setUp(self):
        self.store = FixtureStore()
        self.addCleanup(self.store.sql.close)
        self.policy = Policy(policy_data(), b'k' * 48)
        self.revision = {'revision_id': 'rev_' + 'a' * 32, 'schema_version': research.SCHEMA_VERSION,
                         'selection_max_seq': 100, 'config_json': '{}'}
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        config = SimpleNamespace(sanitisation_available=True, identity_enabled=True,
                                 sanitiser=lambda: Sanitizer(self.policy))
        self.stack.enter_context(mock.patch.object(research, 'ResearchConfig', return_value=config))
        self.stack.enter_context(mock.patch.object(research, '_worker_revision', side_effect=lambda *args: dict(self.revision)))
        self.stack.enter_context(mock.patch.object(research, '_checkpoint', side_effect=self.store.checkpoint))
        self.finalise = self.stack.enter_context(mock.patch.object(research, '_finalise', return_value={'status': 'finalised'}))
        self.stack.enter_context(mock.patch.object(research.db, 'rows', side_effect=self.store.rows))
        self.stack.enter_context(mock.patch.object(research.db, 'insert', side_effect=self.store.insert))
        self.stack.enter_context(mock.patch.object(research.db, 'execute', side_effect=AssertionError('No network')))

    def add(self, records):
        ids = []
        for seq, record in enumerate(records, 1):
            raw = json.dumps(record, sort_keys=True)
            identifier = hashlib.sha256(('source:' + str(seq) + raw).encode()).hexdigest()
            digest = hashlib.sha256(raw.encode()).hexdigest()
            self.store.insert('records', [{'id': identifier, 'seq': seq, 'event_id': 'gateway-' + str(seq),
                              'user_id': record.get('user_id', 1), 'timestamp': 1, 'type': record['type'],
                              'request_id': record.get('request_id', 'same-gateway'), 'endpoint': '/invented',
                              'content_sha256': digest, 'record_json': raw}])
            self.store.insert('research_members', [{'revision_id': self.revision['revision_id'],
                              'record_id': identifier, 'source_seq': seq, 'content_sha256': digest}])
            ids.append(identifier)
        return ids

    def run_worker(self, limit=250):
        for _ in range(limit):
            result = research.process_once({}, page_size=1)
            if result['status'] == 'finalised':
                return
        self.fail('Identity passes did not converge')

    def refs(self, ids):
        values = []
        for identifier in ids:
            rows = self.store.rows("SELECT conversation_ref FROM research_events FINAL WHERE revision_id='" +
                                   self.revision['revision_id'] + "' AND record_id='" + identifier + "'")
            refs = {row['conversation_ref'] for row in rows}
            self.assertEqual(len(refs), 1)
            values.append(refs.pop())
        return values

    def exported(self):
        return [research._export_event(row) for row in self.store.rows(
            "SELECT * FROM research_events FINAL WHERE revision_id='" + self.revision['revision_id'] +
            "' ORDER BY source_seq,event_index,event_id")]

    def test_chain_of_three_activates_one_conversation(self):
        ids = self.add([response('r1'), response('r2', 'r1'), response('r3', 'r2')])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(len(set(refs)), 1)
        self.assertEqual(research.SCHEMA_VERSION, 'research-event/2')
        self.assertTrue(all(event['parser_version'] == parsing.PARSER_VERSION for event in self.exported()))

    def test_out_of_order_matches_ordered_identity(self):
        records = [response('r1'), response('r2', 'r1'), response('r3', 'r2')]
        ids = self.add(list(reversed(records)))
        self.run_worker()
        backwards = self.refs(ids)
        self.assertEqual(len(set(backwards)), 1)
        self.assertTrue(backwards[0])
        # Same revision/key/explicit IDs, with different ingestion sequence.
        for table in self.store.tables:
            self.store.sql.execute('DELETE FROM ' + table)
        self.store.checkpoints.clear()
        ordered = self.add(records)
        self.run_worker()
        self.assertEqual(self.refs(ordered), backwards)

    def test_unknown_links_gateway_ids_text_and_unrelated_records_do_not_merge(self):
        ids = self.add([response('lonely'), response('unresolved', 'absent'), response('another'),
                        {'type': 'request', 'request_id': 'same-gateway', 'user_id': 1,
                         'body': json.dumps({'id': 'lonely', 'messages': [{'role': 'user', 'content': 'Invented reply.'}]})},
                        response('separate', session='invented-session')])
        self.run_worker()
        refs = self.refs(ids)
        self.assertEqual(refs[:4], ['', '', '', ''])
        self.assertTrue(refs[4])

    def test_explicit_session_and_request_previous_response_join(self):
        ids = self.add([response('r1', session='invented-session'), response('r2', 'r1'),
                        {'type': 'request', 'user_id': 1, 'body': json.dumps(
                            {'previous_response_id': 'r2', 'input': 'An invented follow-up.'})}])
        self.run_worker()
        refs = self.refs(ids)
        self.assertEqual(len(set(refs)), 1)
        self.assertTrue(refs[0])

    def test_conflicting_explicit_sessions_stay_distinct(self):
        ids = self.add([response('r3', 'r2'), response('r2', 'r1', 'session-b'),
                        response('r1', session='session-a')])
        self.run_worker()
        refs = self.refs(ids)
        self.assertEqual(refs[0], '')
        self.assertTrue(refs[1] and refs[2])
        self.assertNotEqual(refs[1], refs[2])

    def test_restarts_after_acknowledged_writes_and_replay_are_idempotent(self):
        ids = self.add([response('r3', 'r2'), response('r2', 'r1'), response('r1')])
        self.run_worker()
        baseline = self.exported()
        # Replay from the worker's existing disposition/checkpoint model.
        for fault in ('research_identity_records', 'research_response_ids', 'research_request_ids',
                      'research_processing', 'research_conversation_labels_v2', 'research_events', 'checkpoint'):
            with self.subTest(fault=fault):
                for table in self.store.tables - {'records', 'research_members'}:
                    self.store.sql.execute('DELETE FROM ' + table)
                self.store.checkpoints.clear()
                if fault == 'research_events':
                    for _ in ids:
                        research.process_once({}, page_size=1)
                    for _ in range(250):
                        if self.store.checkpoints['research_worker:' + self.revision['revision_id']].get(
                                'conversation', {}).get('phase') == 'apply':
                            break
                        research.process_once({}, page_size=1)
                    else:
                        self.fail('Did not reach the apply phase')
                if fault == 'checkpoint':
                    self.store.fail_checkpoint = True
                else:
                    self.store.fail_table = fault
                with self.assertRaises(Interrupted):
                    self.run_worker()
                self.run_worker()
                self.assertEqual(self.exported(), baseline)
                self.assertEqual(len(set(self.refs(ids))), 1)

    def test_no_cross_revision_or_user_identity_leakage(self):
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        first = self.refs(ids)[0]
        self.revision['revision_id'] = 'rev_' + 'b' * 32
        ids = self.add([response('r2', 'r1')])
        self.run_worker()
        self.assertEqual(self.refs(ids), [''])
        self.revision['revision_id'] = 'rev_' + 'c' * 32
        other = response('r2', 'r1')
        other['user_id'] = 2
        ids = self.add([response('r1'), other])
        self.run_worker()
        self.assertEqual(self.refs(ids), ['', ''])
        self.revision['revision_id'] = 'rev_' + 'd' * 32
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        self.assertNotEqual(self.refs(ids)[0], first)

    def test_policy_scoped_pseudonyms_do_not_share_response_lookup_state(self):
        self.policy.reference_scope_mode = 'policy'
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        self.assertTrue(self.refs(ids)[0])
        self.revision['revision_id'] = 'rev_' + 'b' * 32
        ids = self.add([response('r2', 'r1')])
        self.run_worker()
        self.assertEqual(self.refs(ids), [''])

    def test_identity_rewrite_space_is_reserved_in_both_byte_budgets(self):
        record = response('isolated')
        clean = Sanitizer(self.policy)
        clean.refs.bind_revision(self.revision['revision_id'])
        parsed = parsing.derive_events(record, clean.refs)
        source = {'id': 'e' * 64, 'seq': 1, 'timestamp': 1, 'content_sha256': 'f' * 64}
        rows, _ = research._event_rows(self.revision, None, source, parsed, clean)
        sizes = [len(canonical(row).encode()) for row in rows]
        for setting, ceiling in [('MAX_EVENT_BYTES', max(sizes)), ('MAX_RECORD_EVENT_BYTES', sum(sizes))]:
            with self.subTest(setting=setting), mock.patch.object(research, setting, ceiling):
                with self.assertRaises(HoldError):
                    research._event_rows(self.revision, None, source, parsed, clean)

    def test_duplicate_response_ids_and_held_sources_do_not_resolve(self):
        ids = self.add([response('duplicate'), response('duplicate'), response('child', 'duplicate')])
        self.run_worker()
        self.assertEqual(self.refs(ids), ['', '', ''])
        # A successfully indexed response from an attempt later held is unavailable.
        row = self.store.rows('SELECT * FROM research_processing LIMIT 1')[0]
        row.update(status='held', pipeline_id='', event_count=0)
        self.store.insert('research_processing', [row])
        entry = self.store.rows('SELECT * FROM research_identity_records LIMIT 1')[0]
        self.assertFalse(conversations.current(entry))

    def test_later_ambiguity_clears_a_previously_applied_conversation(self):
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        self.assertTrue(self.refs(ids)[1].startswith('conv_'))
        # _finalise is mocked here; clear the worker checkpoint it normally resets.
        self.store.checkpoints.clear()
        # A second observation of the same provider response ID makes it
        # ambiguous; the identity already written must be removed, not kept.
        duplicate = response('r1')
        duplicate['body'] = json.dumps({'id': 'r1', 'object': 'response', 'output': [
            {'type': 'message', 'role': 'assistant',
             'content': [{'type': 'output_text', 'text': 'A different invented reply.'}]}]})
        self.add([duplicate])
        self.run_worker()
        self.assertEqual(self.refs(ids), ['', ''])
        for row in self.store.rows('SELECT * FROM research_events'):
            if row['kind'] == 'observation':
                self.assertEqual(row['linkage_status'], 'unknown')

    def test_duplicate_child_unlinks_root_and_child(self):
        # Reviewer reproduction: apply r1 <- r2, then a duplicate r2 makes the
        # child ambiguous. Neither the child nor its isolated root may keep the
        # conversation written by the earlier pass.
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        self.assertTrue(self.refs(ids)[0].startswith('conv_'))
        self.store.checkpoints.clear()
        self.add([variant('r2', 'Ambiguous child reply.', previous='r1')])
        self.run_worker()
        self.assertEqual(self.refs(ids), ['', ''])

    def test_chain_keeps_the_surviving_edge_after_root_ambiguity(self):
        # r1 becomes ambiguous after r1 <- r2 was applied. r1 must unlink, while
        # r2 and r3 keep the still-valid r2 <- r3 edge as one conversation.
        ids = self.add([response('r1'), response('r2', 'r1')])
        self.run_worker()
        self.store.checkpoints.clear()
        more = self.add([variant('r1', 'Ambiguous root reply.'), response('r3', 'r2')])
        self.run_worker()
        refs = self.refs(ids + more)
        self.assertEqual(refs[0], '')
        self.assertEqual(refs[2], '')
        self.assertTrue(refs[1].startswith('conv_'))
        self.assertEqual(refs[1], refs[3])

    def test_ambiguous_session_response_does_not_bridge_to_parent(self):
        # An ambiguous own response that also carries a session ref keeps that
        # session for its own events, but must not link its parent into it.
        ids = self.add([response('r1'), response('r2', 'r1', session='s1')])
        self.run_worker()
        self.store.checkpoints.clear()
        more = self.add([variant('r2', 'Ambiguous child reply.', previous='r1'), response('r3', 'r2')])
        self.run_worker()
        refs = self.refs(ids + more)
        self.assertEqual(refs[0], '')
        self.assertTrue(refs[1].startswith('conv_'))
        self.assertEqual(refs[2], '')
        self.assertEqual(refs[3], '')

    def test_scope_comes_from_the_stored_user_column(self):
        # The response body carries user_id, the request body does not. Both
        # must scope their HMACs by the stored column, or the ids never match.
        first = response('r1')
        request_body = {'type': 'request', 'request_id': 'scope-test',
                        'body': json.dumps({'previous_response_id': 'r1', 'input': 'Invented prompt.'})}
        ids = self.add([first, request_body])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(refs[0], refs[1])

    def test_interaction_header_groups_turns(self):
        first = {'type': 'request', 'user_id': 1, 'request_id': 'q1',
                 'headers': {'X-Interaction-Id': ['iid-1']}, 'body': json.dumps({'input': 'one'})}
        second = {'type': 'request', 'user_id': 1, 'request_id': 'q2',
                  'headers': {'x-interaction-id': ['iid-1']}, 'body': json.dumps({'input': 'two'})}
        ids = self.add([first, second])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(refs[0], refs[1])

    def test_response_pairs_into_its_request_session(self):
        request_record = {'type': 'request', 'user_id': 1, 'request_id': 'q1',
                          'headers': {'X-Interaction-Id': ['iid-2']}, 'body': json.dumps({'input': 'hi'})}
        reply_record = response('r1')
        reply_record['request_id'] = 'q1'
        ids = self.add([request_record, reply_record])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(refs[0], refs[1])

    def test_ungoverned_pair_does_not_create_a_conversation(self):
        # A one-to-one request/response pair with no header and no chain must
        # stay unlinked: the gateway id supplements an anchor, never makes one.
        request_record = {'type': 'request', 'user_id': 1, 'request_id': 'q-x',
                          'body': json.dumps({'input': 'hi'})}
        reply_record = response('r1')
        reply_record['request_id'] = 'q-x'
        ids = self.add([request_record, reply_record])
        self.run_worker()
        self.assertEqual(self.refs(ids), ['', ''])

    def test_two_responses_on_one_request_id_do_not_pair(self):
        request_record = {'type': 'request', 'user_id': 1, 'request_id': 'q2',
                          'headers': {'X-Interaction-Id': ['iid-2']}, 'body': json.dumps({'input': 'hi'})}
        first, second = response('ra'), response('rb')
        first['request_id'] = second['request_id'] = 'q2'
        ids = self.add([request_record, first, second])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(refs[1], '')
        self.assertEqual(refs[2], '')

    def test_request_ids_do_not_pair_across_users(self):
        # Same raw gateway id, different users. The scoped HMAC must differ so
        # the two records never become a pair.
        first = {'type': 'request', 'user_id': 1, 'request_id': 'shared-id',
                 'headers': {'X-Interaction-Id': ['iid-user-1']}, 'body': json.dumps({'input': 'one'})}
        second = response('r1')
        second['user_id'] = 2
        second['request_id'] = 'shared-id'
        ids = self.add([first, second])
        self.run_worker()
        refs = self.refs(ids)
        self.assertTrue(refs[0].startswith('conv_'))
        self.assertEqual(refs[1], '')

    def test_initialise_upgrades_the_request_index(self):
        executed = []
        with mock.patch.object(conversations.db, 'execute', side_effect=executed.append):
            conversations.initialise()
        joined = ' '.join(executed)
        self.assertIn('request_id String', joined)
        self.assertIn('ADD COLUMN IF NOT EXISTS record_type', joined)

    def test_multi_value_session_header_is_ambiguous(self):
        request_record = {'type': 'request', 'user_id': 1, 'request_id': 'q3',
                          'headers': {'X-Interaction-Id': ['a', 'b']},
                          'body': json.dumps({'input': 'hi'})}
        ids = self.add([request_record])
        self.run_worker()
        self.assertEqual(self.refs(ids), [''])

    def test_record_without_header_or_edge_stays_unlinked(self):
        ids = self.add([response('r9')])
        self.run_worker()
        self.assertEqual(self.refs(ids), [''])

    def test_self_referential_edge_does_not_activate_a_conversation(self):
        ids = self.add([response('r1', 'r1')])
        self.run_worker()
        self.assertEqual(self.refs(ids), [''])

    def test_completed_response_id_anchors_a_multi_id_stream(self):
        # Live Responses streams carry distinct created/in_progress/completed
        # ids; only the completed id is referenced by previous_response_id.
        refs = Sanitizer(self.policy).refs
        frames = [{'type': 'response.created', 'response': {'id': 'id-created'}},
                  {'type': 'response.in_progress', 'response': {'id': 'id-progress'}},
                  {'type': 'response.completed', 'response': {'id': 'id-completed'}}]
        body = ''.join('data: ' + json.dumps(frame) + '\n\n' for frame in frames)
        parsed = parsing.derive_events({'type': 'response', 'body': body}, refs)
        self.assertEqual(parsed['response_refs'], [refs.opaque('resp', 'id-completed')])

    def test_mixed_record_is_not_narrowed_to_the_completed_id(self):
        # A record that also carries an unrelated top-level document id must
        # stay ambiguous rather than being narrowed to the completed envelope.
        refs = Sanitizer(self.policy).refs
        body = (json.dumps({'type': 'response.completed', 'response': {'id': 'id-completed'}})
                + '\n' + json.dumps({'id': 'unrelated-document'}))
        parsed = parsing.derive_events({'type': 'response', 'body': body}, refs)
        self.assertEqual(len(parsed['response_refs']), 2)

    def test_response_meta_uses_the_completed_id(self):
        refs = Sanitizer(self.policy).refs
        frames = [{'type': 'response.created', 'response': {'id': 'id-created', 'model': 'm'}},
                  {'type': 'response.completed', 'response': {'id': 'id-completed', 'model': 'm',
                                                              'status': 'completed', 'output': []}}]
        body = ''.join('data: ' + json.dumps(frame) + '\n\n' for frame in frames)
        parsed = parsing.derive_events({'type': 'response', 'body': body}, refs)
        metas = [event for event in parsed['events'] if event['kind'] == 'response_meta'
                 and 'response_ref' in (event.get('payload') or {})]
        self.assertEqual(len(metas), 1)
        self.assertEqual(metas[0]['payload']['response_ref'], refs.opaque('resp', 'id-completed'))

    def test_provider_stream_envelopes_and_ambiguous_identity(self):
        refs = Sanitizer(self.policy).refs
        for event_type, envelope in [('response.completed', 'response'), ('message_start', 'message')]:
            value = {'type': event_type, 'id': 'frame-id', envelope: {'id': 'response-id'}}
            parsed = parsing.derive_events({'type': 'response', 'body': 'data: ' + json.dumps(value) + '\n\n'}, refs)
            self.assertEqual(parsed['response_refs'], [refs.opaque('resp', 'response-id')])
        parsed = parsing.derive_events({'type': 'request', 'body': json.dumps({'id': 'request-body-id'})}, refs)
        self.assertEqual(parsed['response_refs'], [])
        parsed = parsing.derive_events({'type': 'response', 'body': json.dumps({'id': 'one'}) +
                                       json.dumps({'id': 'two'})}, refs)
        self.assertEqual(len(parsed['response_refs']), 2)


if __name__ == '__main__':
    unittest.main()
