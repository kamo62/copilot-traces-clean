"""Lane G: invented WebSocket envelopes only; worker storage is local SQLite."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'api'))
import parsing
import research
from sanitise import HoldError, Policy, Sanitizer, canonical
from test_conversation_identity import FixtureStore
from test_research_poc import policy_data


def ws_request(interaction='invented-interaction-g', previous=None, request_id='invented-q1'):
    body = {'type': 'response.create', 'headers': {'X-Interaction-Id': interaction,
            'X-Agent-Task-Id': 'invented-task-g'}, 'input': 'An invented request.'}
    if previous:
        body['previous_response_id'] = previous
    return {'type': 'request', 'endpoint': 'responses-ws', 'user_id': 1,
            'request_id': request_id, 'body': json.dumps(body)}


def ws_response(identifier='invented-r1', previous=None, request_id='invented-q1'):
    frames = []
    for event_type, response_id in [('response.created', identifier + '-created'),
                                     ('response.completed', identifier)]:
        response = {'id': response_id, 'status': 'completed', 'output': []}
        if previous:
            response['previous_response_id'] = previous
        frames.append({'type': event_type, 'response': response, 'headers': {'X-Request-Id': 'invented-provider-id'}})
    return {'type': 'response', 'endpoint': 'responses-ws', 'user_id': 1,
            'request_id': request_id, 'body': ''.join(json.dumps(frame) for frame in frames)}


class ResponsesWsParsingTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        self.clean.refs.bind_revision('rev_' + 'a' * 32)
        self.clean.refs.identity_scope = '1'

    def test_create_frame_header_uses_the_existing_header_namespace(self):
        record = ws_request()
        parsed = parsing.derive_events(record, self.clean.refs)
        direct = parsing.derive_events({'type': 'request', 'headers': {
            'X-Interaction-Id': ['invented-interaction-g']}, 'body': record['body']}, self.clean.refs)
        self.assertIsNotNone(parsed['conversation_ref'])
        self.assertEqual(parsed['conversation_ref'], direct['conversation_ref'])
        self.assertEqual({link['method'] for link in parsed['links']},
                         {'explicit_header_interaction', 'explicit_header_agent_task'})
        self.assertTrue(all(link['raw_value_exported'] is False for link in parsed['links']))
        self.assertEqual(parsed['events'][0]['linkage_status'], 'explicit')

    def test_case_insensitive_single_value_body_headers(self):
        record = ws_request()
        for headers in ({'x-InTeRaCtIoN-Id': ['invented-interaction-g']},
                        {'X-Session-Id': 'invented-session-g'}):
            with self.subTest(headers=headers):
                body = json.loads(record['body'])
                body['headers'] = headers
                record['body'] = json.dumps(body)
                parsed = parsing.derive_events(record, self.clean.refs)
                direct = parsing.derive_events({'type': 'request', 'headers': headers, 'body': ''}, self.clean.refs)
                self.assertIsNotNone(parsed['conversation_ref'])
                self.assertEqual(parsed['conversation_ref'], direct['conversation_ref'])

    def test_invalid_or_multi_value_body_headers_are_not_anchors(self):
        for value in (None, '', [], ['invented-a', 'invented-b'], 7, {'id': 'invented-a'}):
            with self.subTest(shape=type(value).__name__):
                record = ws_request()
                body = json.loads(record['body'])
                body['headers'] = {'X-Interaction-Id': value}
                record['body'] = json.dumps(body)
                parsed = parsing.derive_events(record, self.clean.refs)
                self.assertIsNone(parsed['conversation_ref'])
                self.assertEqual(parsed['links'], [])

    def test_conflicting_case_variants_are_ambiguous(self):
        record = ws_request()
        body = json.loads(record['body'])
        body['headers'] = {'X-Interaction-Id': 'invented-a', 'x-interaction-id': 'invented-b'}
        record['body'] = json.dumps(body)
        parsed = parsing.derive_events(record, self.clean.refs)
        self.assertIsNone(parsed['conversation_ref'])
        # The same ambiguity rule applies to the existing record-header route.
        direct = parsing.derive_events({'type': 'request', 'headers': body['headers'], 'body': ''}, self.clean.refs)
        self.assertIsNone(direct['conversation_ref'])

    def test_case_variant_ambiguity_is_sticky_and_equal_values_are_not_conflicts(self):
        record = ws_request()
        body = json.loads(record['body'])
        for values, expected in [(['invented-a', 'invented-b', 'invented-b'], None),
                                  (['invented-a', ['invented-a'], 'invented-a'], 'invented-a')]:
            body['headers'] = dict(zip(('X-Interaction-Id', 'x-interaction-id', 'X-INTERACTION-ID'), values))
            record['body'] = json.dumps(body)
            parsed = parsing.derive_events(record, self.clean.refs)
            self.assertEqual(parsed['conversation_ref'], self.clean.refs.opaque(
                'conv', 'header:x-interaction-id:' + expected) if expected else None)

    def test_ambiguity_keeps_observed_evidence_and_cannot_release_a_byte_budget_hold(self):
        body = json.dumps({'messages': [{'role': 'user', 'content': 'An invented phrase. ' * 1024}]})
        normal = {'type': 'request', 'headers': {'X-Interaction-Id': ['invented-last']}, 'body': body}
        ambiguous = dict(normal, headers={'X-Interaction-Id': ['invented-first'],
                                         'x-interaction-id': ['invented-last']})
        revision = {'revision_id': 'rev_' + 'a' * 32, 'schema_version': research.SCHEMA_VERSION, 'config_json': '{}'}
        source = {'id': 'b' * 64, 'seq': 1, 'timestamp': 1, 'content_sha256': 'c' * 64}

        def rows(record):
            clean = Sanitizer(Policy(policy_data(), b'k' * 48))
            clean.refs.bind_revision(revision['revision_id'])
            return research._event_rows(revision, None, source, parsing.derive_events(record, clean.refs), clean)[0]

        ceiling = max(len(canonical(row).encode()) for row in rows(normal)) - 1
        self.assertGreater(ceiling, 16 * 1024)
        with mock.patch.object(research, 'MAX_EVENT_BYTES', ceiling):
            for record in (normal, ambiguous):
                with self.assertRaises(HoldError):
                    rows(record)
        parsed = parsing.derive_events(ambiguous, self.clean.refs)
        self.assertIsNone(parsed['conversation_ref'])
        self.assertEqual(parsed['links'][0]['method'], 'ambiguous_header_interaction')
        self.assertEqual(parsed['links'][0]['ref'], self.clean.refs.opaque('conv', 'header:x-interaction-id:invented-last'))

    def test_large_embedded_header_containers_are_not_rescanned_for_identity(self):
        record = ws_request()
        body = json.loads(record['body'])
        body['headers'].update({'X-Invented-' + str(index): ''
                                for index in range(parsing.MAX_WEBSOCKET_HEADER_FIELDS - len(body['headers']))})
        record['body'] = json.dumps(body)
        self.assertIsNotNone(parsing.derive_events(record, self.clean.refs)['conversation_ref'])
        body['headers']['X-Invented-Over-Budget'] = ''
        record['body'] = json.dumps(body)
        parsed = parsing.derive_events(record, self.clean.refs)
        self.assertIsNone(parsed['conversation_ref'])
        self.assertEqual(parsed['links'], [])

    def test_optional_body_identity_does_not_hash_arbitrarily_large_values(self):
        for size, expected in [(parsing.MAX_WEBSOCKET_IDENTITY_LENGTH, True),
                               (parsing.MAX_WEBSOCKET_IDENTITY_LENGTH + 1, False)]:
            with self.subTest(identifier_length=size):
                record = ws_request('g' * size)
                parsed = parsing.derive_events(record, self.clean.refs)
                self.assertEqual(bool(parsed['conversation_ref']), expected)
                # The pre-existing record-header route remains unchanged.
                direct = parsing.derive_events({'type': 'request', 'headers': {
                    'X-Interaction-Id': 'g' * size}, 'body': ''}, self.clean.refs)
                self.assertIsNotNone(direct['conversation_ref'])

    def test_oversized_unknown_header_names_are_not_lowercased(self):
        class OversizedName(str):
            def __str__(self):
                return self

            def lower(self):
                raise AssertionError('Do not rescan an oversized non-identity key')

        headers = {OversizedName('G' * 8192): 'invented-value', 'X-Interaction-Id': 'invented-interaction-g'}
        ref, _ = parsing._header_refs({'headers': headers}, self.clean.refs)
        self.assertEqual(ref, self.clean.refs.opaque('conv', 'header:x-interaction-id:invented-interaction-g'))

    def test_record_and_body_header_conflicts_are_not_resolved_by_precedence(self):
        record = ws_request('invented-body-anchor')
        record['headers'] = {'X-Interaction-Id': ['invented-record-anchor']}
        parsed = parsing.derive_events(record, self.clean.refs)
        self.assertIsNone(parsed['conversation_ref'])
        # Council round 2: a refused anchor exports no explicit conversation link.
        self.assertEqual([link for link in parsed['links'] if link['method'] == 'explicit_header_interaction'], [])
        self.assertEqual(len([link for link in parsed['links'] if link['method'] == 'ambiguous_header_interaction']), 1)

    def test_same_record_and_body_header_is_not_duplicated(self):
        record = ws_request()
        record['headers'] = {'X-Interaction-Id': ['invented-interaction-g']}
        parsed = parsing.derive_events(record, self.clean.refs)
        self.assertEqual(sum(link['method'] == 'explicit_header_interaction' for link in parsed['links']), 1)

    def test_header_shaped_content_and_other_protocol_boundaries_stay_unlinked(self):
        record = ws_request()
        body = json.loads(record['body'])
        cases = [dict(record, endpoint='/responses'), dict(record, type='response'),
                 dict(record, body=json.dumps(dict(body, type='response.completed'))),
                 dict(record, body=json.dumps({'headers': body['headers'], 'input': body['input']}))]
        for container in ('input', 'metadata', 'response', 'tools'):
            nested = {'headers': body['headers'], 'type': 'response.create'}
            cases.append(dict(record, body=json.dumps({'type': 'response.create', container: [nested]})))
        # A record containing multiple request frames does not name one anchor.
        cases.append(dict(record, body=record['body'] + record['body']))
        for index, candidate in enumerate(cases):
            with self.subTest(boundary=index):
                self.assertIsNone(parsing.derive_events(candidate, self.clean.refs)['conversation_ref'])

    def test_previous_and_completed_response_ids_keep_their_existing_meaning(self):
        parsed = parsing.derive_events(ws_response('invented-r2', 'invented-r1'), self.clean.refs)
        self.assertIsNone(parsed['conversation_ref'])
        self.assertEqual(parsed['response_refs'], [self.clean.refs.opaque('resp', 'invented-r2')])
        self.assertEqual([link['ref'] for link in parsed['links']
                          if link['method'] == 'explicit_previous_response_id'],
                         [self.clean.refs.opaque('resp', 'invented-r1')])

    def test_header_values_never_enter_payloads_and_redaction_is_unchanged(self):
        record = ws_request()
        body = json.loads(record['body'])
        body['headers']['Authorization'] = 'ghp_' + 'z' * 40
        body['input'] = 'Read C:\\Users\\Alex Example\\src\\invented.py with token ghp_' + 'z' * 40
        record['body'] = json.dumps(body)
        parsed = parsing.derive_events(record, self.clean.refs)
        self.assertIsNotNone(parsed['conversation_ref'])
        revision = {'revision_id': 'rev_' + 'a' * 32, 'schema_version': research.SCHEMA_VERSION, 'config_json': '{}'}
        source = {'id': 'b' * 64, 'seq': 1, 'timestamp': 1, 'content_sha256': 'c' * 64}
        rows, _ = research._event_rows(revision, None, source, parsed, self.clean)
        rendered = canonical([research._export_event(row) for row in rows])
        for value in ('invented-interaction-g', 'invented-task-g', 'Alex Example', 'invented.py', 'ghp_' + 'z' * 40):
            self.assertNotIn(value, rendered)
        self.assertTrue(any(event['kind'] == 'unsupported' and 'headers' in event['payload'].get('fields', [])
                            for event in parsed['events']))


class ResponsesWsWorkerTests(unittest.TestCase):
    def setUp(self):
        self.store = FixtureStore()
        self.addCleanup(self.store.sql.close)
        self.policy = Policy(policy_data(), b'k' * 48)
        self.revision = {'revision_id': 'rev_' + 'a' * 32, 'schema_version': research.SCHEMA_VERSION,
                         'selection_max_seq': 100, 'config_json': '{}'}
        stack = ExitStack()
        self.addCleanup(stack.close)
        config = SimpleNamespace(sanitisation_available=True, identity_enabled=True,
                                 sanitiser=lambda: Sanitizer(self.policy))
        stack.enter_context(mock.patch.object(research, 'ResearchConfig', return_value=config))
        stack.enter_context(mock.patch.object(research, '_worker_revision', side_effect=lambda *args: dict(self.revision)))
        stack.enter_context(mock.patch.object(research, '_checkpoint', side_effect=self.store.checkpoint))
        stack.enter_context(mock.patch.object(research, '_finalise', return_value={'status': 'finalised'}))
        stack.enter_context(mock.patch.object(research.db, 'rows', side_effect=self.store.rows))
        stack.enter_context(mock.patch.object(research.db, 'insert', side_effect=self.store.insert))
        stack.enter_context(mock.patch.object(research.db, 'execute', side_effect=AssertionError('No network')))

    def run_records(self, records):
        identifiers = []
        for seq, record in enumerate(records, 1):
            raw = json.dumps(record, sort_keys=True)
            identifier = hashlib.sha256(('invented-g:' + str(seq) + raw).encode()).hexdigest()
            digest = hashlib.sha256(raw.encode()).hexdigest()
            identifiers.append(identifier)
            self.store.insert('records', [{'id': identifier, 'seq': seq, 'event_id': 'invented-gateway-' + str(seq),
                              'user_id': record.get('user_id', 1), 'timestamp': 1, 'type': record['type'],
                              'request_id': record['request_id'], 'endpoint': record['endpoint'],
                              'content_sha256': digest, 'record_json': raw}])
            self.store.insert('research_members', [{'revision_id': self.revision['revision_id'],
                              'record_id': identifier, 'source_seq': seq, 'content_sha256': digest}])
        for _ in range(250):
            if research.process_once({}, page_size=1)['status'] == 'finalised':
                break
        else:
            self.fail('Identity passes did not converge')
        refs = []
        for identifier in identifiers:
            rows = self.store.rows('SELECT conversation_ref FROM research_events WHERE record_id=' +
                                   research.db.literal(identifier))
            values = {row['conversation_ref'] for row in rows}
            self.assertLessEqual(len(values), 1)
            refs.append(next(iter(values), ''))
        return refs

    def anchor(self, interaction):
        clean = Sanitizer(self.policy)
        clean.refs.bind_revision(self.revision['revision_id'])
        clean.refs.identity_scope = '1'
        return clean.refs.opaque('conv', 'header:x-interaction-id:' + interaction)

    def test_initial_request_and_reply_join_the_body_header_anchor_without_a_previous_id(self):
        refs = self.run_records([ws_request(), ws_response()])
        self.assertEqual(refs, [self.anchor('invented-interaction-g')] * 2)

    def test_multiple_turns_and_out_of_order_replies_use_one_explicit_anchor(self):
        refs = self.run_records([ws_response('invented-r2', 'invented-r1', 'invented-q2'),
                                ws_request(previous='invented-r1', request_id='invented-q2'),
                                ws_response(), ws_request()])
        self.assertEqual(refs, [self.anchor('invented-interaction-g')] * 4)

    def test_body_headers_do_not_merge_users_or_different_interactions(self):
        other_user = ws_request()
        other_user['user_id'] = 2
        refs = self.run_records([ws_request(), ws_request('invented-separate'), other_user])
        self.assertTrue(all(ref.startswith('conv_') for ref in refs))
        self.assertEqual(len(set(refs)), 3)

    def test_a_held_request_cannot_supply_the_body_header_anchor_to_its_reply(self):
        request = ws_request()
        body = json.loads(request['body'])
        body['input'] = [{'type': 'function_call_output', 'call_id': 'invented-call-g',
                          'output': {'owner': {'description': 'An ambiguous invented identity.'}}}]
        request['body'] = json.dumps(body)
        refs = self.run_records([request, ws_response()])
        self.assertEqual(refs, ['', ''])
        self.assertEqual(self.store.rows("SELECT count(*) AS c FROM research_processing WHERE status='held'")[0]['c'], 1)


class DatasetCardTests(unittest.TestCase):
    def test_card_documents_the_export_fields_and_pending_licensing(self):
        card = (Path(__file__).resolve().parents[3] / 'docs' / 'DATASET_CARD.md').read_text(encoding='utf-8')
        for field in research.EVENT_SCHEMA['properties']:
            self.assertIn('`' + field + '`', card)
        for required in ('Licensing status: pending', 'Contact:', '2026-10-29.24',
                         '40,411', '33,068', '7,343', '5,843,361', '5,465', 'plan.md'):
            self.assertIn(required, card)


class HeaderConflictAcrossContainersTests(unittest.TestCase):
    """Council round 1 (Astra): an ambiguous record header blocks the frame fallback."""

    def anchor(self, record_headers, frame_headers):
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        body = {'type': 'response.create', 'headers': frame_headers, 'model': 'invented', 'input': []}
        record = {'type': 'request', 'endpoint': 'responses-ws', 'request_id': 'invented-q1',
                  'headers': record_headers, 'body': json.dumps(body)}
        return parsing.derive_events(record, refs).get('conversation_ref')

    def test_multi_value_record_header_blocks_the_frame_anchor(self):
        self.assertFalse(self.anchor({'X-Interaction-Id': ['invented-alpha', 'invented-beta']},
                                     {'X-Interaction-Id': 'invented-gamma'}))

    def test_conflicting_case_variants_in_either_place_block_the_anchor(self):
        self.assertFalse(self.anchor({'X-Interaction-Id': ['invented-alpha'], 'x-interaction-id': ['invented-beta']},
                                     {'X-Interaction-Id': 'invented-gamma'}))
        self.assertFalse(self.anchor({}, {'X-Interaction-Id': 'invented-alpha', 'x-interaction-id': 'invented-beta'}))

    def test_ambiguous_frame_headers_export_no_link(self):
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        body = {'type': 'response.create', 'model': 'invented', 'input': [],
                'headers': {'X-Interaction-Id': 'invented-alpha', 'x-interaction-id': 'invented-beta'}}
        parsed = parsing.derive_events({'type': 'request', 'endpoint': 'responses-ws', 'request_id': 'invented-q1',
                                        'body': json.dumps(body)}, refs)
        self.assertFalse(any(link['method'].startswith('ambiguous_') for link in parsed.get('links', [])))

    def parsed(self, record_headers, frame_headers):
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        body = {'type': 'response.create', 'headers': frame_headers, 'model': 'invented', 'input': []}
        record = {'type': 'request', 'endpoint': 'responses-ws', 'request_id': 'invented-q1', 'body': json.dumps(body)}
        if record_headers:
            record['headers'] = record_headers
        return parsing.derive_events(record, refs)

    def test_refused_anchor_exports_no_explicit_conversation_link(self):
        # Council round 2 (Opus): a refused anchor must not still advertise the join.
        for record_headers in ({'X-Interaction-Id': ['invented-alpha', 'invented-beta']},
                               {'X-Interaction-Id': ['invented-alpha']}):
            with self.subTest(record=record_headers):
                parsed = self.parsed(record_headers, {'X-Interaction-Id': 'invented-gamma'})
                self.assertFalse(parsed.get('conversation_ref'))
                explicit = [link for link in parsed.get('links', [])
                            if link['type'] == 'conversation' and link['method'].startswith('explicit_')]
                self.assertEqual(explicit, [])

    def test_empty_or_null_sibling_header_is_absent_not_ambiguous(self):
        for sibling in ('', None, []):
            with self.subTest(sibling=sibling):
                parsed = self.parsed(None, {'X-Interaction-Id': 'invented-gamma', 'X-Session-Id': sibling})
                self.assertTrue(parsed.get('conversation_ref'))

    def raw(self, body_text):
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        return parsing.derive_events({'type': 'request', 'endpoint': 'responses-ws', 'request_id': 'invented-q1',
                                      'body': body_text}, refs)

    def test_repeated_frame_header_keys_are_ambiguous(self):
        # Council round 2 (Astra): json.loads keeps only the last repeated key.
        for body_text in (
                '{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha",'
                '"X-Interaction-Id":"invented-beta"},"input":[]}',
                '{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha"},'
                '"headers":{"X-Interaction-Id":"invented-beta"},"input":[]}'):
            with self.subTest(body=body_text[:60]):
                parsed = self.raw(body_text)
                self.assertFalse(parsed.get('conversation_ref'))
                self.assertEqual([link for link in parsed.get('links', []) if link['type'] == 'conversation'], [])
        same = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha",'
                        '"X-Interaction-Id":"invented-alpha"},"input":[]}')
        self.assertTrue(same.get('conversation_ref'))

    def test_repeated_header_bypasses_from_round_three(self):
        # Council round 3 (Astra): a BOM made the second decode fail open, and a
        # conflict inside the first of two headers containers was lost.
        for body_text in (
                '\ufeff{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha",'
                '"X-Interaction-Id":"invented-beta"},"input":[]}',
                '{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha",'
                '"X-Interaction-Id":"invented-beta"},"headers":{"X-Interaction-Id":"invented-beta"},"input":[]}'):
            with self.subTest(body=body_text[:40]):
                parsed = self.raw(body_text)
                self.assertFalse(parsed.get('conversation_ref'))
                self.assertEqual([link for link in parsed.get('links', []) if link['type'] == 'conversation'], [])

    def test_unvalidated_frame_refuses_the_anchor_and_ordinary_frames_anchor(self):
        self.assertEqual(parsing._frame_header_repeats('{"headers":{"X-Interaction-Id":"a"}'), {'headers'})
        self.assertEqual(parsing._frame_header_repeats(
            '{"type":"response.create","headers":{"X-Interaction-Id":"a"},"input":[{"t":"]}{\\""},{}]}'), set())

    def test_object_dense_frame_scan_builds_no_object_graph(self):
        import tracemalloc
        body = ('{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha"},"metadata":['
                + ','.join(['{}'] * 200000) + ']}')
        tracemalloc.start()
        try:
            self.assertEqual(parsing._frame_header_repeats(body), set())
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertLess(peak, 1024 * 1024)

    def test_disagreeing_case_variants_and_repeated_task_headers(self):
        # Council round 3 (Opus S4, Gemini S1/S2).
        for record_headers, frame in (({'X-Session-Id': [7], 'x-session-id': ['invented-s']}, {'X-Conversation-Id': 'invented-c'}),
                                      ({'x-interaction-id': [''], 'X-Interaction-Id': ['invented-alpha']},
                                       {'X-Interaction-Id': 'invented-gamma'})):
            with self.subTest(record=record_headers):
                parsed = self.parsed(record_headers, frame)
                self.assertFalse(parsed.get('conversation_ref'))
                self.assertFalse(any(link['type'] == 'conversation' and link['method'].startswith('explicit_')
                                     for link in parsed.get('links', [])))
        parsed = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":"invented-a",'
                          '"X-Agent-Task-Id":"invented-t1","X-Agent-Task-Id":"invented-t2"},"input":[]}')
        self.assertTrue(parsed.get('conversation_ref'))
        self.assertFalse(any(link['type'] == 'task' for link in parsed.get('links', [])))

    def test_any_ambiguous_conversation_header_blocks_record_anchors(self):
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        ref, links = parsing._header_refs({'headers': {'X-Interaction-Id': [' '], 'X-Session-Id': ['invented-s1']}}, refs)
        self.assertIsNone(ref)
        self.assertTrue(all(link['method'].startswith('ambiguous_') for link in links if link['type'] == 'conversation'))

    def test_long_strings_are_skipped_in_constant_memory(self):
        # Council round 4 (Astra): the string pattern kept per-character
        # backtracking state (~1 GiB peak on an 8 MiB string).
        import tracemalloc
        for text in ('x' * 2_000_000, 'ab\\"cd\\\\' * 200_000):
            for container in ('"metadata":"{}"', '"metadata":[{{"k":"{}"}}]'):
                body = ('{"type":"response.create","headers":{"X-Interaction-Id":"invented-alpha"},'
                        + container.format(text) + '}')
                tracemalloc.start()
                try:
                    self.assertEqual(parsing._frame_header_repeats(body), set())
                    peak = tracemalloc.get_traced_memory()[1]
                finally:
                    tracemalloc.stop()
                self.assertLess(peak, 1024 * 1024, container)

    def test_multi_valued_header_stays_ambiguous_beside_an_absent_duplicate(self):
        # Council round 4 (Astra): ["a","b"] and a later null both normalised to
        # None and looked consistent.
        for duplicate in ('null', '""', '[]'):
            with self.subTest(duplicate=duplicate):
                parsed = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":["invented-alpha",'
                                  '"invented-beta"],"X-Interaction-Id":' + duplicate +
                                  ',"X-Session-Id":"invented-shared"},"input":[]}')
                self.assertFalse(parsed.get('conversation_ref'))
        same = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":"invented-a",'
                        '"X-Interaction-Id":["invented-a"]},"input":[]}')
        self.assertTrue(same.get('conversation_ref'))

    def test_over_long_duplicate_is_absent_like_in_header_refs(self):
        # Council round 5 (Opus N1): an over-long value is ignored by
        # _header_refs, so beside a null duplicate it must not refuse the anchor.
        long_value = 'x' * (parsing.MAX_WEBSOCKET_IDENTITY_LENGTH + 1)
        parsed = self.raw('{"type":"response.create","headers":{"X-Session-Id":"' + long_value +
                          '","X-Session-Id":null,"X-Interaction-Id":"invented-a"},"input":[]}')
        self.assertTrue(parsed.get('conversation_ref'))

    def test_whitespace_identity_never_anchors(self):
        first = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":" ","X-Session-Id":"invented-s1"},"input":[]}')
        second = self.raw('{"type":"response.create","headers":{"X-Interaction-Id":" ","X-Session-Id":"invented-s2"},"input":[]}')
        self.assertFalse(first.get('conversation_ref'))
        self.assertFalse(second.get('conversation_ref'))
        refs = Sanitizer(Policy(policy_data(), b'k' * 48)).refs
        refs.bind_revision('rev_' + 'a' * 32)
        refs.identity_scope = 'invented-user'
        record_level, links = parsing._header_refs({'headers': {'X-Interaction-Id': ['   ']}}, refs)
        self.assertIsNone(record_level)
        self.assertTrue(all(link['method'].startswith('ambiguous_') for link in links))

    def test_single_frame_header_still_anchors(self):
        self.assertTrue(self.anchor({}, {'X-Interaction-Id': 'invented-gamma'}))


if __name__ == '__main__':
    unittest.main()
