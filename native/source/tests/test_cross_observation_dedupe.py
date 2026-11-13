"""Lane F: invented-only repeat annotation, recovery, boundedness and reader checks."""
from contextlib import ExitStack
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
import dedupe
import parsing
import research
import research_reader
from sanitise import Policy, Sanitizer, canonical
from test_conversation_identity import FixtureStore, Interrupted
from test_derivation_limits import revision_config
from test_research_poc import policy_data


def performance_record(source_bytes):
    """Invented plain prose fixture, including a near-8-MiB bounded source case."""
    text = 'Invented prose for a bounded performance fixture. '
    chunk = (text * (65536 // len(text) + 1))[:65536]
    count = max(1, (source_bytes - 512) // 65536)
    messages = [{'role': 'user', 'content': chunk} for _ in range(count)]
    if count == 1 and source_bytes < 65536:
        messages[0]['content'] = chunk[:max(1, source_bytes - 512)]
    return {'type': 'request', 'user_id': 1, 'body': canonical({'messages': messages})}


class RepeatStore(FixtureStore):
    KEYS = {**FixtureStore.KEYS,
            'research_dedupe_first_seen': 'revision_id,conversation_ref,role,content_sha256',
            'research_dedupe_decisions': 'revision_id,source_seq,event_index,event_id'}

    def __init__(self):
        self.writes = []
        super().__init__()
        self.writes.clear()
        self.sql.execute('ALTER TABLE research_processing ADD COLUMN dedupe_eligible INTEGER DEFAULT 0')
        self.sql.create_function('length', 1, lambda value: len(value.encode('utf-8')) if isinstance(value, str) else len(value))
        self.fail_phase = None
        self.payload_page_bytes = []

    def insert(self, table, rows):
        self.writes.append((table, copy.deepcopy(rows)))
        super().insert(table, rows)

    def rows(self, query):
        if 'research_dedupe_' in query or query.startswith('SELECT ' + dedupe.METADATA):
            assert 'revision_id=' in query and 'LIMIT ' in query and 'max_memory_usage=536870912' in query
            assert 'OFFSET' not in query and 'GROUP BY' not in query
        query = query.replace("countIf(status NOT IN ('processed','held'))",
                              "coalesce(sum(CASE WHEN status NOT IN ('processed','held') THEN 1 ELSE 0 END),0)")
        query = query.replace(') WHERE ', ') AND ')
        rows = super().rows(query)
        if query.startswith('SELECT ' + dedupe.METADATA + ',payload '):
            self.payload_page_bytes.append(sum(len(row['payload'].encode('utf-8')) for row in rows))
        return rows

    def checkpoint(self, key, value=None):
        result = super().checkpoint(key, value)
        if value is not None:
            phase = 'done' if value.get('done') else 'pending' if value.get('pending') else 'committed'
            if phase == self.fail_phase:
                self.fail_phase = None
                raise Interrupted()
        return result


class CrossObservationDedupeTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(research.db, 'rows', side_effect=lambda query: self.store.rows(query)))
        self.stack.enter_context(mock.patch.object(research.db, 'insert', side_effect=lambda table, rows: self.store.insert(table, rows)))
        self.stack.enter_context(mock.patch.object(research.db, 'execute', side_effect=AssertionError('No network')))
        self.fresh()

    def fresh(self, event_bytes=research.MAX_EVENT_BYTES, page_bytes=research.MAX_PAGE_BYTES):
        self.store = RepeatStore()
        self.addCleanup(self.store.sql.close)
        self.pin = dedupe.configuration(event_bytes, page_bytes)
        self.revision = {'revision_id': 'rev_' + 'a' * 32, 'schema_version': research.SCHEMA_VERSION,
                         'selection_max_seq': 1000, 'expected_records': 0, 'config_json': canonical({'dedupe': self.pin}),
                         'created_at': '2026-10-31T00:00:00+00:00', 'policy_version': 'synthetic-1',
                         'parser_version': parsing.PARSER_VERSION, 'sanitiser_version': research.SANITISER_VERSION,
                         'detector_model': 'disabled', 'detector_policy_version': 'disabled',
                         'processed_records': 0, 'held_records': 0, 'failed_records': 0, 'conversation_count': 1}

    def add(self, sequence, text='Invented repeated prompt.', role='user', conversation='conv_' + 'b' * 24,
            index=0, status='processed', eligible=True, **extra):
        record_id = hashlib.sha256(('invented-record:' + str(sequence)).encode()).hexdigest()
        payload = {'text': text, 'block_type': 'text', 'authorship': 'unknown', 'intent_label': None, 'intent_status': 'unknown'}
        payload.update(extra.pop('payload_extra', {}))
        row = {'revision_id': self.revision['revision_id'], 'schema_version': research.SCHEMA_VERSION,
               'event_id': 'event_' + hashlib.sha256(('invented-event:' + str(sequence) + ':' + str(index)).encode()).hexdigest()[:24],
               'record_id': record_id, 'pipeline_id': 'pipeline-' + str(sequence), 'source_seq': sequence, 'event_index': index,
               'observation_ref': 'obs_' + ('%024x' % sequence), 'conversation_ref': conversation,
               'origin': 'history', 'kind': 'message', 'role': role, 'parent_event_id': '', 'call_ref': '', 'result_ref': '',
               'link_json': '', 'parse_status': 'parsed', 'coverage_status': 'unknown', 'linkage_status': 'explicit',
               'parser_version': parsing.PARSER_VERSION, 'payload': canonical(payload),
               'content_sha256': hashlib.sha256(canonical(payload).encode()).hexdigest(), 'version': 1}
        row.update(extra)
        self.store.insert('research_events', [row])
        self.store.insert('research_processing', [{'revision_id': row['revision_id'], 'record_id': record_id,
                          'pipeline_id': row['pipeline_id'], 'status': status, 'dedupe_eligible': int(eligible)}])
        self.revision['expected_records'] = self.store.sql.execute('SELECT count(*) FROM research_processing').fetchone()[0]
        self.revision['processed_records'] = self.revision['expected_records']
        return row

    def run_index(self, maximum=1000):
        for _ in range(maximum):
            if dedupe.step(self.revision, self.store.checkpoint):
                return self.store.checkpoint('research_dedupe:' + self.revision['revision_id'])
        self.fail('Repeat index did not finish within bounded pages')

    def exported(self):
        rows = self.store.rows("SELECT * FROM research_events WHERE revision_id='" + self.revision['revision_id'] +
                               "' ORDER BY source_seq,event_index,event_id")
        for row in rows:
            row.update(dedupe_version=dedupe.ALGORITHM_VERSION, dedupe_config_json=canonical(self.pin))
        dedupe.annotate(rows, self.store.checkpoint)
        return [research._export_event(row) for row in rows]

    def manifest(self, events):
        config = SimpleNamespace(retention_raw='manual', retention_curated='manual', release_setting='evaluated')
        with mock.patch.object(research, '_all_export_events', return_value=iter(events)), \
                mock.patch.object(research, '_checkpoint', side_effect=self.store.checkpoint), \
                mock.patch.object(research.db, 'rows', return_value=[]):
            return research._build_manifest(self.revision, config)

    def read_events(self, events, manifest=None):
        with tempfile.TemporaryDirectory(prefix='invented-repeat-test-') as directory:
            path = Path(directory) / 'fixture.jsonl'
            path.write_bytes(research.jsonl_bytes(events))
            return research_reader.read_export(path, manifest)

    def test_cross_observation_repeat_keeps_every_payload_and_same_observation_occurrence(self):
        first = self.add(1)
        self.add(1, index=1)
        self.add(2)
        self.add(2, 'Invented new prompt.', index=1)
        before = self.store.sql.execute('SELECT payload FROM research_events ORDER BY source_seq,event_index').fetchall()
        state = self.run_index()
        events = self.exported()
        self.assertEqual([event['payload'][dedupe.FIELD] for event in events], [None, None, first['event_id'], None])
        self.assertEqual(state['counts']['content_repeat_events'], 1)
        self.assertEqual(before, self.store.sql.execute('SELECT payload FROM research_events ORDER BY source_seq,event_index').fetchall())
        self.assertEqual(len(events), 4)
        self.assertTrue(all(event['schema_version'] == 'research-event/2' for event in events))
        for event in events:
            self.assertIn('text', event['payload'])
            self.assertNotIn('record_id', event)
            self.assertNotIn('content_sha256', event['payload'])
        self.assertFalse(self.pin['provider_message_identity_proven'])
        self.assertFalse(self.pin['payloads_suppressed'])

    def test_scope_role_and_unknown_conversation_never_bridge(self):
        first = self.add(1)
        self.add(2, conversation='conv_' + 'c' * 24)
        self.add(3, role='assistant')
        self.add(4, conversation='')
        self.add(5)
        self.run_index()
        events = self.exported()
        self.assertEqual([event['payload'].get(dedupe.FIELD) for event in events], [None, None, None, None, first['event_id']])
        self.assertNotIn(dedupe.FIELD, events[3]['payload'])
        other = dict(self.revision, revision_id='rev_' + 'c' * 32, expected_records=0)
        state = dedupe.step(other, self.store.checkpoint)
        self.assertTrue(state)
        self.assertEqual(self.store.checkpoint('research_dedupe:' + other['revision_id'])['counts']['eligible_events'], 0)

    def test_streams_tools_withheld_summaries_and_partial_units_remain_unmarked(self):
        self.add(1)
        self.add(2, eligible=False)
        self.add(3, payload_extra={'source_frame_refs': ['event_' + 'd' * 24]})
        self.add(4, payload_extra={'stream_status': 'complete'})
        self.add(5, origin='output')
        self.add(6, kind='tool_result')
        self.add(7, coverage_status='incomplete')
        self.add(8, text='[WITHHELD]')
        self.add(9, payload_extra={'withheld': True})
        self.run_index()
        events = self.exported()
        self.assertIn(dedupe.FIELD, events[0]['payload'])
        self.assertTrue(all(dedupe.FIELD not in event['payload'] for event in events[1:]))

    def test_eligibility_excludes_summary_truncation_and_partial_records(self):
        for reason in ('source_summary_present', 'provider_truncated', 'partial_stream'):
            parsed = {'format': 'json', 'parse_status': 'parsed', 'stream_complete': None,
                      'events': [{'kind': 'unsupported', 'payload': {'reason': reason}}]}
            self.assertFalse(dedupe.eligible_observation(parsed))

    def test_superseded_and_held_evidence_cannot_become_a_canonical_target(self):
        self.add(1, status='held')
        current = self.add(2)
        self.add(3)
        stale = self.add(4)
        self.store.insert('research_processing', [{'revision_id': self.revision['revision_id'], 'record_id': stale['record_id'],
                          'pipeline_id': 'different-pipeline', 'status': 'processed'}])
        state = self.run_index()
        rows = [dict(row) for row in self.store.sql.execute('SELECT * FROM research_dedupe_decisions')]
        self.assertEqual({row['event_id'] for row in rows}, {current['event_id'], self.add_event_id(3)})
        self.assertEqual(state['counts']['content_repeat_events'], 1)
        self.assertEqual(state['counts']['superseded_events'], 2)

    @staticmethod
    def add_event_id(sequence):
        return 'event_' + hashlib.sha256(('invented-event:' + str(sequence) + ':0').encode()).hexdigest()[:24]

    def test_hash_collision_invalidates_the_whole_key_even_after_prior_repeat_pages(self):
        with mock.patch.object(dedupe, 'PAGE_ROWS', 1):
            self.fresh()
            first = self.add(1)
            self.add(2)
            self.add(3, text='Invented different prompt.', content_sha256=first['content_sha256'])
            self.add(4)
            state = self.run_index()
            self.assertEqual(state['counts']['content_repeat_events'], 0)
            self.assertEqual(state['counts']['hash_conflict_keys'], 1)
            self.assertTrue(all(event['payload'][dedupe.FIELD] is None for event in self.exported()))

    def test_parser_version_mismatch_is_retained_not_marked(self):
        self.add(1)
        self.add(2, parser_version='synthetic-other-parser')
        self.run_index()
        self.assertTrue(all(event['payload'][dedupe.FIELD] is None for event in self.exported()))

    def test_first_seen_is_source_order_not_arrival_order(self):
        for sequence in (4, 2, 3, 1):
            self.add(sequence)
        self.run_index()
        events = self.exported()
        self.assertEqual(events[0]['payload'][dedupe.FIELD], None)
        self.assertTrue(all(event['payload'][dedupe.FIELD] == events[0]['event_id'] for event in events[1:]))

    def test_acknowledged_write_recovery_has_identical_bytes_and_counts(self):
        with mock.patch.object(dedupe, 'PAGE_ROWS', 2):
            self.fresh()
            for sequence in range(1, 6):
                self.add(sequence)
            expected_counts = self.run_index()['counts']
            expected_bytes = research.jsonl_bytes(self.exported())
            for failure in ('research_dedupe_first_seen', 'research_dedupe_decisions', 'pending', 'committed', 'done'):
                with self.subTest(failure=failure):
                    self.fresh()
                    for sequence in range(1, 6):
                        self.add(sequence)
                    if failure.startswith('research_'):
                        self.store.fail_table = failure
                    else:
                        self.store.fail_phase = failure
                    with self.assertRaises(Interrupted):
                        self.run_index()
                    self.assertEqual(self.run_index()['counts'], expected_counts)
                    self.assertEqual(research.jsonl_bytes(self.exported()), expected_bytes)
                    self.assertNotIn('Invented repeated prompt.', json.dumps(self.store.checkpoints))

    def test_large_group_has_bounded_pages_and_byte_budget_on_both_comparison_sides(self):
        self.fresh(event_bytes=512, page_bytes=1024)
        for sequence in range(1, 502):
            self.add(sequence, text='Invented text. ' * 20)
        state = self.run_index()
        self.assertEqual(state['counts']['eligible_events'], 501)
        self.assertEqual(state['counts']['content_repeat_events'], 500)
        self.assertLessEqual(max(self.store.payload_page_bytes), self.pin['max_payload_bytes'])
        self.assertTrue(all(len(query.encode()) <= self.pin['max_sql_bytes'] for query in self.store.queries))
        self.assertGreater(len(self.store.payload_page_bytes), 10)

    def test_history_scan_selects_bounded_metadata_before_reading_any_payload_column(self):
        self.add(1)
        self.add(2)
        self.run_index()
        scans = [query for query in self.store.queries if '(source_seq,event_index,event_id)>' in query]
        self.assertTrue(scans)
        self.assertTrue(all('length(payload)' not in query and ',payload FROM' not in query for query in scans))
        size_queries = [query for query in self.store.queries if 'length(payload)' in query]
        self.assertTrue(size_queries)
        self.assertTrue(all('(source_seq,event_index,event_id) IN (' in query for query in size_queries))

    def test_changed_comparison_metadata_cannot_be_committed_as_a_repeat(self):
        self.add(1)
        original = self.store.rows

        def changing_rows(query):
            rows = original(query)
            if query.startswith('SELECT ' + dedupe.METADATA + ',payload '):
                rows[0]['role'] = 'assistant'
            return rows

        with mock.patch.object(research.db, 'rows', side_effect=changing_rows):
            with self.assertRaisesRegex(OSError, 'membership changed'):
                self.run_index()
        self.assertIsNone(self.store.checkpoint('research_dedupe:' + self.revision['revision_id']))

    def test_unfinished_retry_cannot_freeze_a_partial_mapping(self):
        self.add(1)
        self.add(2, status='retry_exhausted')
        self.assertTrue(dedupe.step(self.revision, self.store.checkpoint))
        self.assertIsNone(self.store.checkpoint('research_dedupe:' + self.revision['revision_id']))

    def test_export_rejects_partial_missing_or_inconsistent_decisions(self):
        self.add(1)
        self.add(2)
        with self.assertRaisesRegex(OSError, 'incomplete'):
            self.exported()
        self.run_index()
        self.store.sql.execute('UPDATE research_dedupe_decisions SET role=\'assistant\' WHERE source_seq=2')
        with self.assertRaisesRegex(OSError, 'unavailable'):
            self.exported()
        self.store.sql.execute('DELETE FROM research_dedupe_decisions WHERE source_seq=2')
        with self.assertRaisesRegex(OSError, 'unavailable'):
            self.exported()

    def test_even_a_non_message_page_requires_completed_reconciliation(self):
        self.add(1, kind='source_frame', origin='source_stream')
        with self.assertRaisesRegex(OSError, 'incomplete'):
            self.exported()
        self.run_index()
        self.assertNotIn(dedupe.FIELD, self.exported()[0]['payload'])

    def test_default_off_keeps_revision_identity_export_bytes_and_sidecar_reads_unchanged(self):
        config = revision_config()
        before, payload = research.config_revision(config, 10, 'c' * 64)
        config.dedupe_enabled = False
        after, _ = research.config_revision(config, 10, 'c' * 64)
        self.assertEqual(before, after)
        self.assertNotIn('dedupe', payload)
        self.assertFalse(research.ResearchConfig({}).dedupe_enabled)
        row = self.add(1)
        expected = research.jsonl_bytes([research._export_event(row)])
        with mock.patch.object(research.db, 'rows', side_effect=AssertionError('No sidecar read')):
            dedupe.annotate([row], self.store.checkpoint)
        self.assertEqual(expected, research.jsonl_bytes([research._export_event(row)]))

    def test_default_off_body_query_does_not_read_annotation_context_or_hash_columns(self):
        revision_id = self.revision['revision_id']
        ordinary = research._export_query(revision_id)
        self.assertNotIn('config_json', ordinary)
        self.assertNotIn('content_sha256', ordinary)
        self.assertNotIn('dedupe', ordinary)
        self.assertIn('dedupe_config_json', research._export_query(revision_id, metadata=True))
        annotated = research._export_query(revision_id, annotate=True)
        self.assertIn('e.record_id AS record_id,e.pipeline_id AS pipeline_id,e.content_sha256 AS content_sha256', annotated)
        # Council round 1 (Opus): ClickHouse names an unaliased joined column
        # 'e.record_id' when the joined subquery has the same column, and
        # dedupe.annotate then fails with KeyError on every annotated page.
        import re as _re
        joined = set(_re.findall(r'\(SELECT ([a-z_,]+) FROM research_processing', annotated)[0].split(','))
        for column in joined:
            self.assertNotRegex(annotated, r'\be\.' + column + r'(?=,|\s+FROM)')
        self.assertIn('dedupe_config_json', annotated)

    def test_export_page_uses_the_revision_pin_to_attach_markers_and_checksum_all_rows(self):
        first = self.add(1)
        self.add(2)
        self.run_index()
        expected = self.exported()
        manifest = self.manifest(expected)
        stored = [dict(row) for row in self.store.sql.execute('SELECT * FROM research_events ORDER BY source_seq,event_index')]
        release = {'manifest_json': canonical(manifest), 'event_bytes_limit': research.MAX_EVENT_BYTES,
                   'page_bytes_limit': research.MAX_PAGE_BYTES}

        def export_rows(query):
            if query.startswith('SELECT e.event_id,length(e.payload)'):
                return [{'event_id': row['event_id'], 'payload_bytes': len(row['payload'].encode()),
                         'dedupe_config_json': canonical(self.pin)} for row in stored]
            if query.startswith('SELECT e.revision_id AS revision_id'):
                self.assertIn('dedupe_version', query)
                return [dict(row, dedupe_version=dedupe.ALGORITHM_VERSION,
                             dedupe_config_json=canonical(self.pin)) for row in stored]
            return self.store.rows(query)

        with mock.patch.object(research.db, 'rows', side_effect=export_rows), \
                mock.patch.object(research, '_checkpoint', side_effect=self.store.checkpoint), \
                mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48):
            page, body = research.export_page(self.revision['revision_id'], limit=2)
        self.assertEqual(page['events'], expected)
        self.assertEqual(page['event_count'], 2)
        self.assertEqual(page['events'][1]['payload'][dedupe.FIELD], first['event_id'])
        self.assertEqual(hashlib.sha256(body).hexdigest(), manifest['export_sha256'])
        self.assertTrue(page['complete'])

    def test_revision_identity_pins_algorithm_and_all_dedupe_budgets(self):
        config = revision_config()
        first, _ = research.config_revision(config, 10, 'c' * 64)
        config.dedupe_enabled = True
        enabled, payload = research.config_revision(config, 10, 'c' * 64)
        self.assertNotEqual(first, enabled)
        self.assertEqual(payload['dedupe'], self.pin)
        for name, value in (('ALGORITHM_VERSION', 'synthetic-next'), ('PAGE_ROWS', 100), ('MAX_SQL_BYTES', 128 * 1024),
                            ('MAX_QUERY_MEMORY', 256 * 1024 * 1024)):
            with self.subTest(name=name), mock.patch.object(dedupe, name, value):
                changed, _ = research.config_revision(config, 10, 'c' * 64)
                self.assertNotEqual(enabled, changed)

    def test_worker_finishes_conversation_identity_before_repeat_mapping(self):
        config = SimpleNamespace(sanitisation_available=True, identity_enabled=True, dedupe_enabled=True)
        with mock.patch.object(research, 'ResearchConfig', return_value=config), \
                mock.patch.object(research, '_worker_revision', return_value=self.revision), \
                mock.patch.object(research, '_checkpoint', return_value={}), \
                mock.patch.object(research.db, 'rows', return_value=[]), \
                mock.patch.object(research, '_conversation_step', side_effect=[False, True]), \
                mock.patch.object(dedupe, 'step', return_value=False) as step, \
                mock.patch.object(research, '_finalise') as finalise:
            result = research.process_once({}, page_size=1)
            self.assertEqual(result['stage'], 'conversation_identity')
            step.assert_not_called()
            result = research.process_once({}, page_size=1)
            self.assertEqual(result['stage'], 'content_repeat_annotations')
            step.assert_called_once()
            finalise.assert_not_called()

    def test_compose_passes_the_same_disabled_by_default_setting_to_api_and_worker(self):
        compose = (ROOT.parents[1] / 'compose.yaml').read_text()
        self.assertEqual(compose.count('COPILOT_RESEARCH_DEDUPE_ENABLED: ${COPILOT_RESEARCH_DEDUPE_ENABLED:-false}'), 2)

    def test_manifest_rejects_unreconciled_or_partial_annotation_counts(self):
        self.add(1)
        self.add(2)
        self.run_index()
        events = self.exported()
        with self.assertRaisesRegex(OSError, 'reconcile'):
            self.manifest(events[:1])
        self.store.checkpoint('research_dedupe:' + self.revision['revision_id'], {'done': False})
        with self.assertRaisesRegex(OSError, 'incomplete'):
            self.manifest(events)

    def test_worker_commits_eligibility_with_processed_and_preserves_user_scoping(self):
        policy = Policy(policy_data(), b'k' * 48)
        for sequence, user in ((1, 1), (2, 1), (3, 2)):
            record = {'type': 'request', 'user_id': user, 'headers': {'X-Interaction-Id': ['invented-session']},
                      'body': json.dumps({'messages': [{'role': 'user', 'content': 'Invented replay.'}]})}
            raw = canonical(record)
            identifier = hashlib.sha256(('invented-record:' + str(sequence)).encode()).hexdigest()
            digest = hashlib.sha256(raw.encode()).hexdigest()
            self.store.insert('records', [{'id': identifier, 'seq': sequence, 'event_id': '', 'user_id': user,
                              'timestamp': 1, 'type': 'request', 'request_id': '', 'endpoint': '/invented',
                              'content_sha256': digest, 'record_json': raw}])
            self.store.insert('research_members', [{'revision_id': self.revision['revision_id'], 'record_id': identifier,
                              'source_seq': sequence, 'content_sha256': digest}])
        self.revision['expected_records'] = 3
        config = SimpleNamespace(sanitisation_available=True, dedupe_enabled=True, identity_enabled=False,
                                 sanitiser=lambda: Sanitizer(policy))
        with mock.patch.object(research, 'ResearchConfig', return_value=config), \
                mock.patch.object(research, '_worker_revision', return_value=self.revision), \
                mock.patch.object(research, '_checkpoint', side_effect=lambda key, value=None: self.store.checkpoint(key, value)), \
                mock.patch.object(research, '_finalise', return_value={'status': 'finalised'}):
            for _ in range(20):
                if research.process_once({}, page_size=1)['status'] == 'finalised':
                    break
            else:
                self.fail('Invented worker did not finish')
        events = [event for event in self.exported() if event['kind'] == 'message']
        self.assertEqual([event['payload'][dedupe.FIELD] for event in events], [None, events[0]['event_id'], None])
        self.assertNotEqual(events[0]['conversation_ref'], events[2]['conversation_ref'])
        writes = [table for table, rows in self.store.writes if rows]
        for position, table in enumerate(writes):
            if table == 'research_processing':
                self.assertEqual(writes[position - 1], 'research_events')
        self.assertTrue(all(rows[0]['dedupe_eligible'] == 1 for table, rows in self.store.writes if table == 'research_processing'))

    def test_reader_and_manifest_validate_full_references_and_partial_page_uncertainty(self):
        self.add(1)
        self.add(2)
        self.run_index()
        events = self.exported()
        manifest = self.manifest(events)
        summary = self.read_events(events, manifest)
        self.assertTrue(summary['manifest_checksum_verified'])
        self.assertEqual(summary['content_repeat_events'], 1)
        self.assertEqual(manifest['dedupe']['counts']['retained_eligible_events'], 1)
        self.assertEqual(manifest['dedupe']['counts']['payloads_suppressed'], 0)
        partial = self.read_events(events[1:])
        self.assertEqual(partial['content_repeat_validation'], 'incomplete')
        self.assertEqual(partial['unresolved_content_repeat_refs'], 1)
        with self.assertRaises(ValueError):
            self.read_events(events[1:], manifest)

    def test_reader_rejects_bad_scope_roles_content_chains_and_same_observation(self):
        self.add(1)
        self.add(2)
        self.add(3)
        self.run_index()
        original = self.exported()
        mutations = (
            ('conversation_ref', 'conv_' + 'f' * 24), ('role', 'assistant'),
            ('observation_ref', original[0]['observation_ref']),
            ('payload', {**original[1]['payload'], 'text': 'Invented edited text.'}),
            ('payload', {**original[1]['payload'], dedupe.FIELD: original[2]['event_id']}),
            ('payload', {**original[1]['payload'], dedupe.FIELD: original[1]['event_id']}),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                events = copy.deepcopy(original)
                events[1][field] = value
                with self.assertRaises(ValueError):
                    self.read_events(events)
        chained = copy.deepcopy(original)
        chained[2]['payload'][dedupe.FIELD] = original[1]['event_id']
        with self.assertRaisesRegex(ValueError, 'target'):
            self.read_events(chained)
        unmarked_target = copy.deepcopy(original)
        del unmarked_target[0]['payload'][dedupe.FIELD]
        with self.assertRaisesRegex(ValueError, 'target'):
            self.read_events(unmarked_target)

    def test_query_and_result_budgets_fail_closed(self):
        with mock.patch.object(research.db, 'rows', return_value=[{}, {}]):
            with self.assertRaisesRegex(OSError, 'row budget'):
                dedupe._rows('SELECT fixture LIMIT 1', 1, 1024, self.pin)
        with self.assertRaisesRegex(OSError, 'query'):
            dedupe._rows('SELECT ' + 'x' * self.pin['max_sql_bytes'], 1, 1024, self.pin)

    def test_largest_performance_fixture_is_invented_and_within_source_and_event_budgets(self):
        record = performance_record(8 * 1024 * 1024)
        self.assertLessEqual(len(canonical(record).encode()), research.MAX_SOURCE_BYTES)
        messages = json.loads(record['body'])['messages']
        self.assertEqual(len(messages), 127)
        self.assertTrue(all(len(message['content'].encode()) < research.MAX_EVENT_BYTES for message in messages))


if __name__ == '__main__':
    unittest.main()
