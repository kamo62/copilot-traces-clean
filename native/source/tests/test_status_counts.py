"""GET /v1/research/status reports live dispositions while a revision is still deriving."""
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))

import clickhouse
import research

DERIVING = 'rev_' + 'd' * 32
CURATED = 'rev_' + 'c' * 32
INCOMPLETE = 'rev_' + 'e' * 32
RESETTING = 'rev_' + 'f' * 32
LIVE_MARKER = 'FROM research_processing FINAL WHERE revision_id IN'


def stored(revision_id, status, **counts):
    """A research_revisions row as status() selects it; invented values only."""
    row = {'revision_id': revision_id, 'created_at': '2026-10-29T03:00:00+00:00', 'status': status,
           'policy_version': 'synthetic-1', 'parser_version': 'synthetic-parser', 'detector_model': 'disabled',
           'expected_records': 2616, 'pending_records': 2616, 'processed_records': 0, 'held_records': 0,
           'retry_pending_records': 0, 'retry_exhausted_records': 0, 'failed_records': 0, 'event_count': 0,
           'conversation_count': 0, 'complete': 0, 'updated_at': '2026-10-29T03:00:00+00:00'}
    row.update(counts)
    return row


class FakeDb:
    """Dispatch mocked reads by statement, record every statement and refuse any write."""

    literal = staticmethod(clickhouse.literal)

    def __init__(self, revisions, dispositions):
        self.revisions, self.dispositions, self.statements = revisions, dispositions, []

    def rows(self, sql):
        self.statements.append(sql)
        if 'FROM research_revisions FINAL' in sql:
            return [dict(row) for row in self.revisions]
        if LIVE_MARKER in sql:
            return [dict(row) for row in self.dispositions if self.literal(row['revision_id']) in sql]
        if 'SELECT count() AS c FROM records' in sql:
            return [{'c': 0}]
        return []

    def insert(self, table, values):
        raise AssertionError('status must not write ' + table)

    def execute(self, sql, data=None):
        raise AssertionError('status must not execute statements')


def disposition(revision_id, status, records, events=0):
    return {'revision_id': revision_id, 'status': status, 'records': records, 'events': events}


class StatusCountTests(unittest.TestCase):
    def status(self, revisions, dispositions):
        fake = FakeDb(revisions, dispositions)
        with mock.patch.object(research, 'db', fake):
            result = research.status({})
        return result, fake

    def live_statements(self, fake):
        return [sql for sql in fake.statements if LIVE_MARKER in sql]

    def test_deriving_revision_reports_live_dispositions(self):
        # The stored row still holds its creation-time values: everything pending.
        result, _ = self.status([stored(DERIVING, 'deriving')], [
            disposition(DERIVING, 'processed', 1500, 270000), disposition(DERIVING, 'held', 40),
            disposition(DERIVING, 'pending', 1074), disposition(DERIVING, 'retry_pending', 2)])
        row = result['revisions'][0]
        self.assertEqual(row['processed_records'], 1500)
        self.assertEqual(row['held_records'], 40)
        self.assertEqual(row['pending_records'], 1074)
        self.assertEqual(row['retry_pending_records'], 2)
        self.assertEqual(row['retry_exhausted_records'], 0)
        self.assertEqual(row['failed_records'], 0)
        self.assertEqual(row['event_count'], 270000)
        # Membership, completeness and identity counts are not disposition counts.
        self.assertEqual(row['expected_records'], 2616)
        self.assertEqual(row['complete'], 0)
        self.assertEqual(row['conversation_count'], 0)
        self.assertEqual(row['status'], 'deriving')

    def test_finalised_revisions_keep_stored_counts_without_the_aggregate(self):
        curated = stored(CURATED, 'curated', pending_records=0, processed_records=1581, held_records=1035,
                         event_count=477579, complete=1)
        incomplete = stored(INCOMPLETE, 'incomplete', pending_records=0, processed_records=10, failed_records=3,
                            event_count=90)
        # Dispositions that disagree with the stored rows must not leak into a finalised report.
        result, fake = self.status([curated, incomplete], [disposition(CURATED, 'processed', 1),
                                                           disposition(INCOMPLETE, 'processed', 1)])
        self.assertEqual(result['revisions'], [curated, incomplete])
        self.assertEqual(self.live_statements(fake), [])

    def test_only_in_progress_revisions_are_aggregated_and_shape_is_unchanged(self):
        revisions = [stored(RESETTING, 'resetting', pending_records=5, processed_records=20, event_count=200),
                     stored(DERIVING, 'deriving'),
                     stored(CURATED, 'curated', pending_records=0, processed_records=7, complete=1)]
        result, fake = self.status(revisions, [
            disposition(RESETTING, 'processed', 20, 200), disposition(RESETTING, 'pending', 3),
            disposition(RESETTING, 'retry_exhausted', 2), disposition(DERIVING, 'processed', 9, 45),
            disposition(DERIVING, 'pending', 2607), disposition(CURATED, 'processed', 999)])
        statements = self.live_statements(fake)
        self.assertEqual(len(statements), 1)
        self.assertIn(clickhouse.literal(RESETTING), statements[0])
        self.assertIn(clickhouse.literal(DERIVING), statements[0])
        self.assertNotIn(clickhouse.literal(CURATED), statements[0])
        rows = result['revisions']
        self.assertEqual([row['revision_id'] for row in rows], [RESETTING, DERIVING, CURATED])
        for before, after in zip(revisions, rows):
            self.assertEqual(set(after), set(before))
            self.assertEqual({key: type(value) for key, value in after.items()},
                             {key: type(value) for key, value in before.items()})
        self.assertEqual((rows[0]['pending_records'], rows[0]['retry_exhausted_records']), (3, 2))
        self.assertEqual((rows[1]['processed_records'], rows[1]['pending_records'], rows[1]['event_count']), (9, 2607, 45))
        self.assertEqual(rows[2], revisions[2])

    def test_in_progress_revision_without_dispositions_keeps_its_stored_row(self):
        row = stored(DERIVING, 'deriving')
        result, _ = self.status([row], [])
        self.assertEqual(result['revisions'], [row])

    def test_live_aggregate_is_bounded_and_content_free(self):
        _, fake = self.status([stored(DERIVING, 'deriving'), stored(RESETTING, 'resetting')], [])
        statement = self.live_statements(fake)[0]
        self.assertIn('GROUP BY revision_id,status', statement)
        self.assertIn('LIMIT 32', statement)
        self.assertIn('max_threads=1', statement)
        self.assertIn('max_execution_time=30', statement)
        for forbidden in ('record_json', 'research_events', 'payload', 'observation_ref', 'record_id'):
            self.assertNotIn(forbidden, statement)

    def test_no_revisions_issue_no_aggregate(self):
        result, fake = self.status([], [])
        self.assertEqual(result['revisions'], [])
        self.assertEqual(self.live_statements(fake), [])


if __name__ == '__main__':
    unittest.main()


class SupersededRevisionTests(unittest.TestCase):
    def test_superseded_revision_keeps_the_dispositions_it_reached(self):
        revision = stored(DERIVING, 'deriving')
        revision.update(selection_max_seq=10, membership_sha256='a' * 64)
        live = {DERIVING: {'pending_records': 1000, 'processed_records': 1500, 'held_records': 116,
                           'retry_pending_records': 0, 'retry_exhausted_records': 0, 'failed_records': 0,
                           'event_count': 4321}}
        written = []
        with mock.patch.object(research, '_latest', side_effect=lambda states: revision if states == ['deriving'] else None), \
                mock.patch.object(research, 'config_revision', return_value=('rev_' + '9' * 32, {})), \
                mock.patch.object(research, '_live_dispositions', return_value=live), \
                mock.patch.object(research, 'create_revision', return_value={'revision_id': 'rev_' + '9' * 32}), \
                mock.patch.object(research.db, 'insert', side_effect=lambda table, rows: written.extend(rows)):
            research._worker_revision(object())
        self.assertEqual(written[0]['status'], 'incomplete')
        self.assertEqual(written[0]['processed_records'], 1500)
        self.assertEqual(written[0]['event_count'], 4321)


class SanitiserVersionRecordTests(unittest.TestCase):
    def test_revision_row_and_manifest_name_the_sanitiser_version(self):
        source = Path(research.__file__).read_text()
        self.assertIn("'sanitiser_version': SANITISER_VERSION,", source)
        self.assertIn("'sanitiser_version': revision.get('sanitiser_version')", source)
