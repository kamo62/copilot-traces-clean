"""Focused synthetic checks for configurable derivation limits and read-only health reporting."""
import os
from pathlib import Path
import sys
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1]))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import research
import research_reader
import verify


def revision_config():
    policy = SimpleNamespace(version='synthetic-1', scope='synthetic-scope', reference_scope_mode='revision',
                             fingerprint='0' * 64, pseudonym_key=b'synthetic-key', detector_policy_version='none')
    return SimpleNamespace(policy=policy, detector=None, detector_model='disabled')


class LimitTests(unittest.TestCase):
    def test_default_when_unset(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('COPILOT_SYNTHETIC_LIMIT', None)
            self.assertEqual(research._byte_limit('COPILOT_SYNTHETIC_LIMIT', 1024, 16, 4096), 1024)

    def test_parses_bounded_value(self):
        with mock.patch.dict(os.environ, {'COPILOT_SYNTHETIC_LIMIT': '2048'}):
            self.assertEqual(research._byte_limit('COPILOT_SYNTHETIC_LIMIT', 1024, 16, 4096), 2048)

    def test_rejects_malformed_value(self):
        with mock.patch.dict(os.environ, {'COPILOT_SYNTHETIC_LIMIT': '2MiB'}):
            with self.assertRaises(ValueError):
                research._byte_limit('COPILOT_SYNTHETIC_LIMIT', 1024, 16, 4096)

    def test_rejects_out_of_range_value(self):
        with mock.patch.dict(os.environ, {'COPILOT_SYNTHETIC_LIMIT': '8'}):
            with self.assertRaises(ValueError):
                research._byte_limit('COPILOT_SYNTHETIC_LIMIT', 1024, 16, 4096)

    def test_effective_limits_cover_observed_bodies(self):
        # Largest observed Enterprise body was ~5.24 MiB; the source ceiling must cover it.
        self.assertGreaterEqual(research.MAX_SOURCE_BYTES, 6 * 1024 * 1024)
        self.assertGreaterEqual(research.MAX_PAGE_BYTES, research.MAX_EVENT_BYTES)
        self.assertGreaterEqual(research.MAX_RECORD_EVENT_BYTES, research.MAX_EVENT_BYTES)
        # The strict reader must accept a line at the server's event ceiling.
        self.assertGreaterEqual(research_reader.MAX_LINE_BYTES, research.MAX_EVENT_BYTES)

    def test_revision_identity_changes_with_sanitiser_version(self):
        config = revision_config()
        first, payload = research.config_revision(config, 10, 'a' * 64)
        self.assertEqual(payload['sanitiser_version'], research.SANITISER_VERSION)
        with mock.patch.object(research, 'SANITISER_VERSION', 'synthetic-next'):
            second, _ = research.config_revision(config, 10, 'a' * 64)
        self.assertNotEqual(first, second)

    def test_revision_identity_pins_limits(self):
        config = revision_config()
        first, payload = research.config_revision(config, 10, 'a' * 64)
        self.assertEqual(payload['limits']['max_source_bytes'], research.MAX_SOURCE_BYTES)
        with mock.patch.object(research, 'MAX_SOURCE_BYTES', research.MAX_SOURCE_BYTES * 2):
            second, changed = research.config_revision(config, 10, 'a' * 64)
        self.assertNotEqual(first, second)
        self.assertEqual(changed['limits']['max_source_bytes'], research.MAX_SOURCE_BYTES * 2)
        self.assertNotIn('content', str(payload).lower())


class IdentityGateTests(unittest.TestCase):
    def test_conversation_identity_is_off_by_default(self):
        self.assertFalse(research.ResearchConfig({}).identity_enabled)
        self.assertTrue(research.ResearchConfig({'COPILOT_RESEARCH_IDENTITY_ENABLED': 'true'}).identity_enabled)


class CollectionHealthTests(unittest.TestCase):
    def _jobs(self, status, created, finished=None, interval=900):
        return {'collection_enabled': True, 'interval_seconds': interval,
                'jobs': [{'status': status, 'created_at': created, 'finished_at': finished}]}

    def test_healthy_recent_completion(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        jobs = self._jobs('complete', (now - timedelta(minutes=20)).isoformat(),
                          (now - timedelta(minutes=16)).isoformat())
        health = verify.collection_health(jobs, now=now)
        self.assertEqual(health['lag_seconds'], 960)
        self.assertFalse(health['stale'])
        self.assertEqual(health['stuck_running'], 0)

    def test_stale_collection(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        jobs = self._jobs('complete', (now - timedelta(hours=5)).isoformat(),
                          (now - timedelta(hours=5)).isoformat())
        self.assertTrue(verify.collection_health(jobs, now=now)['stale'])

    def test_stuck_running_job(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        jobs = self._jobs('running', (now - timedelta(hours=2)).isoformat())
        self.assertEqual(verify.collection_health(jobs, now=now)['stuck_running'], 1)

    def test_fifty_failures_hide_last_success(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        jobs = {'collection_enabled': True, 'interval_seconds': 900,
                'jobs': [{'status': 'failed', 'created_at': (now - timedelta(minutes=index * 15)).isoformat()}
                         for index in range(50)]}
        health = verify.collection_health(jobs, now=now)
        self.assertIsNone(health['last_complete_at'])
        self.assertTrue(health['stale'])
        self.assertEqual(health['failed_recent'], 50)

    def test_fresh_database_has_grace_period(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        health = verify.collection_health({'collection_enabled': True, 'interval_seconds': 900, 'jobs': []}, now=now)
        self.assertTrue(health['stale'])
        self.assertEqual(health['failed_recent'], 0)
        self.assertIsNone(health['last_complete_at'])

    def test_recent_failure_is_counted_not_fatal(self):
        now = datetime(2026, 10, 28, 9, 0, tzinfo=timezone.utc)
        jobs = self._jobs('failed', (now - timedelta(minutes=10)).isoformat())
        health = verify.collection_health(jobs, now=now)
        self.assertEqual(health['failed_today'], 1)
        self.assertEqual(health['stuck_running'], 0)


if __name__ == '__main__':
    unittest.main()


class SourceByteGateTests(unittest.TestCase):
    """The source limit is UTF-8 bytes, and oversized content is never fetched."""

    def run_worker(self, source_json, stored_bytes):
        import hashlib, json  # noqa: E401
        sha = hashlib.sha256(source_json.encode()).hexdigest()
        meta = {'id': 'a' * 64, 'seq': 7, 'expected_sha256': sha, 'source_bytes': stored_bytes}
        source = {'id': meta['id'], 'seq': 7, 'content_sha256': sha, 'record_json': source_json,
                  'user_id': 'synthetic', 'timestamp': 1, 'type': 'response'}
        fetched, statuses = [], []

        def rows(query):
            if 'SELECT attempt_count' in query:
                return []
            if 'AS expected_sha256' in query:
                return [meta]
            if 'length(record_json)' in query:
                return [{'bytes': stored_bytes}]
            fetched.append(query)
            return [source]

        def insert(table, values):
            if table == 'research_processing':
                statuses.append((values[0]['status'], values[0]['failure_class']))

        config = SimpleNamespace(sanitisation_available=True, detector_model='disabled', sanitiser=lambda: SimpleNamespace(refs=mock.MagicMock()))
        with mock.patch.object(research, 'MAX_SOURCE_BYTES', 64), \
                mock.patch.object(research, 'ResearchConfig', return_value=config), \
                mock.patch.object(research, '_worker_revision', return_value={'revision_id': 'rev_' + 'd' * 32}), \
                mock.patch.object(research, '_checkpoint', return_value=None), \
                mock.patch.object(research.db, 'rows', side_effect=rows), \
                mock.patch.object(research.db, 'insert', side_effect=insert):
            research.process_once({})
        return fetched, statuses

    def test_oversized_record_is_held_before_its_content_is_fetched(self):
        fetched, statuses = self.run_worker('{"body":"' + 'x' * 100 + '"}', 111)
        self.assertEqual(fetched, [])
        self.assertEqual(statuses, [('held', 'source_record_oversized')])

    def test_limit_counts_utf8_bytes_not_characters(self):
        # 40 characters, 120 bytes: under the limit by characters, over it by bytes.
        source = '{"b":"' + '\u20ac' * 40 + '"}'
        fetched, statuses = self.run_worker(source, 0)
        self.assertEqual(statuses, [('held', 'source_record_oversized')])
