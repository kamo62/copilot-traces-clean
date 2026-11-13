"""Lane E: invented-only collection recovery; no database or network is contacted."""
from contextlib import contextmanager, ExitStack
from datetime import datetime, timezone
import http.client
import io
import json
import os
from pathlib import Path
import re
import runpy
import sys
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))

import archive
import clickhouse
import collection


class StopWorker(BaseException):
    """Stop an otherwise infinite worker without exercising its failure handler."""


def record(number=1):
    return {'event_id': 'invented-event-' + str(number), 'user_id': 7,
            '@timestamp': 1760000000000, 'type': 'request',
            'github_request_id': 'invented-request-' + str(number),
            'body': json.dumps({'messages': [{'role': 'user', 'content': 'invented task'}]})}


def page_url(number):
    return f'https://api.github.com/enterprises/{collection.ENTERPRISE}/copilot/usage-records?page={number}'


class Response(io.BytesIO):
    def __init__(self, records, following=None):
        super().__init__(json.dumps(records).encode())
        self.headers = {'Link': '<' + following + '>; rel="next"'} if following else {}


class Database:
    """Small replacing-table mock, including commits whose acknowledgement is lost."""
    def __init__(self):
        self.tables = {'records': {}, 'jobs': {}, 'checkpoints': {}}
        self.faults = []
        self.writes = []
        self.queries = []
        self.stop_when_idle = False
        stamp = datetime.now(timezone.utc).isoformat()
        self.tables['checkpoints']['records_window'] = {
            'key': 'records_window', 'version': 1,
            'value': json.dumps({'start': stamp, 'end': stamp, 'next_url': page_url(1),
                                 'complete': False, 'pages': 0, 'returned_records': 0})}

    def add_fault(self, method, predicate, after=False, times=1, error=None):
        self.faults.append({'method': method, 'predicate': predicate, 'after': after,
                            'remaining': times, 'error': error or clickhouse.ClickHouseError(241, 500)})

    def _fault(self, method, args, after):
        for fault in self.faults:
            if (fault['remaining'] and fault['method'] == method and fault['after'] == after
                    and fault['predicate'](*args)):
                fault['remaining'] -= 1
                raise fault['error']

    def insert(self, table, values):
        self._fault('insert', (table, values), False)
        self.writes.append((table, json.loads(json.dumps(values))))
        for row in values:
            key = row['key'] if table == 'checkpoints' else row['id']
            previous = self.tables[table].get(key)
            if previous is None or row['version'] >= previous['version']:
                self.tables[table][key] = json.loads(json.dumps(row))
        self._fault('insert', (table, values), True)

    def rows(self, query):
        self.queries.append(query)
        self._fault('rows', (query,), False)
        if query.startswith('SELECT id,content_sha256 FROM records FINAL'):
            ids = re.findall(r"'([a-f0-9]{64})'", query)
            result = [{'id': identifier, 'content_sha256': self.tables['records'][identifier]['content_sha256']}
                      for identifier in ids if identifier in self.tables['records']]
        elif query.startswith('SELECT ifNull(max(seq),0) AS seq FROM records'):
            result = [{'seq': max((row['seq'] for row in self.tables['records'].values()), default=0)}]
        elif query.startswith('SELECT value FROM checkpoints FINAL WHERE key='):
            key = re.search(r"key='([^']+)'", query).group(1)
            row = self.tables['checkpoints'].get(key)
            result = [{'value': row['value']}] if row else []
        elif query.startswith('SELECT * EXCEPT version FROM jobs FINAL'):
            if 'WHERE id=' in query:
                identifier = re.search(r"id='([^']+)'", query).group(1)
                values = [self.tables['jobs'][identifier]] if identifier in self.tables['jobs'] else []
            else:
                values = list(self.tables['jobs'].values())
            result = [{key: value for key, value in row.items() if key != 'version'} for row in values]
        elif query.startswith("SELECT id FROM jobs FINAL WHERE status='queued'"):
            values = [row for row in self.tables['jobs'].values() if row['status'] == 'queued']
            if not values and self.stop_when_idle:
                raise StopWorker()
            result = [{'id': row['id']} for row in values[:1]]
        else:
            raise AssertionError('Unexpected invented database query')
        self._fault('rows', (query,), True)
        return json.loads(json.dumps(result))

    def checkpoint(self):
        return json.loads(self.tables['checkpoints']['records_window']['value'])

    def queue(self):
        identifier = 'a' * 32
        self.tables['jobs'][identifier] = {
            'id': identifier, 'kind': 'records', 'parameters': '{"kind":"records"}',
            'status': 'queued', 'created_at': archive.now(), 'started_at': '',
            'finished_at': '', 'error': '', 'version': 1}
        self.stop_when_idle = True
        return identifier


class CollectionResilienceTests(unittest.TestCase):
    @contextmanager
    def database(self, database):
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(archive.db, 'rows', side_effect=database.rows))
            stack.enter_context(mock.patch.object(archive.db, 'insert', side_effect=database.insert))
            stack.enter_context(mock.patch.object(collection.Path, 'read_text', return_value='invented-token'))
            sleep = stack.enter_context(mock.patch.object(collection.time, 'sleep'))
            output = stack.enter_context(mock.patch('builtins.print'))
            exit_process = stack.enter_context(mock.patch.object(collection.os, '_exit'))
            yield SimpleNamespace(sleep=sleep, output=output, exit=exit_process)

    def test_transient_database_read_uses_bounded_exponential_backoff(self):
        with mock.patch.object(archive.db, 'rows', side_effect=[
                clickhouse.ClickHouseError(241, 500), clickhouse.ClickHouseError(), [{'ready': 1}]
                ]) as rows, mock.patch.object(collection.time, 'sleep') as sleep, \
                mock.patch('builtins.print') as output:
            self.assertEqual(collection.retry_database(archive.db.rows, 'SELECT 1 AS ready'), [{'ready': 1}])
        self.assertEqual(rows.call_count, 3)
        self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(4)])
        self.assertIn('code 241', str(output.call_args_list))

    def test_persistent_database_failure_restarts_only_after_all_attempts(self):
        with mock.patch.object(archive.db, 'rows', side_effect=clickhouse.ClickHouseError(241, 500)) as rows, \
                mock.patch.object(collection.time, 'sleep') as sleep, \
                mock.patch.object(collection.os, '_exit') as exit_process, mock.patch('builtins.print'):
            collection.worker()
        self.assertEqual(rows.call_count, 6)
        self.assertEqual(sleep.call_args_list, [mock.call(value) for value in (2, 4, 8, 16, 30)])
        exit_process.assert_called_once_with(1)

    def test_permanent_database_failure_does_not_retry(self):
        with mock.patch.object(archive.db, 'rows', side_effect=clickhouse.ClickHouseError(62, 400)) as rows, \
                mock.patch.object(collection.time, 'sleep') as sleep, \
                mock.patch.object(collection.os, '_exit') as exit_process, mock.patch('builtins.print'):
            collection.worker()
        rows.assert_called_once()
        sleep.assert_not_called()
        exit_process.assert_called_once_with(1)

    def test_success_resets_retry_budget_for_the_next_operation(self):
        outcomes = ([clickhouse.ClickHouseError(241, 500)] * 5 + [[{'ready': 1}]]) * 2
        with mock.patch.object(archive.db, 'rows', side_effect=outcomes) as rows, \
                mock.patch.object(collection.time, 'sleep') as sleep, mock.patch('builtins.print'):
            for _ in range(2):
                self.assertEqual(collection.retry_database(archive.db.rows, 'SELECT 1 AS ready'), [{'ready': 1}])
        self.assertEqual(rows.call_count, 12)
        self.assertEqual(sleep.call_args_list, [mock.call(value) for value in (2, 4, 8, 16, 30)] * 2)

    def test_non_database_errors_are_not_retried(self):
        with mock.patch.object(archive, 'store_records', side_effect=ValueError('invented conflict')), \
                mock.patch.object(collection.time, 'sleep') as sleep:
            with self.assertRaises(ValueError):
                collection.retry_database(archive.store_records, [record()])
        sleep.assert_not_called()

    def test_plain_os_error_is_not_a_database_retry(self):
        with mock.patch.object(collection.time, 'sleep') as sleep:
            with self.assertRaises(OSError):
                collection.retry_database(mock.Mock(side_effect=OSError('GitHub token is empty')))
        sleep.assert_not_called()

    def test_backoff_releases_the_lock_for_job_creation(self):
        import threading
        created = []

        def sleep(_delay):
            # Another thread (an API handler) must be able to take LOCK here.
            def handler():
                acquired = collection.LOCK.acquire(timeout=1)
                created.append(acquired)
                if acquired:
                    collection.LOCK.release()
            worker = threading.Thread(target=handler)
            worker.start()
            worker.join()

        with mock.patch.object(archive.db, 'rows', side_effect=[clickhouse.ClickHouseError(241, 500), [{'ready': 1}]]), \
                mock.patch.object(collection.time, 'sleep', side_effect=sleep), mock.patch('builtins.print'):
            self.assertEqual(collection.retry_database(archive.db.rows, 'SELECT 1', lock=collection.LOCK), [{'ready': 1}])
        self.assertEqual(created, [True])

    def test_page_recovery_preserves_checkpoint_and_deduplicates_lost_insert_ack(self):
        database = Database()
        database.add_fault('insert', lambda table, values: table == 'records', after=True)
        database.add_fault('insert', lambda table, values: table == 'checkpoints', after=True)
        with self.database(database) as controls, mock.patch.object(collection.urllib.request, 'urlopen',
                side_effect=[Response([record(1)], page_url(2)), Response([record(1), record(2)])]) as fetch:
            collection.fetch_records()
        self.assertEqual([call.args[0].full_url for call in fetch.call_args_list], [page_url(1), page_url(2)])
        self.assertEqual(len(database.tables['records']), 2)
        self.assertEqual(sorted(row['seq'] for row in database.tables['records'].values()), [1, 2])
        self.assertEqual(sum(len(values) for table, values in database.writes if table == 'records'), 2)
        state = database.checkpoint()
        self.assertEqual((state['pages'], state['returned_records'], state['next_url'], state['complete']),
                         (2, 3, None, True))
        self.assertEqual(controls.sleep.call_args_list, [mock.call(2), mock.call(2), mock.call(0.2), mock.call(0.2)])
        controls.exit.assert_not_called()

    def test_checkpoint_read_after_ack_is_retried_without_advancing_twice(self):
        database = Database()
        database.add_fault('rows', lambda query: query.startswith('SELECT value FROM checkpoints')
                           and database.checkpoint()['pages'] == 1)
        with self.database(database), mock.patch.object(collection.urllib.request, 'urlopen',
                return_value=Response([record()])) as fetch:
            collection.fetch_records()
        fetch.assert_called_once()
        self.assertEqual(database.checkpoint()['pages'], 1)
        self.assertEqual(database.checkpoint()['returned_records'], 1)
        self.assertEqual(len(database.tables['records']), 1)

    def test_checkpoint_failure_before_ack_never_fetches_the_following_page(self):
        database = Database()
        database.add_fault('insert', lambda table, values: table == 'checkpoints', times=6)
        with self.database(database), mock.patch.object(collection.urllib.request, 'urlopen',
                return_value=Response([record()], page_url(2))) as fetch:
            with self.assertRaises(collection.DatabaseRetryExhausted):
                collection.fetch_records()
        fetch.assert_called_once()
        self.assertEqual(database.checkpoint()['next_url'], page_url(1))
        self.assertEqual(database.checkpoint()['pages'], 0)
        self.assertEqual(len(database.tables['records']), 1)
        # A later worker resumes the old page; its already committed record is not duplicated.
        with self.database(database), mock.patch.object(collection.urllib.request, 'urlopen',
                side_effect=[Response([record()], page_url(2)), Response([record(2)])]):
            collection.fetch_records()
        self.assertEqual(len(database.tables['records']), 2)
        self.assertEqual(database.checkpoint()['returned_records'], 2)
        self.assertEqual(database.checkpoint()['pages'], 2)

    def test_unacknowledged_record_write_does_not_advance_checkpoint(self):
        database = Database()
        database.add_fault('insert', lambda table, values: table == 'records', times=6)
        with self.database(database), mock.patch.object(collection.urllib.request, 'urlopen',
                return_value=Response([record()], page_url(2))) as fetch:
            with self.assertRaises(collection.DatabaseRetryExhausted):
                collection.fetch_records()
        fetch.assert_called_once()
        self.assertEqual(database.checkpoint()['pages'], 0)
        self.assertEqual(database.checkpoint()['next_url'], page_url(1))
        self.assertEqual(len(database.tables['records']), 0)

    def test_worker_retries_poll_claim_and_completion_without_refetching_job(self):
        database = Database()
        identifier = database.queue()
        database.add_fault('rows', lambda query: query.startswith("SELECT id FROM jobs FINAL WHERE status='queued'"))
        for status in ('running', 'complete'):
            database.add_fault('insert', lambda table, values, status=status:
                               table == 'jobs' and values[0]['status'] == status, after=True)
        with self.database(database) as controls, mock.patch.object(collection.urllib.request, 'urlopen',
                return_value=Response([record()])) as fetch:
            with self.assertRaises(StopWorker):
                collection.worker()
        fetch.assert_called_once()
        self.assertEqual(database.tables['jobs'][identifier]['status'], 'complete')
        self.assertEqual(database.tables['jobs'][identifier]['error'], '')
        self.assertEqual(len(database.tables['records']), 1)
        self.assertEqual(database.checkpoint()['pages'], 1)
        self.assertEqual(controls.sleep.call_args_list, [mock.call(2), mock.call(2), mock.call(0.2), mock.call(2)])
        controls.exit.assert_not_called()

    def test_exhausted_record_write_restarts_instead_of_marking_job_failed(self):
        database = Database()
        identifier = database.queue()
        database.add_fault('insert', lambda table, values: table == 'records', times=6)
        with self.database(database) as controls, mock.patch.object(collection.urllib.request, 'urlopen',
                return_value=Response([record()])) as fetch:
            collection.worker()
        fetch.assert_called_once()
        self.assertEqual(database.tables['jobs'][identifier]['status'], 'running')
        self.assertEqual(database.checkpoint()['pages'], 0)
        self.assertEqual(controls.sleep.call_args_list, [mock.call(value) for value in (2, 4, 8, 16, 30)])
        controls.exit.assert_called_once_with(1)

    def test_github_failure_remains_a_failed_job_not_a_database_retry(self):
        database = Database()
        identifier = database.queue()
        error = urllib.error.HTTPError(page_url(1), 401, 'invented token failure', {}, io.BytesIO())
        with self.database(database) as controls, mock.patch.object(collection.urllib.request, 'urlopen',
                side_effect=error) as fetch:
            with self.assertRaises(StopWorker):
                collection.worker()
        error.close()
        fetch.assert_called_once()
        self.assertEqual(database.tables['jobs'][identifier]['status'], 'failed')
        self.assertEqual(database.checkpoint()['pages'], 0)
        self.assertNotIn('invented token failure', database.tables['jobs'][identifier]['error'])
        controls.sleep.assert_not_called()
        controls.exit.assert_not_called()

    def test_collection_start_retries_schema_and_checkpoint_operations(self):
        database = Database()
        database.tables['checkpoints'].clear()
        database.add_fault('rows', lambda query: "key='records_started_at'" in query)
        database.add_fault('insert', lambda table, values: table == 'checkpoints', after=True)
        with self.database(database) as controls, mock.patch.object(archive, 'initialise',
                side_effect=[clickhouse.ClickHouseError(241, 500), None]) as initialise, \
                mock.patch.object(collection.threading, 'Thread') as thread, \
                mock.patch.object(collection, 'ENABLED', False):
            collection.start()
        self.assertEqual(initialise.call_count, 2)
        self.assertEqual(controls.sleep.call_args_list, [mock.call(2)] * 3)
        self.assertTrue(database.checkpoint()['fresh_start'])
        self.assertEqual(database.checkpoint()['pages'], 0)
        thread.assert_called_once_with(target=collection.worker, name='enterprise-worker', daemon=True)
        thread.return_value.start.assert_called_once()

    def test_service_bootstrap_retries_raw_schema_before_starting_server(self):
        import auth
        import research
        import review
        with mock.patch.object(Path, 'read_text', return_value='invented-token'), \
                mock.patch.object(auth, 'validate_credentials'), mock.patch.object(os, 'umask'), \
                mock.patch.object(archive, 'initialise', side_effect=[clickhouse.ClickHouseError(241, 500), None]) as initialise, \
                mock.patch.object(research, 'initialise'), mock.patch.object(review, 'initialise'), \
                mock.patch.object(collection, 'start'), mock.patch.object(collection.time, 'sleep') as sleep, \
                mock.patch('builtins.print'), mock.patch('http.server.ThreadingHTTPServer') as server:
            runpy.run_path(str(ROOT / 'api' / 'service.py'), run_name='__main__')
        self.assertEqual(initialise.call_count, 2)
        sleep.assert_called_once_with(2)
        server.return_value.serve_forever.assert_called_once()


class ClickHouseFailureTests(unittest.TestCase):
    def test_http_failure_classification_uses_numeric_headers_not_private_bodies(self):
        for status, code, retryable in ((500, '241', True), (500, '202', True),
                                       (400, '62', False), (404, '60', False),
                                       (401, '516', False), (429, '', True),
                                       (500, '', True), (503, '', True), (403, '', False),
                                       (500, 'invented private header', True)):
            with self.subTest(status=status, code=code):
                body = io.BytesIO(b'invented private provider body')
                error = urllib.error.HTTPError('http://invented.invalid/?query=invented-private-query',
                                               status, 'invented private reason',
                                               {'X-ClickHouse-Exception-Code': code}, body)
                with mock.patch.dict(os.environ, {'CLICKHOUSE_PASSWORD': 'invented-password'}), \
                        mock.patch.object(clickhouse.urllib.request, 'urlopen', side_effect=error) as open_url:
                    with self.assertRaises(clickhouse.ClickHouseError) as caught:
                        clickhouse.execute('SELECT invented_private_query')
                failure = caught.exception
                self.assertIsInstance(failure, OSError)
                self.assertEqual(failure.retryable, retryable)
                self.assertEqual(failure.code, int(code) if code.isdigit() else None)
                self.assertEqual(failure.http_status, status)
                self.assertEqual(str(failure), 'ClickHouse operation failed')
                self.assertIsNone(failure.__cause__)
                self.assertTrue(failure.__suppress_context__)
                self.assertTrue(body.closed)
                open_url.assert_called_once()  # Non-worker API requests do not retry here.

    def test_network_and_response_read_failures_are_content_free_and_retryable(self):
        for error in (urllib.error.URLError('invented private URL'), TimeoutError('invented timeout'),
                      ConnectionResetError('invented reset'), http.client.RemoteDisconnected('invented disconnect'),
                      http.client.IncompleteRead(b'invented private response', 100)):
            with self.subTest(error=type(error).__name__):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.read.side_effect = error
                with mock.patch.dict(os.environ, {'CLICKHOUSE_PASSWORD': 'invented-password'}), \
                        mock.patch.object(clickhouse.urllib.request, 'urlopen', return_value=response):
                    with self.assertRaises(clickhouse.ClickHouseError) as caught:
                        clickhouse.execute('SELECT 1')
                self.assertTrue(caught.exception.retryable)
                self.assertIsNone(caught.exception.code)
                self.assertIsNone(caught.exception.http_status)
                self.assertEqual(str(caught.exception), 'ClickHouse operation failed')
                self.assertTrue(caught.exception.__suppress_context__)


if __name__ == '__main__':
    unittest.main()
