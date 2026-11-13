"""Council November round 2 (Astra): app reads are readonly=2 so abandoned reads are cancelled."""
from pathlib import Path
import sys
import unittest
from unittest import mock
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))

import clickhouse


class Response:
    def __init__(self, body=b''):
        self.body = body

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class ReadonlyReadsTests(unittest.TestCase):
    def sent(self, call):
        requests = []

        def urlopen(request, timeout):
            requests.append(urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query))
            return Response(b'{"n":1}\n')

        with mock.patch.dict('os.environ', {'CLICKHOUSE_PASSWORD': 'invented'}), \
                mock.patch.object(clickhouse.urllib.request, 'urlopen', side_effect=urlopen):
            call()
        return requests[0]

    def test_rows_are_read_only(self):
        self.assertEqual(self.sent(lambda: clickhouse.rows('SELECT 1 AS n'))['readonly'], ['2'])

    def test_writes_are_not_read_only(self):
        self.assertNotIn('readonly', self.sent(lambda: clickhouse.execute('CREATE TABLE IF NOT EXISTS t (x UInt8) ENGINE=Memory')))
        self.assertNotIn('readonly', self.sent(lambda: clickhouse.insert('t', [{'x': 1}])))


class NoQuerySetsReadonlyTests(unittest.TestCase):
    def test_no_sql_settings_clause_sets_readonly(self):
        # rows() sends readonly=2; ClickHouse refuses any query that changes it (164).
        import re
        for folder in ('api', 'tools'):
            for path in sorted((ROOT / folder).glob('*.py')):
                text = path.read_text()
                for match in re.finditer(r'(?i)\bSETTINGS\b[^\n]*', text):
                    self.assertIsNone(re.search(r'\breadonly\s*=', match.group(0)), str(path))


if __name__ == '__main__':
    unittest.main()
