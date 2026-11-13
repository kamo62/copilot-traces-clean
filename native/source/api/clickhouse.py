"""Authenticated HTTP SQL for the independent traces database."""
import base64
import http.client
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

DATABASE = os.environ.get('CLICKHOUSE_DATABASE', 'copilot_traces')
if not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_]*', DATABASE):
    raise ValueError('Invalid database name')

TRANSIENT_CODES = frozenset((159, 202, 203, 209, 210, 241, 252, 279, 319))


class ClickHouseError(OSError):
    """Content-free failure metadata; never include a query, URL or response body."""
    def __init__(self, code=None, http_status=None):
        super().__init__('ClickHouse operation failed')
        self.code = code
        self.http_status = http_status
        self.retryable = (code in TRANSIENT_CODES if code is not None else
                          http_status is None or http_status in (429, 500, 502, 503, 504))


def literal(value):
    return "'" + str(value).replace('\\', '\\\\').replace("'", "\\'") + "'"


def execute(sql, data=None, read_only=False):
    endpoint = os.environ.get('CLICKHOUSE_URL', 'http://clickhouse:8123').rstrip('/')
    password = os.environ.get('CLICKHOUSE_PASSWORD', '')
    if not password:
        raise OSError('ClickHouse credential is required')
    query = urllib.parse.urlencode({'database': DATABASE, 'query': sql,
                                   'wait_end_of_query': '1', 'buffer_size': '1048576', 'output_format_json_quote_64bit_integers': '0',
                                   # readonly=2 still allows per-query SETTINGS, except 'readonly'
                                   # itself. It lets ClickHouse cancel a read whose client went away.
                                   **({'readonly': '2'} if read_only else {})})
    auth = (os.environ.get('CLICKHOUSE_USER', 'copilot') + ':' + password).encode()
    request = urllib.request.Request(endpoint + '/?' + query, data=data or b'', headers={
        'Authorization': 'Basic ' + base64.b64encode(auth).decode(),
        'Content-Type': 'application/octet-stream'})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            return response.read()
    except urllib.error.HTTPError as failure:
        value = (failure.headers or {}).get('X-ClickHouse-Exception-Code', '')
        code = int(value) if isinstance(value, str) and re.fullmatch(r'[0-9]{1,6}', value) else None
        failure.close()
        raise ClickHouseError(code, failure.code) from None
    except (OSError, http.client.HTTPException):
        # SQL can contain source content; never include provider exception bodies or URLs.
        raise ClickHouseError() from None


def rows(sql):
    return [json.loads(line) for line in execute(sql + ' FORMAT JSONEachRow', read_only=True).splitlines() if line]


def insert(table, values):
    if not re.fullmatch(r'[a-z_][a-z0-9_]*', table):
        raise ValueError('Invalid table')
    if values:
        raw = b'\n'.join(json.dumps(row, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
                         for row in values) + b'\n'
        execute('INSERT INTO ' + table + ' FORMAT JSONEachRow', raw)


def initialise():
    for ddl in (
        """CREATE TABLE IF NOT EXISTS records (
          id FixedString(64), seq UInt64, event_id String, user_id UInt64, timestamp Int64,
          type LowCardinality(String), request_id String, endpoint String,
          source_sha256 String, content_sha256 FixedString(64), record_json String CODEC(ZSTD(3)),
          version UInt64, INDEX request_idx request_id TYPE bloom_filter GRANULARITY 4
        ) ENGINE=ReplacingMergeTree(version) ORDER BY id""",
        """CREATE TABLE IF NOT EXISTS client_batches (
          id FixedString(64), signal LowCardinality(String), received_at String,
          service_name String, payload String CODEC(ZSTD(3)), version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (signal,id)""",
        """CREATE TABLE IF NOT EXISTS jobs (
          id String, kind String, parameters String, status String, created_at String,
          started_at String, finished_at String, error String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY id""",
        """CREATE TABLE IF NOT EXISTS checkpoints (
          key String, value String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY key""",
        """CREATE VIEW IF NOT EXISTS client_spans AS SELECT
          JSONExtractString(span,'traceId') AS trace_id, JSONExtractString(span,'spanId') AS span_id,
          JSONExtractString(span,'parentSpanId') AS parent_span_id, JSONExtractString(span,'name') AS span_name,
          JSONExtractString(span,'startTimeUnixNano') AS start_time_unix_nano,
          JSONExtractRaw(span,'attributes') AS attributes_json, span AS full_span_json,
          JSONExtractRaw(resource,'resource') AS resource_json, service_name, id AS batch_id
          FROM (SELECT id,service_name,resource,arrayJoin(JSONExtractArrayRaw(resource,'scopeSpans')) AS scope
                FROM (SELECT id,service_name,arrayJoin(JSONExtractArrayRaw(payload,'resourceSpans')) AS resource
                      FROM client_batches FINAL WHERE signal='traces'))
          ARRAY JOIN JSONExtractArrayRaw(scope,'spans') AS span""",
    ):
        execute(ddl)
