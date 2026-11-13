"""Exact Enterprise records and OTLP content in ClickHouse, without file archives."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from import_records import records_from_bytes
import clickhouse as db

WRITE_LOCK = threading.RLock()
initialise = db.initialise


def now():
    return datetime.now(timezone.utc).isoformat()


def canonical(record):
    return json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def record_id(record):
    stable = str(record['event_id']) if record.get('event_id') else json.dumps(record, sort_keys=True)
    return hashlib.sha256(stable.encode()).hexdigest()


def store_records(records, source_sha256=''):
    """Deduplicate overlap. Reject changed content for an existing event ID."""
    with WRITE_LOCK:
        unique = {}
        for record in records:
            identifier = record_id(record)
            if identifier in unique and canonical(unique[identifier]) != canonical(record):
                raise ValueError('Conflicting records within a page')
            unique[identifier] = record
        if not unique:
            return 0
        ids = ','.join(db.literal(identifier) for identifier in unique)
        existing = {row['id']: row['content_sha256'] for row in db.rows(
            'SELECT id,content_sha256 FROM records FINAL WHERE id IN (' + ids + ')')}
        seq = int(db.rows('SELECT ifNull(max(seq),0) AS seq FROM records')[0]['seq'])
        values = []
        for identifier, record in unique.items():
            content = canonical(record)
            digest = hashlib.sha256(content.encode()).hexdigest()
            if identifier in existing:
                if existing[identifier] != digest:
                    raise ValueError('Conflicting content for an existing event ID; earlier log preserved')
                continue
            seq += 1
            values.append({'id': identifier, 'seq': seq,
                'event_id': str(record.get('event_id') or ''), 'user_id': record['user_id'],
                'timestamp': record['@timestamp'], 'type': record['type'],
                'request_id': record['github_request_id'], 'endpoint': record.get('endpoint', ''),
                'source_sha256': source_sha256, 'content_sha256': digest,
                'record_json': content, 'version': time.time_ns()})
        db.insert('records', values)
        return len(values)


def ingest_records(raw):
    records = records_from_bytes(raw)
    if not 1 <= len(records) <= 1000:
        raise ValueError('Supply 1 to 1000 records')
    digest = hashlib.sha256(raw).hexdigest()
    inserted = store_records(records, digest)
    return {'source_sha256': digest, 'submitted_records': len(records), 'inserted_records': inserted,
            'retained': True, 'deduplication': 'Stable event IDs; exact record objects and body strings in ClickHouse'}


def status():
    records = db.rows('SELECT count() AS retained_unique_records,min(timestamp) AS first_timestamp_ms,'
                      'max(timestamp) AS latest_timestamp_ms FROM records FINAL')[0]
    size = db.rows("SELECT sum(bytes_on_disk) AS database_bytes_on_disk FROM system.parts WHERE active AND database=" + db.literal(db.DATABASE))[0]
    batches = db.rows('SELECT signal,count() AS batches FROM client_batches FINAL GROUP BY signal ORDER BY signal')
    return {'storage': 'ClickHouse on an SSD-backed Docker named volume',
            'source': 'Enterprise Usage Records API and independent optional client OTLP',
            'metrics_new_integration': False, **records, **size, 'client_telemetry_batches': batches,
            'collection_checkpoint': checkpoint('records_window')}


def review_records(after=0, limit=25, request_id=None, order='asc'):
    where = ('seq<' + str(after) if after else 'seq>=0') if order == 'desc' else 'seq>' + str(after)
    if request_id:
        where += ' AND request_id=' + db.literal(request_id)
    values = db.rows('SELECT seq AS cursor,id AS record_id,event_id,user_id,timestamp,type,request_id,endpoint '
                     'FROM records FINAL WHERE ' + where + ' ORDER BY seq ' + order.upper() + ' LIMIT ' + str(limit))
    return {'records': values, 'next_after': int(values[-1]['cursor']) if values else None, 'content_included': False}


def review_record(identifier):
    values = db.rows('SELECT source_sha256,content_sha256,record_json FROM records FINAL PREWHERE id=' + db.literal(identifier) + ' SETTINGS max_threads=1,max_block_size=1')
    if not values:
        raise LookupError('Record not found')
    row = values[0]
    if hashlib.sha256(row['record_json'].encode()).hexdigest() != row['content_sha256']:
        raise OSError('Content checksum mismatch')
    return {'record_id': identifier, 'source_sha256': row['source_sha256'],
            'content_sha256': row['content_sha256'], 'record': json.loads(row['record_json'])}


def checkpoint(key, value=None):
    if value is not None:
        db.insert('checkpoints', [{'key': key, 'value': json.dumps(value), 'version': time.time_ns()}])
    rows = db.rows('SELECT value FROM checkpoints FINAL WHERE key=' + db.literal(key))
    return json.loads(rows[0]['value']) if rows else None


def store_telemetry(signal, raw):
    if signal not in ('traces','logs','metrics'):
        raise ValueError('Invalid signal')
    value = json.loads(raw)
    key = {'traces':'resourceSpans','logs':'resourceLogs','metrics':'resourceMetrics'}[signal]
    if not isinstance(value, dict) or set(value) - {key} or not isinstance(value.get(key), list):
        raise ValueError('Supply an OTLP JSON export request')
    services = set()
    for resource in value[key]:
        if not isinstance(resource, dict):
            raise ValueError('Invalid OTLP resource')
        for attribute in resource.get('resource', {}).get('attributes', []):
            if attribute.get('key') == 'service.name':
                services.add(attribute.get('value', {}).get('stringValue', ''))
    payload = canonical(value)
    identifier = hashlib.sha256(payload.encode()).hexdigest()
    with WRITE_LOCK:
        exists = db.rows('SELECT id FROM client_batches FINAL WHERE signal=' + db.literal(signal) + ' AND id=' + db.literal(identifier))
        if not exists:
            db.insert('client_batches', [{'id':identifier,'signal':signal,'received_at':now(),
                'service_name': ', '.join(sorted(services)), 'payload':payload,'version':time.time_ns()}])
    return identifier


def telemetry(identifier=None):
    if identifier:
        values = db.rows('SELECT signal,payload FROM client_batches FINAL WHERE id=' + db.literal(identifier))
        if not values:
            raise LookupError('Client batch not found')
        payload = values[0]['payload']
        if hashlib.sha256(payload.encode()).hexdigest() != identifier:
            raise OSError('Client content checksum mismatch')
        return {'batch_id':identifier,'signal':values[0]['signal'],'payload':json.loads(payload)}
    return {'batches':db.rows('SELECT id AS batch_id,signal,received_at,service_name FROM client_batches FINAL ORDER BY received_at DESC LIMIT 100')}
