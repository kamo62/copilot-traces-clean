"""Serial Enterprise polling with database checkpoints and no archive files."""
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

import archive
from import_records import records_from_bytes

INTERVAL = int(os.environ.get('COPILOT_COLLECTION_INTERVAL_SECONDS', '900'))
ENABLED = os.environ.get('COPILOT_COLLECTION_ENABLED', 'false').lower() == 'true'
ENTERPRISE = os.environ.get('COPILOT_ENTERPRISE', 'example-enterprise')
LOCK = threading.RLock()
DATABASE_ATTEMPTS = 6
DATABASE_MAX_BACKOFF = 30
if not re.fullmatch(r'[a-zA-Z0-9-]+', ENTERPRISE):
    raise ValueError('Invalid enterprise')


class DatabaseRetryExhausted(OSError):
    pass


def retry_database(operation, *args, lock=None):
    """Retry only database reads or idempotent writes, retaining the caller's state.

    With lock, each attempt holds it and the backoff sleeps without it, so API
    handlers waiting on the same lock are not blocked through the retries.
    """
    for attempt in range(DATABASE_ATTEMPTS):
        try:
            if lock is None:
                return operation(*args)
            with lock:
                return operation(*args)
        except archive.db.ClickHouseError as failure:
            if not failure.retryable or attempt == DATABASE_ATTEMPTS - 1:
                raise DatabaseRetryExhausted('Collection database unavailable') from None
            delay = min(DATABASE_MAX_BACKOFF, 2**(attempt + 1))
            print(f'Enterprise ClickHouse retry {attempt + 1}/{DATABASE_ATTEMPTS - 1} in {delay}s '
                  f'(HTTP {failure.http_status}, code {failure.code})', flush=True)
            time.sleep(delay)


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname != 'api.github.com' or parsed.port not in (None,443)
            or parsed.username or parsed.password or parsed.fragment
            or parsed.path != f'/enterprises/{ENTERPRISE}/copilot/usage-records'):
        raise ValueError('Unexpected pagination destination')
    return url


def next_url(header):
    for part in (header or '').split(','):
        match = re.fullmatch(r'\s*<([^>]+)>;\s*rel="next"\s*', part)
        if match:
            return allowed_url(match.group(1))
    return None


def fetch_records():
    token = Path(os.environ.get('COPILOT_GITHUB_TOKEN_FILE', '/run/secrets/github_token')).read_text().strip()
    if not token:
        raise OSError('GitHub token is empty')
    now = datetime.now(timezone.utc)
    state = retry_database(archive.checkpoint, 'records_window')
    if state and state.get('next_url') and datetime.fromisoformat(state['end']) > now-timedelta(hours=48):
        url = state['next_url']
    else:
        start = now-timedelta(hours=48)+timedelta(seconds=2)
        if state:
            start = max(start, datetime.fromisoformat(state['end'])-(timedelta(0) if state.get('fresh_start') else timedelta(minutes=10)))
        floor = retry_database(archive.checkpoint, 'records_started_at')
        if floor:
            start = max(start, datetime.fromisoformat(floor))
        start = min(start, now)
        state = {'start':start.isoformat(),'end':now.isoformat(),'complete':False,'pages':0,'returned_records':0}
        bounds = f"created:{start.strftime('%Y-%m-%dT%H:%M:%SZ')}..{now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        query = urllib.parse.urlencode({'per_page':25,'order':'asc','phrase':bounds})
        url = f'https://api.github.com/enterprises/{ENTERPRISE}/copilot/usage-records?{query}'
    while url:
        request = urllib.request.Request(allowed_url(url), headers={'Authorization':'Bearer '+token,
            'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2026-03-10'})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    raw = response.read()
                    following = next_url(response.headers.get('Link'))
                break
            except urllib.error.HTTPError as error:
                if error.code not in (429,500,502,503,504) or attempt == 3:
                    raise OSError(f'GitHub returned HTTP {error.code}') from None
                time.sleep(min(30,2**(attempt+1)))
            except (urllib.error.URLError,TimeoutError):
                if attempt == 3:
                    raise OSError('GitHub network read failed') from None
                time.sleep(min(30,2**(attempt+1)))
        records = records_from_bytes(raw)
        retry_database(archive.store_records, records, hashlib.sha256(raw).hexdigest())
        # Advance only after ClickHouse acknowledged the insert. Retry overlap is idempotent.
        state.update(next_url=following,pages=state['pages']+1,
                     returned_records=state['returned_records']+len(records),updated_at=archive.now(),complete=not following)
        retry_database(archive.checkpoint, 'records_window', state)
        url = following
        if state['pages'] % 100 == 0 or not following:
            print(f"Enterprise polling: {state['pages']} pages, {state['returned_records']} returned records", flush=True)
        time.sleep(0.2)


def job(identifier=None):
    clause = 'WHERE id='+archive.db.literal(identifier) if identifier else 'ORDER BY created_at DESC LIMIT 50'
    values = archive.db.rows('SELECT * EXCEPT version FROM jobs FINAL '+clause)
    for row in values:
        row['parameters'] = json.loads(row['parameters'])
        for key in ('started_at','finished_at','error'):
            row[key] = row[key] or None
    if identifier:
        if not values:
            raise LookupError('Job not found')
        return values[0]
    return {'collection_enabled':ENABLED,'interval_seconds':INTERVAL,'jobs':values}


def save_job(row):
    value = dict(row)
    value['parameters'] = json.dumps(value['parameters'])
    for key in ('started_at','finished_at','error'):
        value[key] = value.get(key) or ''
    value['version'] = time.time_ns()
    archive.db.insert('jobs',[value])


def create_job(parameters):
    if not isinstance(parameters,dict) or set(parameters) != {'kind'} or parameters['kind'] not in ('records','refresh'):
        raise ValueError('Supply kind records or refresh; daily usage belongs to analytics')
    with LOCK:
        active = archive.db.rows("SELECT id FROM jobs FINAL WHERE status IN ('queued','running') LIMIT 1")
        if active:
            raise BlockingIOError('A collection job is active')
        row = {'id':uuid.uuid4().hex,'kind':parameters['kind'],'parameters':parameters,
               'status':'queued','created_at':archive.now(),'started_at':None,'finished_at':None,'error':None}
        save_job(row)
    return row


def worker():
    try:
        run_worker()
    except Exception as failure:
        # A dead worker must not leave a healthy-looking API with permanently queued jobs.
        print('Enterprise worker stopped ('+type(failure).__name__+'); restarting service for recovery',flush=True)
        os._exit(1)


def run_worker():
    for row in retry_database(job)['jobs']:
        if row['status'] == 'running':
            row.update(status='interrupted',finished_at=archive.now(),error='Service restarted; database checkpoint retained')
            retry_database(save_job, row)
    while True:
        # Each step holds LOCK only per attempt. A queued row counts as active, so
        # create_job cannot add another between these steps; save_job is idempotent.
        values = retry_database(archive.db.rows, "SELECT id FROM jobs FINAL WHERE status='queued' ORDER BY created_at LIMIT 1",
                                lock=LOCK)
        row = retry_database(job, values[0]['id'], lock=LOCK) if values else None
        if row:
            row.update(status='running',started_at=archive.now())
            retry_database(save_job, row, lock=LOCK)
        if not row:
            time.sleep(2)
            continue
        try:
            if row['kind'] == 'records':
                fetch_records()
            else:
                retry_database(archive.status)
        except DatabaseRetryExhausted:
            # Persistent database failure needs recovery, not a failed job with a lost page.
            raise
        except Exception as failure:
            # Only a safe error class is persisted; no provider responses or source bodies.
            row.update(status='failed',error=type(failure).__name__+'; check collector connectivity and token expiry')
        else:
            row.update(status='complete',error=None)
        row['finished_at'] = archive.now()
        retry_database(save_job, row, lock=LOCK)


def scheduler():
    while True:
        time.sleep(INTERVAL)
        try:
            create_job({'kind':'records'})
        except Exception:
            pass


def start():
    retry_database(archive.initialise)
    if retry_database(archive.checkpoint, 'records_started_at') is None:
        prior = retry_database(archive.checkpoint, 'records_window')
        retry_database(archive.checkpoint, 'records_started_at', prior['start'] if prior else archive.now())
    if retry_database(archive.checkpoint, 'records_window') is None:
        timestamp=archive.now()
        retry_database(archive.checkpoint, 'records_window', {'start':timestamp,'end':timestamp,'complete':True,'next_url':None,'pages':0,'returned_records':0,'fresh_start':True})
    if INTERVAL < 60:
        raise ValueError('Collection interval must be at least 60 seconds')
    threading.Thread(target=worker,name='enterprise-worker',daemon=True).start()
    if ENABLED:
        threading.Thread(target=scheduler,name='enterprise-scheduler',daemon=True).start()
