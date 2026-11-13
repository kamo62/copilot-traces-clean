#!/usr/bin/env python3
"""Read-only deployment verification; no test conversation, collection job or paid model call."""
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import urllib.error
import urllib.request

ROOT=Path(__file__).resolve().parent


def _time(value):
    return datetime.fromisoformat(value) if value else None


def collection_health(jobs, now=None):
    """Content-free collection health from the bounded job list.

    Reports lag against the configured interval instead of treating any single
    failed poll as an outage: polling retries with a ten-minute overlap, so only
    a stale or stuck scheduler is a real failure.
    """
    now=now or datetime.now(timezone.utc)
    interval=int(jobs.get('interval_seconds') or 900)
    items=jobs.get('jobs') or []
    failed=[job for job in items if job.get('status')=='failed'
            and (_time(job.get('created_at')) or now)>=now.replace(hour=0,minute=0,second=0,microsecond=0)]
    # The job list is bounded, so a long failure run can evict the last success.
    # Count every failure in the window, not only today's.
    failed_recent=[job for job in items if job.get('status')=='failed']
    running=[job for job in items if job.get('status')=='running']
    stuck_after=now.timestamp()-max(1800,interval*3)
    stuck=[job for job in running
           if (_time(job.get('created_at')) or now).timestamp()<=stuck_after]
    last_complete=max((job.get('finished_at') for job in items
                       if job.get('status')=='complete' and job.get('finished_at')),default=None)
    lag=int((now-_time(last_complete)).total_seconds()) if last_complete else None
    return {'enabled':bool(jobs.get('collection_enabled')),
            'interval_seconds':interval,
            'last_complete_at':last_complete,
            'lag_seconds':lag,
            'failed_today':len(failed),
            'failed_recent':len(failed_recent),
            'running':len(running),
            'stuck_running':len(stuck),
            'stale':lag is None or lag>max(1800,interval*3)}


def token_expiry(token, now=None):
    """Read the authenticating token's expiry from GitHub's response header only.

    The token is never printed and no record content is requested. GitHub omits
    the header for classic tokens, so an absent value is reported as unknown.
    """
    now=now or datetime.now(timezone.utc)
    request=urllib.request.Request('https://api.github.com/rate_limit',headers={
        'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','User-Agent':'traces-clean-verify'})
    with urllib.request.urlopen(request,timeout=20) as response:
        expires=response.headers.get('github-authentication-token-expiration')
    if not expires:
        return {'expires_at':None,'days_remaining':None}
    # GitHub can send a timestamp with a UTC suffix for fine-grained tokens, which
    # fromisoformat rejects; accept the UTC/GMT suffixes and numeric offsets.
    text=expires.strip()
    for suffix in (' UTC',' GMT'):
        if text.endswith(suffix):
            text=text[:-len(suffix)]+'+00:00'
            break
    expires_at=datetime.fromisoformat(text.replace('Z','+00:00'))
    return {'expires_at':expires_at.isoformat(),'days_remaining':int((expires_at-now).total_seconds()//86400)}


def main():
    env=dict(line.split('=',1) for line in (ROOT/'.env').read_text().splitlines() if '=' in line and not line.startswith('#'))
    base=os.environ.get('COPILOT_TRACES_API','http://127.0.0.1:13330')
    def get(path,key=None):
        request=urllib.request.Request(base+path,headers={'Authorization':'Bearer '+key} if key else {})
        with urllib.request.urlopen(request,timeout=30) as response:return json.load(response)
    for key in (None,env['COPILOT_STATS_API_KEY']):
        try:get('/v1/review/records',key)
        except urllib.error.HTTPError as error:
            assert error.code==401
        else:raise AssertionError('Content role separation failed')
    health=get('/healthz')
    metadata=get('/v1/review/records?limit=1&order=desc',env['COPILOT_ADMIN_API_KEY'])
    assert metadata['content_included'] is False
    rows=metadata['records']
    if rows:
        record=get('/v1/review/records/'+rows[0]['record_id'],env['COPILOT_ADMIN_API_KEY'])
        content=json.dumps(record['record'],sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)
        assert hashlib.sha256(content.encode()).hexdigest()==record['content_sha256']
    status=get('/v1/copilot/storage',env['COPILOT_STATS_API_KEY'])
    spec=get('/openapi.json')
    assert get('/')['frontend'] is False
    for path in ('/viewer','/viewer/','/review','/review/',
                 '/docs/viewer.html','/docs/viewer.js','/docs/review.html','/docs/review.js'):
        try:get(path)
        except urllib.error.HTTPError as error:
            assert error.code==404
        else:raise AssertionError('Removed frontend still served at '+path)
    assert '/v1/copilot/summary' not in spec['paths']
    assert status['metrics_new_integration'] is False
    collection=collection_health(get('/v1/collection/jobs',env['COPILOT_ADMIN_API_KEY']))
    assert not collection['stuck_running'],'Collection job stuck in running state'
    # A fresh database has no history at all; that is a grace period. A quiet
    # scheduler is a failure whether the last success is visible or has been
    # evicted by a run of failures in the bounded job list.
    assert not (collection['stale'] and (collection['last_complete_at'] or collection['failed_recent'])),'Collection has stalled'
    research_checked=False
    research_key=env.get('COPILOT_RESEARCH_API_KEY','')
    if research_key:
        for path in ('/v1/review/records','/v1/copilot/storage','/v1/collection/jobs','/v1/research/status','/v1/research/review/taxonomy'):
            try:get(path,research_key)
            except urllib.error.HTTPError as error:
                assert error.code==401
            else:raise AssertionError('Research role separation failed for '+path)
        schema=get('/v1/research/schema',research_key)
        assert 'event_id' in schema.get('required',[])
        research_checked=True
    research=get('/v1/research/status',env['COPILOT_ADMIN_API_KEY'])
    release=research['research']
    summary={'release_setting':release['release_setting'],'release_blocked':release['release_blocked'],
             'revisions':len(research['revisions']),'releases':len(research['releases']),
             'records_without_processing_status':research['raw_records_without_any_processing_status'],
             'limits':release.get('limits')}
    token={}
    if os.environ.get('COPILOT_CHECK_TOKEN','').lower() in ('1','true','yes'):
        token=token_expiry((ROOT/'.github-token').read_text().strip())
        assert token['days_remaining'] is None or token['days_remaining']>7,'GitHub token expires within 7 days'
    print(json.dumps({'health':health,'api_version':spec['info']['version'],'custom_frontend_removed':True,
                      'retained_unique_records':status['retained_unique_records'],
                      'content_checksum_sample_passed':bool(rows),'role_separation_passed':True,
                      'research_role_separation_checked':research_checked,
                      'client_telemetry_batches':status['client_telemetry_batches'],
                      'collection':collection,'research':summary,'github_token':token,
                      'metrics_new_integration':False}))

if __name__=='__main__':main()
