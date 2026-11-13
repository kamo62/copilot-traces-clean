#!/usr/bin/env python3
"""Opt-in disposable ClickHouse test. NEVER point at a live POC database.

Set COPILOT_SYNTHETIC_DATABASE_ACK=empty-disposable and CLICKHOUSE_URL/password.
Runs only when the database has no source records; it deliberately leaves its
invented fixture for inspection until the disposable container is removed.
"""
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
import archive
import research
import research_reader


def main():
    if os.environ.get('COPILOT_SYNTHETIC_DATABASE_ACK') != 'empty-disposable':
        raise SystemExit('Explicit disposable-database acknowledgement required')
    archive.initialise();research.initialise()
    if int(archive.status()['retained_unique_records']) != 0:
        raise SystemExit('Refusing to write synthetic data to a non-empty database')
    with tempfile.TemporaryDirectory(prefix='research-integration-') as directory:
        root = Path(directory)
        (root/'key').write_bytes(b'synthetic-key-only-'*3)
        policy = {'policy_version':'integration-1','scope':'synthetic-only',
                  'aliases':{'organisations':['ExampleCorp']},'assisted_detector':{'enabled':False}}
        (root/'policy.json').write_text(json.dumps(policy))
        os.environ.update(COPILOT_RESEARCH_POLICY_FILE=str(root/'policy.json'),
                          COPILOT_RESEARCH_PSEUDONYM_KEY_FILE=str(root/'key'),
                          COPILOT_RESEARCH_RETENTION_RAW='manual', COPILOT_RESEARCH_RETENTION_CURATED='manual',
                          COPILOT_RESEARCH_RELEASE_SETTING='held')
        messages=[{'role':'user','content':'Find the test issue. 東京\u2028second line'},
                  {'role':'assistant','content':[{'type':'tool_use','id':'tool-1','name':'read',
                     'input':{'path':'/home/example/ExampleCorp/tests/example.py'}}]},
                  {'role':'user','content':[{'type':'tool_result','tool_use_id':'tool-1','content':'synthetic result'}]}]
        records=[]
        for number in range(3):
            records.append({'event_id':'synthetic-event-'+str(number),'user_id':1,
                '@timestamp':int(time.time()*1000),'type':'request','github_request_id':'synthetic-gateway-'+str(number),
                'headers':{'x-agent-task-id':'synthetic-task'},'body':json.dumps({'messages':messages})})
        # Oversized input remains raw and is held before any parsing/loading into the worker.
        records.append({**records[0],'event_id':'synthetic-oversized',
                        'body':json.dumps({'input':'x'*(research.MAX_SOURCE_BYTES+1)})})
        stream = [
            {'type':'message_start','message':{'role':'assistant','content':[]}},
            {'type':'content_block_start','index':0,'content_block':{'type':'text','text':''}},
            {'type':'content_block_delta','index':0,'delta':{'type':'text_delta','text':'Keep this observed text.'}},
            {'type':'content_block_delta','index':0,'delta':{'type':'citations_delta','citation':'INVENTED_UNSUPPORTED_CITATION'}},
            {'type':'message_stop'},
        ]
        records.append({**records[0],'event_id':'synthetic-mixed-stream','type':'response',
                        'body':'\n\n'.join('data: '+json.dumps(frame) for frame in stream)+'\n\n'})
        nested = {'role':'tool','tool_call_id':'nested-tool','content':[
            {'type':'text','text':'Keep this ordinary nested result.'},
            {'type':'document','source':{'type':'text','text':'INVENTED_RESTRICTED_DOCUMENT'}},
        ]}
        records.append({**records[0],'event_id':'synthetic-nested-exclusion',
                        'body':json.dumps({'messages':[nested]})})
        assert archive.store_records(records)==len(records)
        assert archive.store_records(records)==0
        originals = research.db.rows('SELECT id,record_json,content_sha256 FROM records FINAL ORDER BY id')
        for row in originals:
            assert hashlib.sha256(row['record_json'].encode()).hexdigest()==row['content_sha256']
        while True:
            result=research.process_once()
            if result['status']=='finalised':break
            assert result['status']=='processed',result
        assert result['held_records']==1 and result['failed_records']==0
        revision=result['revision_id']
        assert research.process_once()['status']=='idle'
        try:research.release_revision(revision,True)
        except research.HoldError:pass
        else:raise AssertionError('Default release gate bypassed')
        # This switch approves ONLY this invented fixture, never a production dataset.
        os.environ['COPILOT_RESEARCH_RELEASE_SETTING']='evaluated'
        research.release_revision(revision,True)
        manifest=research.manifest(revision)
        export=root/'events.jsonl'
        cursor=None; ids=[]; pages=0
        with export.open('wb') as handle:
            while True:
                body,_,headers=research.export_jsonl(revision,cursor,limit=2,compress=True)
                raw=gzip.decompress(body)
                assert hashlib.sha256(raw).hexdigest()==headers['X-Research-Page-SHA256']
                handle.write(raw);pages+=1
                ids.extend(json.loads(line)['event_id'] for line in raw.split(b'\n') if line)
                cursor=headers.get('X-Research-Next-Cursor') or None
                if not cursor:
                    assert headers['X-Research-Complete']=='true';break
        assert len(ids)==len(set(ids))==manifest['counts']['events']
        summary=research_reader.read_export(export,manifest)
        assert summary['conversations']==1
        exported=export.read_text()
        assert 'ExampleCorp' not in exported
        assert 'Keep this observed text.' in exported and 'Keep this ordinary nested result.' in exported
        assert 'INVENTED_UNSUPPORTED_CITATION' not in exported and 'INVENTED_RESTRICTED_DOCUMENT' not in exported
        counts=manifest['counts']
        assert counts['source_frames']==len(stream)
        assert counts['source_frames_mapped']==len(stream)-1 and counts['source_frames_unsupported']==1
        assert counts['source_frames_withheld']==0
        assert any(item['reasons'].get('unsupported_attachment',0)>0
                   for item in manifest['per_observation_exclusions'])
        assert archive.status()['retained_unique_records']==len(records)
        assert research.db.rows('SELECT id,record_json,content_sha256 FROM records FINAL ORDER BY id')==originals
        # Policy mutation under the same version must not release/reuse an old snapshot.
        policy['aliases']['organisations'].append('OtherExample')
        (root/'policy.json').write_text(json.dumps(policy))
        try:research.release_revision(revision,True)
        except research.HoldError:pass
        else:raise AssertionError('Changed policy reused a released revision')
        print(json.dumps({'synthetic_integration':'passed','raw_records':len(records),'held_oversized':1,
                          'events':summary['events'],'pages':pages,'gzip_sha256_resume':True,
                          'manifest_verified':True,'policy_mutation_blocked':True,
                          'raw_checksums_unchanged':True,'mixed_frame_accounting':True,
                          'nested_exclusion_accounted':True}))


if __name__=='__main__':main()
