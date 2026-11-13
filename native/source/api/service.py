#!/usr/bin/env python3
"""Independent, restricted Enterprise-log and client-telemetry review API."""
import json
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
from urllib.parse import parse_qs,urlsplit

import archive
import auth
import collection
import openapi
import research
import review
from sanitise import HoldError

KEY = os.environ.get('COPILOT_STATS_API_KEY','')
ADMIN_KEY = os.environ.get('COPILOT_ADMIN_API_KEY','')
RESEARCH_KEY = os.environ.get('COPILOT_RESEARCH_API_KEY','')
TOKEN = Path(os.environ.get('COPILOT_OTLP_TOKEN_FILE','/run/secrets/otlp_token')).read_text().strip()
DOCS = Path(__file__).with_name('docs')
CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
PUBLIC_GET = {'/healthz','/openapi.json','/','/docs','/docs/'}


def role_key(role):
    return {'status':KEY,'admin':ADMIN_KEY,'research':RESEARCH_KEY,'otlp':TOKEN}.get(role)


class Handler(BaseHTTPRequestHandler):
    def reply(self,status,value,headers=None):
        self.send_bytes(status,json.dumps(value,allow_nan=False).encode(),'application/json',headers)

    def send_bytes(self,status,body,content_type,extra=None):
        self.send_response(status)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('Content-Security-Policy',CSP)
        for name,value in (extra or {}).items():
            if value is not None:
                self.send_header(name,str(value))
        self.end_headers()
        self.wfile.write(body)

    def authorised(self,key):
        if auth.authorised(self.headers.get('Authorization',''),key):
            return True
        self.send_response(401)
        self.send_header('WWW-Authenticate','Bearer')
        self.send_header('Content-Length','0')
        self.end_headers()
        return False

    def static(self,path):
        if path in ('/docs','/docs/'):
            path = 'index.html'
        else:
            path = path.removeprefix('/docs/')
        target = (DOCS/path).resolve()
        if not target.is_relative_to(DOCS.resolve()) or not target.is_file():
            self.reply(404,{'error':'NOT_FOUND'})
            return
        types = {'.html':'text/html; charset=utf-8','.js':'application/javascript; charset=utf-8',
                 '.css':'text/css; charset=utf-8','.png':'image/png'}
        self.send_bytes(200,target.read_bytes(),types.get(target.suffix,'text/plain'))

    @staticmethod
    def review_read(path,query):
        """Admin-only research review reads; every selection is explicit and bounded."""
        def params(required,optional=()):
            if set(query)-set(required)-set(optional) or not set(required)<=set(query):
                raise ValueError('Invalid parameters')
            return {name:value[0] for name,value in query.items()}
        name = path.removeprefix('/v1/research/review/')
        if name == 'taxonomy':
            params(())
            return review.taxonomy()
        if name == 'summary':
            return review.summary(params(('revision',))['revision'])
        if name == 'observations':
            values = params(('revision',),('after','limit','status'))
            return review.observations(values['revision'],values.get('after',''),int(values.get('limit','50')),values.get('status'))
        if name == 'compare':
            values = params(('revision','observation'),('from',))
            return review.compare(values['revision'],values['observation'],int(values.get('from','0')))
        if name == 'annotations':
            values = params(('revision','observation'))
            return review.annotations(values['revision'],values['observation'])
        raise LookupError('Endpoint not found')

    def do_GET(self):
        self.connection.settimeout(30)
        if len(self.path)>4096:
            self.reply(414,{'error':'URL_TOO_LONG'})
            return
        parsed = urlsplit(self.path)
        if parsed.path == '/healthz':
            try:
                archive.db.rows('SELECT 1 AS ready')
            except Exception:
                self.reply(503,{'status':'database_unavailable'})
            else:
                self.reply(200,{'status':'ok','database':'ClickHouse','purpose':'independent traces POC'})
            return
        if parsed.path == '/openapi.json':
            self.reply(200,openapi.SPECIFICATION)
            return
        if parsed.path == '/':
            self.reply(200,{'service':'traces-clean','version':openapi.SPECIFICATION['info']['version'],
                            'docs':'/docs','openapi':'/openapi.json','frontend':False,
                            'research_format':'research-event/2 JSONL or gzip; released revisions only'})
            return
        if parsed.path in ('/viewer','/viewer/','/review','/review/'):
            self.reply(404,{'error':'NOT_FOUND'})
            return
        if parsed.path in PUBLIC_GET or parsed.path.startswith('/docs/'):
            self.static(parsed.path)
            return
        role = auth.required_role('GET',parsed.path)
        if not role or not self.authorised(role_key(role)):
            return
        try:
            query = parse_qs(parsed.query,keep_blank_values=True)
            if any(len(value)!=1 for value in query.values()):
                raise ValueError('Repeated parameters')
            if parsed.path == '/v1/copilot/storage' and not query:
                result = archive.status()
            elif parsed.path == '/v1/review/records':
                if set(query)-{'after','limit','request_id','order'}:
                    raise ValueError('Invalid parameters')
                after,limit = int(query.get('after',['0'])[0]),int(query.get('limit',['25'])[0])
                order = query.get('order',['asc'])[0]
                if after<0 or not 1<=limit<=100 or order not in ('asc','desc'):
                    raise ValueError('Invalid pagination')
                result = archive.review_records(after,limit,query.get('request_id',[None])[0],order)
            elif re.fullmatch(r'/v1/review/records/[a-f0-9]{64}',parsed.path) and not query:
                result = archive.review_record(parsed.path.rsplit('/',1)[-1])
            elif parsed.path == '/v1/review/client-batches' and not query:
                result = archive.telemetry()
            elif re.fullmatch(r'/v1/review/client-batches/[a-f0-9]{64}',parsed.path) and not query:
                result = archive.telemetry(parsed.path.rsplit('/',1)[-1])
            elif parsed.path == '/v1/collection/jobs' and not query:
                result = collection.job()
            elif re.fullmatch(r'/v1/collection/jobs/[a-f0-9]{32}',parsed.path) and not query:
                result = collection.job(parsed.path.rsplit('/',1)[-1])
            elif parsed.path == '/v1/research/status' and not query:
                result = research.status()
            elif parsed.path.startswith('/v1/research/review/'):
                result = self.review_read(parsed.path,query)
            elif parsed.path == '/v1/research/schema':
                if query:
                    raise ValueError('Invalid parameters')
                result = research.EVENT_SCHEMA
            elif parsed.path == '/v1/research/manifest':
                if set(query) != {'revision'}:
                    raise ValueError('revision is required')
                result = research.manifest(query['revision'][0])
            elif parsed.path in ('/v1/research/export','/v1/research/export/pages'):
                if set(query)-{'revision','cursor','limit','gzip'} or 'revision' not in query:
                    raise ValueError('Invalid export parameters')
                revision = query['revision'][0]
                cursor = query.get('cursor',[None])[0]
                limit = int(query.get('limit',[str(research.MAX_PAGE)])[0])
                if parsed.path == '/v1/research/export':
                    compress = query.get('gzip',['0'])[0] in ('1','true','yes')
                    body,content_type,headers = research.export_jsonl(revision,cursor,limit,compress)
                    self.send_bytes(200,body,content_type,headers)
                    return
                page,_ = research.export_page(revision,cursor,limit)
                result = page
            else:
                raise LookupError('Endpoint not found')
        except HoldError as failure:
            self.reply(409,{'error':'RESEARCH_HELD','message':'Dataset is not released or failed the release gate','reason':failure.reason})
        except research.ConfigError as failure:
            self.reply(409,{'error':'RESEARCH_HELD','message':str(failure)})
        except (ValueError,TypeError,OverflowError):
            self.reply(400,{'error':'VALIDATION_ERROR','message':'Invalid filters, revision, cursor or pagination'})
        except LookupError:
            self.reply(404,{'error':'NOT_FOUND'})
        except (OSError,KeyError):
            self.reply(503,{'error':'DATABASE_UNAVAILABLE','message':'Database or checksum verification unavailable'})
        else:
            self.reply(200,result)

    def do_POST(self):
        self.connection.settimeout(120)
        path = urlsplit(self.path).path
        role = auth.required_role('POST',path)
        if not role or not self.authorised(role_key(role)):
            return
        allowed = ('/v1/collection/jobs','/v1/ingest/records','/v1/traces','/v1/logs','/v1/metrics',
                   '/v1/research/revisions','/v1/research/releases','/v1/research/review/annotations')
        if self.path != path or path not in allowed:
            self.reply(404,{'error':'NOT_FOUND'})
            return
        try:
            length = int(self.headers.get('Content-Length','0'))
            limit = (16384 if path=='/v1/research/review/annotations' else 4096
                     if path in ('/v1/collection/jobs','/v1/research/revisions','/v1/research/releases') else 64*1024*1024)
            if (not 1<=length<=limit or self.headers.get('Transfer-Encoding')
                    or self.headers.get('Content-Type','').split(';')[0]!='application/json'):
                raise ValueError('Expected bounded JSON')
            raw = self.rfile.read(length)
            if len(raw)!=length:
                raise ValueError('Incomplete request')
            if path in ('/v1/traces','/v1/logs','/v1/metrics'):
                archive.store_telemetry(path.rsplit('/',1)[-1],raw)
                result = {}
            elif path == '/v1/ingest/records':
                result = archive.ingest_records(raw)
            elif path == '/v1/research/revisions':
                parameters = json.loads(raw)
                if not isinstance(parameters,dict) or parameters:
                    raise ValueError('Expected an empty snapshot request object')
                result = research.create_revision()
            elif path == '/v1/research/review/annotations':
                result = review.store_annotation(json.loads(raw))
            elif path == '/v1/research/releases':
                parameters = json.loads(raw)
                if (not isinstance(parameters,dict) or set(parameters)!={'revision_id','acknowledge_review'}
                        or type(parameters['acknowledge_review']) is not bool):
                    raise ValueError('Expected revision_id and explicit acknowledge_review boolean')
                result = research.release_revision(parameters['revision_id'],parameters['acknowledge_review'])
            else:
                result = collection.create_job(json.loads(raw))
        except BlockingIOError:
            self.reply(409,{'error':'COLLECTION_BUSY'})
        except HoldError as failure:
            self.reply(409,{'error':'RESEARCH_HELD','message':'Publication held by policy or release checks','reason':failure.reason})
        except research.ConfigError as failure:
            self.reply(409,{'error':'RESEARCH_HELD','message':str(failure)})
        except LookupError:
            self.reply(404,{'error':'NOT_FOUND'})
        except (ValueError,TypeError,KeyError,UnicodeError,AttributeError,json.JSONDecodeError):
            self.reply(400,{'error':'VALIDATION_ERROR','message':'Invalid bounded JSON export, research or collection request'})
        except OSError:
            self.reply(503,{'error':'DATABASE_UNAVAILABLE'})
        else:
            status = 202 if path=='/v1/collection/jobs' else (201 if path.startswith('/v1/research/') else 200)
            self.reply(status,result)

    def log_message(self,*args):
        pass # Never print bodies, headers, request IDs or URLs.


if __name__=='__main__':
    try:
        auth.validate_credentials(KEY,ADMIN_KEY,RESEARCH_KEY,TOKEN)
    except ValueError as failure:
        raise SystemExit(str(failure))
    os.umask(0o077)
    collection.retry_database(archive.initialise)
    try:
        research.initialise()
        review.initialise()
    except Exception as failure:
        # A research schema problem must not stop raw collection or restricted reads.
        print('Research tables unavailable (' + type(failure).__name__ + '); raw collection continues', flush=True)
    collection.start()
    ThreadingHTTPServer(('0.0.0.0',8081),Handler).serve_forever()
