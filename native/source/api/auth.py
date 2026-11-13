"""Explicit role separation for the traces POC."""
import hmac
import re

ROLES = ('status', 'admin', 'research', 'otlp')
RESEARCH_PREFIX = '/v1/research/'
ADMIN_RESEARCH_POST = {'/v1/research/revisions', '/v1/research/releases', '/v1/research/review/annotations'}


def required_role(method, path):
    if method == 'GET':
        if path in ('/healthz', '/openapi.json', '/', '/docs', '/docs/') or path.startswith('/docs/'):
            return None
        if path == '/v1/copilot/storage':
            return 'status'
        if path.startswith(RESEARCH_PREFIX):
            if path in ('/v1/research/schema', '/v1/research/manifest', '/v1/research/export',
                        '/v1/research/export/pages'):
                return 'research'
            return 'admin'
        return 'admin'
    if method == 'POST':
        if path in ('/v1/traces', '/v1/logs', '/v1/metrics'):
            return 'otlp'
        if path in ADMIN_RESEARCH_POST:
            return 'admin'
        return 'admin'
    return 'admin'


def credential(role, status_key, admin_key, research_key, otlp_token):
    return {'status': status_key, 'admin': admin_key, 'research': research_key, 'otlp': otlp_token}.get(role)


def authorised(header, key):
    if not key:
        return False
    expected = ('Bearer ' + key).encode()
    return hmac.compare_digest(header.encode(), expected)


def validate_credentials(status_key, admin_key, research_key, otlp_token):
    required = {'status': status_key, 'admin': admin_key, 'otlp': otlp_token}
    for name, value in required.items():
        if not isinstance(value, str) or len(value) < 32:
            raise ValueError(name + ' credential must contain at least 32 characters')
    values = list(required.values())
    if len(set(values)) != len(values):
        raise ValueError('Admin, status and OTLP credentials must be distinct')
    if research_key:
        if not isinstance(research_key, str) or len(research_key) < 32:
            raise ValueError('Research credential must contain at least 32 characters')
        if research_key in values:
            raise ValueError('Research credential must be distinct from admin, status and OTLP credentials')
    return True


def safe_path(path):
    """Defensive helper for callers that want to test role routing only."""
    if not isinstance(path, str) or len(path) > 4096:
        return '/invalid'
    return path if path.startswith('/') else '/' + path
