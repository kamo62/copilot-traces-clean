"""A tool's parameter schema is documentation, not identity data.

Real holds for ambiguous_identity_field were all JSON Schema property
definitions whose parameter name opens identity context (owner, repo, session,
task, id, *_id, author, actor, tenant, node_id) while the held leaf documented
the parameter: description, pattern, format, or an extension keyword restating
the parameter's own name. Every fixture here is invented.
"""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import parsing
import research
from sanitise import HoldError, Policy, Sanitizer, canonical
from test_research_poc import policy_data

REVISION = {'revision_id': 'rev_' + 'a' * 32, 'config_json': '{}', 'schema_version': research.SCHEMA_VERSION}
RECORD_ROW = {'id': 'b' * 64, 'seq': 7, 'timestamp': 1760000000000, 'content_sha256': 'c' * 64}
REF_PREFIXES = ('person_', 'repo_', 'org_', 'conv_', 'id_')


def sanitizer():
    return Sanitizer(Policy(policy_data(), b'k' * 48))


def parameters(**properties):
    return {'type': 'object', 'properties': properties, 'required': sorted(properties)[:1]}


def invented_schema():
    """The held shape: identity-named parameters documented by schema keywords."""
    return parameters(
        owner={'type': 'string', 'description': 'Account that owns the invented repository',
               'x-param-name': 'owner'},
        repo={'type': 'string', 'description': 'Name of the invented repository', 'x-param-name': 'repo'},
        issue_id={'type': 'string', 'description': 'Identifier of the invented issue', 'pattern': '^[0-9]+$'},
        id={'type': 'string', 'description': 'Identifier of an invented terminal', 'format': 'uuid'},
        session={'type': 'string', 'description': 'Invented session to resume'},
        author={'type': 'string', 'description': 'Only commits by this author'},
        actor={'type': 'string', 'description': 'Only runs started by this actor'},
        tenant={'type': 'string', 'description': 'Invented tenant to query'},
        node_id={'type': 'string', 'description': 'Global node identifier'},
        task={'type': 'object', 'description': 'Invented task definition', 'required': ['label'],
              'properties': {'label': {'type': 'string', 'description': 'Task label shown to the user'},
                             'args': {'type': 'array', 'description': 'Task arguments',
                                      'items': {'type': 'string', 'description': 'One argument'}}}},
        conversation_id={'anyOf': [{'type': 'string', 'description': 'Invented conversation'}, {'type': 'null'}],
                         'title': 'Conversation Id'},
    )


def request(tools, shape='chat'):
    message = {'role': 'user', 'content': 'List the open issues in the invented repository.'}
    if shape == 'chat':
        body = {'model': 'invented-model', 'messages': [message],
                'tools': [{'type': 'function', 'function': {'name': name, 'description': 'Invented tool.',
                                                            'parameters': schema}} for name, schema in tools]}
    elif shape == 'anthropic':
        body = {'model': 'invented-model', 'max_tokens': 16, 'messages': [message],
                'tools': [{'name': name, 'description': 'Invented tool.', 'input_schema': schema}
                          for name, schema in tools]}
    else:
        body = {'model': 'invented-model', 'input': [message],
                'tools': [{'type': 'function', 'name': name, 'description': 'Invented tool.', 'parameters': schema,
                           'strict': False} for name, schema in tools]}
    return {'type': 'request', 'body': json.dumps(body), 'headers': {'Authorization': 'invented'}}


def event_rows(record):
    """The worker's own derivation path, without storage."""
    clean = sanitizer()
    clean.refs.bind_revision(REVISION['revision_id'])
    rows, _ = research._event_rows(REVISION, None, RECORD_ROW, parsing.derive_events(record, clean.refs), clean)
    return rows


def tool_schemas(record):
    return [json.loads(row['payload']) for row in event_rows(record) if row['kind'] == 'tool_schema']


class ToolSchemaDocumentationTests(unittest.TestCase):
    def test_held_shape_is_processed_in_every_request_format(self):
        for shape in ('chat', 'anthropic', 'responses'):
            with self.subTest(shape=shape):
                schemas = tool_schemas(request([('invented_get_issue', invented_schema())], shape))
                self.assertEqual(len(schemas), 1)
                properties = schemas[0]['parameters']['properties']
                self.assertEqual(properties['owner']['description'], 'Account that owns the invented repository')
                self.assertEqual(properties['repo']['x-param-name'], 'repo')
                self.assertEqual(properties['issue_id']['pattern'], '^[0-9]+$')
                self.assertEqual(properties['id']['format'], 'uuid')
                self.assertEqual(properties['task']['properties']['label']['description'], 'Task label shown to the user')
                self.assertEqual(properties['task']['properties']['args']['items']['description'], 'One argument')
                self.assertEqual(properties['conversation_id']['anyOf'][0]['description'], 'Invented conversation')
                self.assertEqual(properties['conversation_id']['title'], 'Conversation Id')

    def test_documentation_never_becomes_an_identity_reference(self):
        schema = tool_schemas(request([('invented_get_issue', invented_schema())]))[0]

        def documentation(node):
            if isinstance(node, dict):
                for key, item in node.items():
                    if key in ('description', 'title', 'pattern', 'format', 'x-param-name') and isinstance(item, str):
                        yield item
                    else:
                        yield from documentation(item)
            elif isinstance(node, list):
                for item in node:
                    yield from documentation(item)
        texts = list(documentation(schema['parameters']))
        self.assertGreaterEqual(len(texts), 14)
        for text in texts:
            self.assertFalse(text.startswith(REF_PREFIXES), text)

    def test_documentation_is_still_redacted_as_prose(self):
        schema = parameters(repo={'type': 'string', 'description': (
            'Repository such as example-holdings/pricing-service; ask alex@example.com or read '
            '/home/alex/repos/pricing/src/quote.py first')})
        rendered = canonical(tool_schemas(request([('invented_tool', schema)]))[0])
        for raw in ('example-holdings', 'alex@example.com', '/home/alex', 'quote.py'):
            self.assertNotIn(raw, rendered)
        self.assertIn('Repository such as ', rendered)

    def test_credential_named_parameter_is_still_withheld(self):
        schema = parameters(api_token={'type': 'string', 'description': 'Invented token parameter'})
        properties = tool_schemas(request([('invented_tool', schema)]))[0]['parameters']['properties']
        self.assertEqual(properties['api_token'], '[WITHHELD]')

    def test_instance_lists_of_identity_parameters_stay_pseudonymised(self):
        schema = parameters(owner={'type': 'string', 'description': 'Account', 'enum': ['invented-org-a', 'invented-org-b'],
                                   'examples': ['invented-org-c']})
        owner = tool_schemas(request([('invented_tool', schema)]))[0]['parameters']['properties']['owner']
        self.assertEqual(owner['description'], 'Account')
        self.assertTrue(all(value.startswith('person_') for value in owner['enum'] + owner['examples']))
        self.assertNotIn('invented-org', canonical(owner))


class GenuineIdentityAmbiguityTests(unittest.TestCase):
    def assert_held(self, record):
        with self.assertRaises(HoldError) as context:
            event_rows(record)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_instance_values_of_identity_parameters_stay_held(self):
        for keyword in ('default', 'const', 'example'):
            with self.subTest(keyword=keyword):
                schema = parameters(owner={'type': 'string', 'description': 'Account', keyword: 'invented-org'})
                self.assert_held(request([('invented_tool', schema)]))

    def test_pattern_spelling_out_a_value_stays_held(self):
        # A regex is an assertion: '^invented\\.person$' names its only match,
        # and escaping hides it from alias matching.
        for pattern in (r'^invented\.person$', '^(invented-org|other-org)$', '^[E][x][a][m][p][l][e] [H][o][l][d][i][n][g][s]$',
                        '^\u0418\u0440\u0438\u043d\u0430$', '^123456$', '^[a-a][b-b]$', r'\[invented]', '^[i][n][v][e][n][t][e][d]$'):
            with self.subTest(pattern=pattern):
                schema = parameters(owner={'type': 'string', 'pattern': pattern})
                self.assert_held(request([('invented_tool', schema)]))

    def test_structural_pattern_check_is_linear(self):
        import time
        from sanitise import structural_pattern
        started = time.perf_counter()
        for pattern in ('.?' * 25 + 'X', '.?' * 128, '(' * 128, '[a-z]?' * 42 + 'X', '\\d??' * 60 + 'X'):
            structural_pattern(pattern)
        self.assertLess(time.perf_counter() - started, 0.1)
        self.assertTrue(structural_pattern('^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'))
        self.assertTrue(structural_pattern('^[a-f0-9]{40}$'))

    def test_pattern_property_keys_spelling_a_value_stay_held(self):
        for key in ('^elara[.]brightwater$', '^invented\\.org$', '^[E][x]$'):
            with self.subTest(key=key):
                schema = parameters(owner={'type': 'object', 'patternProperties': {
                    key: {'type': 'string', 'description': 'Invented metadata'}}})
                self.assert_held(request([('invented_tool', schema)]))

    def test_structural_pattern_property_keys_are_processed(self):
        schema = parameters(owner={'type': 'object', 'patternProperties': {
            '^[a-z0-9-]+$': {'type': 'string', 'description': 'Invented metadata'}}})
        schemas = tool_schemas(request([('invented_tool', schema)]))
        self.assertIn('^[a-z0-9-]+$', schemas[0]['parameters']['properties']['owner']['patternProperties'])

    def test_unrecognised_keyword_with_a_new_value_stays_held(self):
        schema = parameters(owner={'type': 'string', 'x-default-owner': 'invented-org'})
        self.assert_held(request([('invented_tool', schema)]))

    def test_data_inside_an_instance_value_stays_held(self):
        schema = parameters(owner={'type': 'object', 'default': {'login': 'invented-login',
                                                                'description': 'Invented free text about a person'}})
        self.assert_held(request([('invented_tool', schema)]))

    def test_schema_shaped_tool_arguments_are_data_and_stay_held(self):
        # Only the parser's tool definitions are declared as schemas. The same
        # shape inside replayed tool-call arguments keeps the existing hold.
        arguments = {'owner': {'type': 'string', 'description': 'Invented free text'}}
        body = {'model': 'invented-model', 'messages': [
            {'role': 'assistant', 'content': None, 'tool_calls': [{'id': 'call_invented', 'type': 'function',
             'function': {'name': 'invented_tool', 'arguments': json.dumps(arguments)}}]}]}
        self.assert_held({'type': 'request', 'body': json.dumps(body)})

    def test_undeclared_payload_keeps_the_hold(self):
        payload = {'name': 'invented_tool', 'description': 'Invented tool.', 'supported': True,
                   'parameters': invented_schema()}
        with self.assertRaises(HoldError) as context:
            sanitizer().payload(payload)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')
        self.assertIn('owner', sanitizer().payload(payload, schema_fields=('parameters',))['parameters']['properties'])

    def test_identity_object_with_free_text_stays_held(self):
        # The privacy evaluation's intentional hold: a real identity object.
        for payload in ({'repository': {'name': 'pricing-service', 'description': 'free text that cannot be classified'}},
                        {'author': {'login': 'invented-login', 'email': 'invented@example.com'}}):
            with self.assertRaises(HoldError) as context:
                sanitizer().payload(payload)
            self.assertEqual(context.exception.reason, 'ambiguous_identity_field')


if __name__ == '__main__':
    unittest.main()
