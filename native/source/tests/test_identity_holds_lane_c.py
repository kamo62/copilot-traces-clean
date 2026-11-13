"""Lane C identity-hold regressions. Every fixture is invented."""
import json
from pathlib import Path
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sanitise
from sanitise import HoldError, canonical, structural_pattern
from test_identity_refusal import event_rows, parameters, request, sanitizer, tool_schemas

# Public UUID-format syntax, not an identity value or a captured fixture.
UUID_VALIDATOR = (r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-'
                  r'[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$')
GROUPED_UUID_VALIDATOR = (r'^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                          r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$')
NUMERIC_RANGE_VALIDATOR = r'^\d+[:-]\d+$'
INVENTED_UUID = '12345678-90ab-4cde-8fab-0123456789ab'


class IdentityHoldsLaneCTests(unittest.TestCase):
    def assert_held(self, payload, **options):
        with self.assertRaises(HoldError) as context:
            sanitizer().payload(payload, **options)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_complete_uuid_validator_is_structural_documentation(self):
        self.assertTrue(sanitise.Sanitizer._structural_pattern(UUID_VALIDATOR))
        for shape in ('chat', 'anthropic', 'responses'):
            with self.subTest(shape=shape):
                schema = parameters(id={'type': 'string', 'description': 'Invented terminal identifier',
                                        'pattern': UUID_VALIDATOR})
                rendered = tool_schemas(request([('invented_terminal', schema)], shape))
                self.assertEqual(rendered[0]['parameters']['properties']['id']['pattern'], UUID_VALIDATOR)

    def test_uuid_validator_inside_nested_schema_is_documentation(self):
        schema = parameters(session={'anyOf': [
            {'type': 'object', 'properties': {'terminal_id': {'type': 'string', 'pattern': UUID_VALIDATOR}}},
            {'type': 'null'},
        ]})
        rendered = tool_schemas(request([('invented_terminal', schema)]))[0]
        self.assertEqual(rendered['parameters']['properties']['session']['anyOf'][0]['properties']
                         ['terminal_id']['pattern'], UUID_VALIDATOR)

    def test_uuid_pattern_property_key_keeps_the_strict_key_gate(self):
        # Sol review round 1: the format whitelist is for 'pattern' annotations
        # only; a regex key opens no identity context for its subschema.
        schema = parameters(owner={'type': 'object', 'patternProperties': {
            UUID_VALIDATOR: {'type': 'string', 'description': 'Invented identity map', 'enum': [INVENTED_UUID]}}})
        with self.assertRaises(HoldError):
            event_rows(request([('invented_tool', schema)]))

    def test_grouped_uuid_and_numeric_range_are_complete_format_validators(self):
        for pattern in (GROUPED_UUID_VALIDATOR, NUMERIC_RANGE_VALIDATOR):
            with self.subTest(pattern=pattern):
                self.assertTrue(sanitise.Sanitizer._structural_pattern(pattern))
                schema = parameters(range_id={'type': 'string', 'pattern': pattern})
                rendered = tool_schemas(request([('invented_tool', schema)]))[0]
                self.assertEqual(rendered['parameters']['properties']['range_id']['pattern'], pattern)

    def test_numeric_range_components_and_literal_prefixes_stay_held(self):
        for pattern in ('^[:]+$', '^([0-9]{8}-[0-9]{4})$', r'^invented\d+[:-]\d+$',
                        r'^(?:\d+[:-]\d+|[X]\d+[:-]\d+(?:Y\d+[:-]\d+)*)$'):
            with self.subTest(pattern=pattern):
                self.assertFalse(sanitise.Sanitizer._structural_pattern(pattern))
                self.assert_held({'parameters': parameters(id={'pattern': pattern})}, schema_fields=('parameters',))

    def test_uuid_components_do_not_expand_the_general_grammar(self):
        for pattern in ('^[1-5]+$', '^[89abAB]+$', '^[1-5][89abAB]$', '^12345$',
                        '^[i][n][v][e][n][t][e][d]$', r'^invented\.person$'):
            with self.subTest(pattern=pattern):
                self.assertFalse(sanitise.Sanitizer._structural_pattern(pattern))
                self.assert_held({'parameters': parameters(owner={'type': 'string', 'pattern': pattern})},
                                 schema_fields=('parameters',))

    def test_uuid_validator_requires_the_whole_exact_shape(self):
        mutations = [
            UUID_VALIDATOR + '|invented', 'invented|' + UUID_VALIDATOR,
            UUID_VALIDATOR.replace('{8}', '{7}', 1), UUID_VALIDATOR.replace('{12}', '{11}'),
            UUID_VALIDATOR.replace('[1-5]', '[4]'), UUID_VALIDATOR.replace('[89abAB]', '[8]'),
            UUID_VALIDATOR.replace('[0-9a-fA-F]', '[0]', 1),
            UUID_VALIDATOR[:-1] + r'(?:invented\.person)$', '^' + INVENTED_UUID + '$',
        ]
        for pattern in mutations:
            with self.subTest(pattern=pattern):
                self.assertFalse(sanitise.Sanitizer._structural_pattern(pattern))
                self.assert_held({'parameters': parameters(id={'type': 'string', 'pattern': pattern})},
                                 schema_fields=('parameters',))

    def test_instance_strings_are_not_exempt_even_if_they_look_structural(self):
        for keyword in ('default', 'const', 'example'):
            for value in (UUID_VALIDATOR, INVENTED_UUID, 'owner'):
                with self.subTest(keyword=keyword, value=value):
                    self.assert_held({'parameters': parameters(owner={'type': 'string', keyword: value})},
                                     schema_fields=('parameters',))

    def test_instance_lists_keep_identity_references(self):
        schema = parameters(owner={'type': 'string', 'enum': [INVENTED_UUID],
                                   'examples': [INVENTED_UUID, UUID_VALIDATOR]})
        rendered = tool_schemas(request([('invented_tool', schema)]))[0]['parameters']['properties']['owner']
        self.assertTrue(all(value.startswith('person_') for value in rendered['enum'] + rendered['examples']))
        self.assertNotIn(INVENTED_UUID, canonical(rendered))
        self.assertNotIn(UUID_VALIDATOR, canonical(rendered))

    def test_schema_shaped_instance_objects_stay_data(self):
        instance = {'properties': {'id': {'type': 'string', 'pattern': UUID_VALIDATOR}}}
        for keyword in ('default', 'const', 'examples'):
            with self.subTest(keyword=keyword):
                self.assert_held({'parameters': parameters(owner={'type': 'object', keyword: instance})},
                                 schema_fields=('parameters',))

    def test_tool_call_arguments_are_not_exempt(self):
        arguments = {'owner': {'type': 'string', 'pattern': UUID_VALIDATOR}}
        body = {'model': 'invented-model', 'messages': [
            {'role': 'assistant', 'content': None, 'tool_calls': [
                {'id': 'call_invented', 'type': 'function', 'function': {
                    'name': 'invented_tool', 'arguments': json.dumps(arguments)}}]}]}
        with self.assertRaises(HoldError) as context:
            event_rows({'type': 'request', 'body': json.dumps(body)})
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_undeclared_schema_and_identity_free_text_stay_held(self):
        self.assert_held({'parameters': parameters(owner={'type': 'string', 'pattern': UUID_VALIDATOR})})
        self.assert_held({'owner': {'login': 'invented-login', 'description': 'Invented free text about a person'}})
        self.assert_held({'parameters': parameters(owner={'type': 'string', 'x-default-owner': 'invented-person'})},
                         schema_fields=('parameters',))

    def test_uuid_documentation_still_runs_all_prose_redactions(self):
        schema = parameters(id={'type': 'string', 'pattern': UUID_VALIDATOR, 'description': (
            'Invented example ' + INVENTED_UUID + '; contact alex@example.com at '
            'https://invented.example; password="inventedSecretValue"; Example Holdings')})
        rendered = canonical(tool_schemas(request([('invented_tool', schema)])))
        for value in (INVENTED_UUID, 'alex@example.com', 'https://invented.example',
                      'inventedSecretValue', 'Example Holdings'):
            self.assertNotIn(value, rendered)
        self.assertIn('[REDACTED_CREDENTIAL]', rendered)

    def test_unaffected_payload_is_byte_identical_without_uuid_extension(self):
        payload = {'parameters': parameters(owner={'type': 'string', 'description': 'Contact alex@example.com',
                                                   'pattern': '^[a-z]+$'},
                                            id={'type': 'string', 'pattern': '^[0-9]+$',
                                                'enum': [INVENTED_UUID]})}
        actual = canonical(sanitizer().payload(payload, schema_fields=('parameters',))).encode()
        with mock.patch.object(sanitise, '_STRUCTURAL_FORMAT_PATTERNS', frozenset()):
            original = canonical(sanitizer().payload(payload, schema_fields=('parameters',))).encode()
        self.assertEqual(actual, original)

    def test_local_schema_reference_under_identity_context_stays_held(self):
        # Council round 1 (Astra): withholding only the pointer left its target
        # ('$defs.X.const') sanitised without the referring identity context.
        for pointer in ('#/$defs/InventedDefinition', '#/properties/invented_item/items'):
            with self.subTest(pointer=pointer):
                payload = {'parameters': parameters(request={'type': 'array', 'items': {'$ref': pointer}})}
                self.assert_held(payload, schema_fields=('parameters',))
        for keyword, value in (('const', 'Nerina Frostwillow'), ('default', 'Nerina Frostwillow'),
                               ('enum', ['Nerina Frostwillow'])):
            with self.subTest(keyword=keyword):
                schema = {'type': 'object', 'properties': {'owner': {'$ref': '#/$defs/OwnerValue'}},
                          '$defs': {'OwnerValue': {'type': 'string', keyword: value}}}
                self.assert_held({'parameters': schema}, schema_fields=('parameters',))

    def test_nonlocal_reference_and_reference_shaped_identity_data_stay_held(self):
        for pointer in ('Invented Person', 'https://invented.example/schema.json', '#InventedPerson',
                        '#/$defs/' + 'x' * 257):
            with self.subTest(pointer=pointer):
                self.assert_held({'parameters': parameters(owner={'$ref': pointer})}, schema_fields=('parameters',))
        self.assert_held({'owner': {'$ref': '#/$defs/InventedDefinition'}})
        for keyword in ('default', 'const', 'enum', 'examples'):
            with self.subTest(keyword=keyword):
                instance = {'$ref': '#/$defs/InventedDefinition'}
                value = [instance] if keyword in ('enum', 'examples') else instance
                self.assert_held({'parameters': parameters(owner={keyword: value})}, schema_fields=('parameters',))

    def test_oversized_and_adversarial_patterns_stay_bounded(self):
        oversized = UUID_VALIDATOR + 'x' * (8 * 1024 * 1024 - len(UUID_VALIDATOR))
        started = time.perf_counter()
        for _ in range(1000):
            self.assertFalse(sanitise.Sanitizer._structural_pattern(oversized))
        for pattern in ('.?' * 25 + 'X', '(' * 128, '[a-z]?' * 42 + 'X'):
            sanitise.Sanitizer._structural_pattern(pattern)
        self.assertLess(time.perf_counter() - started, 0.1)



class FormatKeysStayStrictTests(unittest.TestCase):
    """Sol review round 1: the format whitelist must not admit patternProperties keys."""

    def test_format_validators_are_not_structural_keys(self):
        for pattern in sorted(sanitise._STRUCTURAL_FORMAT_PATTERNS):
            with self.subTest(pattern=pattern):
                self.assertFalse(structural_pattern(pattern))
                self.assertTrue(sanitise.Sanitizer._structural_pattern(pattern))

    def test_format_key_outside_identity_context_still_holds(self):
        for pattern in sorted(sanitise._STRUCTURAL_FORMAT_PATTERNS):
            with self.subTest(pattern=pattern):
                schema = {'type': 'object', 'patternProperties': {
                    pattern: {'type': 'string', 'const': 'Nerina Frostwillow'}}}
                with self.assertRaises(HoldError):
                    event_rows(request([('invented_tool', schema)]))


if __name__ == '__main__':
    unittest.main()
