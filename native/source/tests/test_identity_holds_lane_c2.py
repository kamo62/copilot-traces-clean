"""November identity-hold boundaries. All fixtures and names are invented.

A literal-prefix pattern at an identity-named tool parameter is not proof of
identity-free documentation. Schema authority comes from the parser, never
from a schema-shaped instance or a tool-call argument.
"""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sanitise
from sanitise import HoldError, canonical, structural_pattern
from test_identity_holds_lane_c import (GROUPED_UUID_VALIDATOR, NUMERIC_RANGE_VALIDATOR,
                                        UUID_VALIDATOR)
from test_identity_refusal import event_rows, parameters, request, sanitizer, tool_schemas

LITERAL_PREFIX = '^inventedPrefix'
INVENTED_PERSON = 'Nerina Frostwillow'


class IdentityHoldsLaneC2Tests(unittest.TestCase):
    def assert_held(self, payload, **options):
        with self.assertRaises(HoldError) as context:
            sanitizer().payload(payload, **options)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def assert_record_held(self, record):
        with self.assertRaises(HoldError) as context:
            event_rows(record)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_literal_prefix_pattern_stays_held_in_every_provider_format(self):
        for shape in ('chat', 'anthropic', 'responses'):
            with self.subTest(shape=shape):
                schema = parameters(agent_id={'type': 'string', 'description': 'Invented agent identifier',
                                              'pattern': LITERAL_PREFIX})
                self.assert_record_held(request([('invented_delegate', schema)], shape))

    def test_nested_identity_pattern_stays_held(self):
        schema = parameters(options={'anyOf': [
            {'type': 'array', 'items': parameters(agent_id={'type': 'string', 'pattern': LITERAL_PREFIX})},
            {'type': 'null'},
        ]})
        self.assert_record_held(request([('invented_delegate', schema)]))

    def test_accepted_validator_does_not_release_a_literal_pattern_sibling(self):
        schema = parameters(id={'type': 'string', 'pattern': UUID_VALIDATOR},
                            agent_id={'type': 'string', 'pattern': LITERAL_PREFIX})
        self.assert_record_held(request([('invented_delegate', schema)]))

    def test_prefix_matching_the_parameter_name_is_not_an_annotation(self):
        for name in ('owner', 'invented_id'):
            with self.subTest(name=name):
                schema = parameters(**{name: {'type': 'string', 'x-param-name': name, 'pattern': '^' + name}})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_literal_prefixes_do_not_extend_the_complete_format_allowlist(self):
        patterns = (LITERAL_PREFIX, LITERAL_PREFIX + '$',
                    LITERAL_PREFIX + UUID_VALIDATOR[1:],
                    LITERAL_PREFIX + GROUPED_UUID_VALIDATOR[1:],
                    LITERAL_PREFIX + NUMERIC_RANGE_VALIDATOR[1:])
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertFalse(structural_pattern(pattern))
                self.assertFalse(sanitise.Sanitizer._structural_pattern(pattern))
                self.assert_held({'parameters': parameters(agent_id={'pattern': pattern})},
                                 schema_fields=('parameters',))

    def test_prior_exact_format_annotations_still_process(self):
        for pattern in (UUID_VALIDATOR, GROUPED_UUID_VALIDATOR, NUMERIC_RANGE_VALIDATOR):
            with self.subTest(pattern=pattern):
                schema = parameters(agent_id={'type': 'string', 'pattern': pattern})
                rendered = tool_schemas(request([('invented_delegate', schema)]))[0]
                self.assertEqual(rendered['parameters']['properties']['agent_id']['pattern'], pattern)

    def test_ordinary_annotations_still_run_prose_redaction(self):
        schema = parameters(agent_id={'type': 'string', 'pattern': UUID_VALIDATOR,
                                      'description': 'Invented help; contact alex@example.com; '
                                                     'password="inventedSecretValue"'})
        rendered = canonical(tool_schemas(request([('invented_delegate', schema)])))
        self.assertNotIn('alex@example.com', rendered)
        self.assertNotIn('inventedSecretValue', rendered)
        self.assertIn('[REDACTED_CREDENTIAL]', rendered)

    def test_string_instance_keywords_keep_the_identity_hold(self):
        for keyword in ('default', 'const', 'example'):
            for value in (LITERAL_PREFIX, UUID_VALIDATOR, 'owner', INVENTED_PERSON):
                with self.subTest(keyword=keyword, value=value):
                    self.assert_held({'parameters': parameters(owner={'type': 'string', keyword: value})},
                                     schema_fields=('parameters',))

    def test_identity_instance_lists_are_references_not_documentation(self):
        for keyword in ('enum', 'examples'):
            with self.subTest(keyword=keyword):
                schema = parameters(owner={'type': 'string', keyword: [LITERAL_PREFIX, INVENTED_PERSON]})
                rendered = tool_schemas(request([('invented_delegate', schema)]))[0]
                values = rendered['parameters']['properties']['owner'][keyword]
                self.assertTrue(all(value.startswith('person_') for value in values))
                self.assertNotIn(LITERAL_PREFIX, canonical(rendered))
                self.assertNotIn(INVENTED_PERSON, canonical(rendered))

    def test_schema_shaped_instance_objects_never_gain_schema_authority(self):
        instance = {'properties': {'invented_option': {'description': 'Invented instructions',
                                                     'pattern': UUID_VALIDATOR}}}
        for keyword in ('default', 'const', 'enum', 'examples', 'example'):
            with self.subTest(keyword=keyword):
                value = [instance] if keyword in ('enum', 'examples') else instance
                self.assert_held({'parameters': parameters(owner={keyword: value})},
                                 schema_fields=('parameters',))

    def test_schema_shaped_tool_arguments_stay_data_in_every_provider_format(self):
        arguments = {'agent_id': {'type': 'string', 'description': 'Invented instructions',
                                  'pattern': UUID_VALIDATOR}}
        bodies = (
            {'messages': [{'role': 'assistant', 'content': None, 'tool_calls': [
                {'id': 'call_invented', 'type': 'function', 'function': {
                    'name': 'invented_delegate', 'arguments': json.dumps(arguments)}}]}]},
            {'messages': [{'role': 'assistant', 'content': [
                {'type': 'tool_use', 'id': 'call_invented', 'name': 'invented_delegate', 'input': arguments}]}]},
            {'input': [{'type': 'function_call', 'call_id': 'call_invented', 'name': 'invented_delegate',
                        'arguments': json.dumps(arguments)}]},
        )
        for index, body in enumerate(bodies):
            with self.subTest(provider=index):
                self.assert_record_held({'type': 'request', 'body': json.dumps(body)})

    def test_schema_looking_request_object_in_tool_arguments_stays_held(self):
        self.assert_held({'arguments': {'request': {
            'properties': {'invented_option': {'title': 'Invented option', 'description': 'Invented help'}}}}})

    def test_undeclared_schema_and_identity_object_stay_held(self):
        self.assert_held({'parameters': parameters(agent_id={'pattern': UUID_VALIDATOR})})
        self.assert_held({'owner': {'login': 'invented-login', 'description': 'Invented help',
                                    'pattern': UUID_VALIDATOR}})

    def test_local_reference_targets_under_identity_context_stay_held(self):
        for keyword in ('default', 'const', 'enum', 'examples'):
            with self.subTest(keyword=keyword):
                value = [INVENTED_PERSON] if keyword in ('enum', 'examples') else INVENTED_PERSON
                schema = {'type': 'object', 'properties': {'owner': {'$ref': '#/$defs/InventedOwner'}},
                          '$defs': {'InventedOwner': {'type': 'string', keyword: value}}}
                self.assert_held({'parameters': schema}, schema_fields=('parameters',))

    def test_literal_pattern_property_keys_stay_held_with_or_without_identity_context(self):
        for pattern in (LITERAL_PREFIX, UUID_VALIDATOR, GROUPED_UUID_VALIDATOR, NUMERIC_RANGE_VALIDATOR):
            for name in ('owner', 'invented_options'):
                with self.subTest(pattern=pattern, name=name):
                    schema = parameters(**{name: {'type': 'object', 'patternProperties': {
                        pattern: {'type': 'string', 'const': INVENTED_PERSON}}}})
                    self.assert_record_held(request([('invented_delegate', schema)]))

    def test_non_identity_pattern_keeps_existing_prose_handling(self):
        payload = {'parameters': parameters(invented_filter={'type': 'string', 'pattern': LITERAL_PREFIX})}
        rendered = sanitizer().payload(payload, schema_fields=('parameters',))
        self.assertEqual(canonical(rendered).encode(), canonical(payload).encode())


if __name__ == '__main__':
    unittest.main()
