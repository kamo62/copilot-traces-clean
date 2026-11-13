"""The public OpenCode session-prefix validator is documentation, not an ID.

All records, tools, prose and identity values here are invented. Only the
public parameter name / validator pair is taken from the published schema.
"""
import json
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sanitise
from sanitise import HoldError, canonical, structural_pattern
from test_identity_holds_lane_c import UUID_VALIDATOR
from test_identity_refusal import event_rows, parameters, request, sanitizer, tool_schemas
from test_research_poc import policy_data

SESSION_PATTERN = '^ses'
INVENTED_PERSON = 'Nerina Frostwillow'


class IdentityHoldsLaneC3Tests(unittest.TestCase):
    def assert_held(self, payload, **options):
        with self.assertRaises(HoldError) as context:
            sanitizer().payload(payload, **options)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def assert_record_held(self, record):
        with self.assertRaises(HoldError) as context:
            event_rows(record)
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_exact_pair_is_documentation_in_every_provider_format(self):
        for shape in ('chat', 'anthropic', 'responses'):
            with self.subTest(shape=shape):
                schema = parameters(sessionID={'type': 'string', 'pattern': SESSION_PATTERN,
                                               'description': 'Resume an invented child task'})
                rendered = tool_schemas(request([('invented_delegate', schema)], shape))[0]
                self.assertEqual(rendered['parameters']['properties']['sessionID'],
                                 schema['properties']['sessionID'])

    def test_exact_pair_still_sanitises_every_other_annotation(self):
        payload = {'parameters': parameters(sessionID={
            'type': 'string', 'pattern': SESSION_PATTERN,
            'description': 'Invented help; contact alex@example.com; '
                           'password="inventedSecretValue"; Example Holdings'})}
        clean = sanitizer()
        with mock.patch.object(clean, 'assert_clean', wraps=clean.assert_clean) as final_check:
            rendered = clean.payload(payload, schema_fields=('parameters',))
        final_check.assert_called_once_with(payload, rendered)
        safe = canonical(rendered)
        self.assertEqual(rendered['parameters']['properties']['sessionID']['pattern'], SESSION_PATTERN)
        self.assertNotIn('alex@example.com', safe)
        self.assertNotIn('inventedSecretValue', safe)
        self.assertNotIn('Example Holdings', safe)
        self.assertIn('[REDACTED_CREDENTIAL]', safe)

    def test_exact_pair_cannot_bypass_a_final_leak_rejection(self):
        payload = {'parameters': parameters(sessionID={'pattern': SESSION_PATTERN})}
        clean = sanitizer()
        with mock.patch.object(clean, 'assert_clean', side_effect=HoldError('final_leak_check_alias')) as check:
            with self.assertRaises(HoldError) as context:
                clean.payload(payload, schema_fields=('parameters',))
        self.assertEqual(context.exception.reason, 'final_leak_check_alias')
        check.assert_called_once()

    def test_public_prefix_does_not_expand_the_pattern_only_grammar(self):
        self.assertFalse(structural_pattern(SESSION_PATTERN))
        self.assertFalse(sanitise.Sanitizer._structural_pattern(SESSION_PATTERN))
        self.assertNotIn(SESSION_PATTERN, sanitise._STRUCTURAL_FORMAT_PATTERNS)
        self.assertTrue(sanitise.Sanitizer._structural_pattern(UUID_VALIDATOR))

    def test_other_identity_parameter_names_stay_held(self):
        for name in ('id', 'owner', 'task_id', 'session', 'session_id', 'session_uuid'):
            with self.subTest(name=name):
                schema = parameters(**{name: {'type': 'string', 'pattern': SESSION_PATTERN}})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_raw_name_is_not_case_folded_normalised_or_sanitised_for_pairing(self):
        for name in ('SessionID', 'sessionId', 'session_ID',
                     'session-ID', 'session ID', 'sessionID ', ' sessionID', 'sessionID_'):
            with self.subTest(name=name):
                schema = parameters(**{name: {'type': 'string', 'pattern': SESSION_PATTERN}})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_case_variants_and_any_added_pattern_text_stay_held(self):
        for pattern in ('^SES', '^Ses', '^seS', '^ses$', '^ses_', '^ses.*', '^ses|invented',
                        'invented|^ses', ' ^ses', '^ses\n', '^ses\x00', '^ses\u2603',
                        '^ses' + 'x' * 257):
            with self.subTest(pattern=pattern):
                schema = parameters(sessionID={'type': 'string', 'pattern': pattern})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_a_sanitised_key_collision_cannot_supply_the_public_parameter_name(self):
        payload = {'parameters': parameters(invented_session_id={'pattern': SESSION_PATTERN})}
        clean = sanitizer()
        original_key = clean._key
        with mock.patch.object(clean, '_key', side_effect=lambda key: (
                'sessionID' if key == 'invented_session_id' else original_key(key))):
            with self.assertRaises(HoldError) as context:
                clean.payload(payload, schema_fields=('parameters',))
        self.assertEqual(context.exception.reason, 'ambiguous_identity_field')

    def test_annotation_keyword_must_be_exactly_pattern(self):
        for keyword in ('Pattern', 'PATTERN', 'pattern ', 'x-pattern'):
            with self.subTest(keyword=keyword):
                schema = parameters(sessionID={'type': 'string', keyword: SESSION_PATTERN})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_pattern_property_keys_stay_held_even_beside_the_exact_pair(self):
        schemas = (
            {'type': 'object', 'patternProperties': {SESSION_PATTERN: {'type': 'string'}}},
            parameters(sessionID={'pattern': SESSION_PATTERN, 'patternProperties': {
                SESSION_PATTERN: {'type': 'string', 'const': INVENTED_PERSON}}}),
            parameters(invented_options={'type': 'object', 'patternProperties': {
                SESSION_PATTERN: {'type': 'string'}}}),
            {'type': 'object', 'patternProperties': {'sessionID': {'pattern': SESSION_PATTERN}}},
        )
        for schema in schemas:
            with self.subTest(schema=schema):
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_instance_string_keywords_stay_held(self):
        for keyword in ('default', 'const', 'enum', 'examples', 'example'):
            with self.subTest(keyword=keyword):
                schema = parameters(sessionID={'type': 'string', keyword: SESSION_PATTERN})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_instance_lists_keep_the_existing_identity_references(self):
        # Lists were already pseudonymised, not refused. They must not become
        # documentation merely because one value is the public validator.
        for keyword in ('enum', 'examples'):
            with self.subTest(keyword=keyword):
                schema = parameters(sessionID={keyword: [SESSION_PATTERN, INVENTED_PERSON]})
                rendered = tool_schemas(request([('invented_delegate', schema)]))[0]
                values = rendered['parameters']['properties']['sessionID'][keyword]
                self.assertTrue(all(value.startswith('id_') for value in values))
                self.assertNotIn(SESSION_PATTERN, canonical(rendered))
                self.assertNotIn(INVENTED_PERSON, canonical(rendered))

    def test_schema_shaped_instances_stay_held(self):
        instance = parameters(sessionID={'type': 'string', 'pattern': SESSION_PATTERN})
        for keyword in ('default', 'const', 'enum', 'examples', 'example'):
            with self.subTest(keyword=keyword):
                value = [instance] if keyword in ('enum', 'examples') else instance
                schema = parameters(sessionID={keyword: value})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_tool_call_arguments_stay_data_in_every_provider_format(self):
        arguments = {'parameters': parameters(sessionID={'type': 'string', 'pattern': SESSION_PATTERN})}
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

    def test_undeclared_schema_and_other_declared_fields_stay_held(self):
        schema = parameters(sessionID={'type': 'string', 'pattern': SESSION_PATTERN})
        self.assert_held({'parameters': schema})
        self.assert_held({'input_schema': schema}, schema_fields=('input_schema',))
        self.assert_held({'arguments': {'parameters': schema}}, schema_fields=('parameters',))

    def test_identity_objects_stay_held(self):
        for payload in ({'sessionID': {'type': 'string', 'pattern': SESSION_PATTERN}},
                        {'owner': {'sessionID': {'type': 'string', 'pattern': SESSION_PATTERN}}},
                        {'owner': {'login': 'invented-login', 'pattern': SESSION_PATTERN}}):
            with self.subTest(payload=payload):
                self.assert_held(payload)

    def test_reference_annotations_stay_held_even_beside_the_exact_pair(self):
        for pointer in ('#/$defs/InventedSession', '#/properties/sessionID',
                        SESSION_PATTERN, 'https://invented.example/schema'):
            with self.subTest(pointer=pointer):
                schema = parameters(sessionID={'pattern': SESSION_PATTERN, '$ref': pointer})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_reference_target_maps_do_not_name_parameters_for_the_exemption(self):
        for keyword in ('$defs', 'definitions', 'dependentSchemas'):
            for target in ({'sessionID': {'type': 'string', 'pattern': SESSION_PATTERN}},
                           {'InventedTarget': parameters(sessionID={'pattern': SESSION_PATTERN})}):
                with self.subTest(keyword=keyword, target=target):
                    schema = {keyword: target, 'type': 'object', 'properties': {}}
                    self.assert_record_held(request([('invented_delegate', schema)]))

    def test_nested_properties_and_schema_children_do_not_inherit_the_pair(self):
        for child in (parameters(sessionID={'pattern': SESSION_PATTERN}),
                      {'type': 'array', 'items': {'pattern': SESSION_PATTERN}},
                      {'anyOf': [{'type': 'string', 'pattern': SESSION_PATTERN}, {'type': 'null'}]},
                      {'allOf': [{'type': 'string', 'pattern': SESSION_PATTERN}]}):
            with self.subTest(child=child):
                schema = parameters(sessionID=child)
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_non_string_schema_shaped_patterns_stay_held(self):
        for pattern in ({'sessionID': {'pattern': SESSION_PATTERN}},
                        [{'sessionID': {'pattern': SESSION_PATTERN}}]):
            with self.subTest(pattern=pattern):
                schema = parameters(sessionID={'pattern': pattern})
                self.assert_record_held(request([('invented_delegate', schema)]))

    def test_non_string_pattern_values_keep_existing_typed_identity_handling(self):
        for pattern in (None, True, 7, [SESSION_PATTERN]):
            with self.subTest(pattern=pattern):
                schema = parameters(sessionID={'pattern': pattern})
                rendered = tool_schemas(request([('invented_delegate', schema)]))[0]
                safe = rendered['parameters']['properties']['sessionID']['pattern']
                if isinstance(pattern, list):
                    self.assertTrue(all(item.startswith('id_') for item in safe))
                else:
                    self.assertEqual(safe, pattern)
                self.assertNotIn(SESSION_PATTERN, canonical(rendered))

    def test_string_subclasses_do_not_match_the_exact_string_pair(self):
        class InventedString(str):
            pass
        schema = parameters(sessionID={'pattern': InventedString(SESSION_PATTERN)})
        self.assert_held({'parameters': schema}, schema_fields=('parameters',))
        schema = {'type': 'object', 'properties': {InventedString('sessionID'): {'pattern': SESSION_PATTERN}}}
        self.assert_held({'parameters': schema}, schema_fields=('parameters',))

    def test_non_identity_parameters_retain_their_prior_prose_handling(self):
        # The baseline did not hold non-identity prose. This rule must not grant
        # it new schema authority or otherwise change its output.
        for name in ('invented_filter', 'sessionid', 'SESSIONID'):
            with self.subTest(name=name):
                payload = {'parameters': parameters(**{name: {'type': 'string', 'pattern': SESSION_PATTERN}})}
                rendered = sanitizer().payload(payload, schema_fields=('parameters',))
                self.assertEqual(canonical(rendered).encode(), canonical(payload).encode())

    def test_additional_identity_bearing_annotation_still_holds(self):
        for keyword in ('x-owner-value', 'x-session-default'):
            with self.subTest(keyword=keyword):
                schema = parameters(sessionID={'type': 'string', 'pattern': SESSION_PATTERN,
                                               keyword: INVENTED_PERSON})
                self.assert_record_held(request([('invented_delegate', schema)]))



class OpencodeIdTextTests(unittest.TestCase):
    """Council C3 Opus S1: released subagent results carry raw child session IDs."""
    SESSION = 'ses_' + '0a1b2c3d4e5f' + 'Q7rT2vX9kLm3Np'
    MESSAGE = 'msg_' + 'f0e1d2c3b4a5' + 'Zy8Xw7Vu6Ts5Rq'

    def test_prefixed_ids_in_prose_become_the_same_reference_as_the_argument(self):
        clean = sanitizer()
        text = clean.text('<subagent sessionID="%s" state="completed"> (sessionID: %s) reply %s'
                          % (self.SESSION, self.SESSION, self.MESSAGE))
        self.assertNotIn(self.SESSION, text)
        self.assertNotIn(self.MESSAGE, text)
        self.assertNotIn('0a1b2c3d4e5f', text)
        ref = clean.refs.opaque('id', self.SESSION)
        self.assertEqual(text.count(ref), 2)
        rendered = clean.payload({'arguments': {'sessionID': self.SESSION}, 'content': 'done ' + self.SESSION})
        self.assertEqual(canonical(rendered).count(ref), 2)
        self.assertNotIn(self.SESSION, canonical(rendered))

    def test_final_check_refuses_a_surviving_prefixed_id(self):
        with self.assertRaises(HoldError) as context:
            sanitizer().assert_clean({'content': 'resume ' + self.SESSION}, {'content': 'resume Q' + self.SESSION + 'Q'})
        self.assertEqual(context.exception.reason, 'final_leak_check_original_value')

    def test_underscore_adjacent_ids_are_replaced_and_checked(self):
        # Council C3 r2, Astra S2: \\b treats '_' as a word character.
        for wrapped in ('_%s_', '__%s__', '%s_x', 'child_%s', 'x%s', '%s_summary', '\x1b[1m%s\x1b[0m',
                        '%%22%s%%22', '\u5b50\u4f1a\u8bdd%s\u5df2\u5b8c\u6210'):
            text = wrapped % self.SESSION
            with self.subTest(text=text):
                clean = sanitizer()
                safe = clean.text('result ' + text + ' done')
                self.assertNotIn(self.SESSION[4:], safe)
                with self.assertRaises(HoldError) as context:
                    sanitizer().assert_clean({'content': 'result ' + text}, {'content': 'result ' + text})
                self.assertIn(context.exception.reason, ('final_leak_check_original_value',))
        clean = sanitizer()
        self.assertIn(clean.refs.opaque('id', self.SESSION), clean.text('child_' + self.SESSION + ' ok'))

    def test_long_tokens_holding_an_id_are_still_replaced_whole(self):
        # Council C3 r2, Astra S1: replacing the ID first shortened a 40-character
        # token below the long-token threshold and exposed its prefix.
        for separator in ('/', '-', '+'):
            for prefix in ('nerinafox', 'nerinafoxes'):
                token = prefix + separator + self.SESSION
                with self.subTest(token=token):
                    self.assertGreaterEqual(len(token), 40)
                    safe = sanitizer().text('see ' + token + ' now')
                    self.assertNotIn(prefix, safe)
                    self.assertNotIn(self.SESSION[4:], safe)
        short = 'nerinaf/' + self.SESSION
        self.assertLess(len(short), 40)
        self.assertNotIn(self.SESSION[4:], sanitizer().text('see ' + short + ' now'))

    def test_lines_at_the_long_run_thresholds_are_still_replaced_whole(self):
        # Council C3 r3, Astra S1: replacing an ID shortened a line below the
        # long-run (128) and path-run (256) guards and exposed its prefix.
        for tail in ('a.' * 29, '.a/' * 62):
            text = 'nerinafox._' + self.SESSION + '_.' + 'a' * 20 + '=' + 'b' * 19 + '.' + tail
            with self.subTest(tail=tail[:3]):
                safe = sanitizer().text(text)
                self.assertNotIn('nerinafox', safe)
                self.assertNotIn(self.SESSION[4:], safe)

    def test_final_check_refuses_a_surviving_tail_alone(self):
        # Council C3 r3, Opus S2: only the tail check catches this.
        with self.assertRaises(HoldError) as context:
            sanitizer().assert_clean({'content': 'see ' + self.SESSION}, {'content': 'see SES_' + self.SESSION[4:]})
        self.assertEqual(context.exception.reason, 'final_leak_check_original_value')

    def test_an_alias_reference_beside_an_escape_keeps_its_residual_signal(self):
        # Council C3 r4, Astra S1: the ID rule consumed 'file_<ref>AB' after
        # 'Nerina\\' and with it the signal that replaces the whole line.
        data = policy_data()
        data['aliases'] = {'file': ['project-']}
        clean = sanitise.Sanitizer(sanitise.Policy(data, b'k' * 48))
        safe = canonical(clean.payload({'content': 'Nerina\\project-AB'}))
        self.assertNotIn('Nerina', safe)

    def test_partly_rewritten_urls_and_emails_still_hold(self):
        # Council C3 r4, Opus S1: the ID rule rewrote only the ID inside a URL or
        # email the URL/email rules missed, so the whole original value no longer
        # matched and the record was emitted with the host or address prefix.
        cases = (
            {'a': 'open https://app.corp.ex/chat?session=%s&tab=1 now' % self.SESSION,
             'b': 'log:\\nhttps://app.corp.ex/chat?session=%s&tab=1' % self.SESSION},
            {'a': 'mail nerina@frostwillow.com now', 'b': 'owner nerina@frostwillow.com%s x' % self.SESSION},
        )
        for payload in cases:
            with self.subTest(payload=sorted(payload.values())[0][:12]):
                with self.assertRaises(HoldError) as context:
                    sanitizer().payload(payload)
                self.assertEqual(context.exception.reason, 'final_leak_check_original_value')

    def test_many_ids_stay_within_the_final_check_budget(self):
        # Council C3 r3, Astra S2: whole IDs and tails together doubled the budget.
        original = {'content': ' '.join('ses_%012xQ7rT2vX9kLm3Np' % i for i in range(16000))}
        clean = sanitizer()
        rendered = clean.payload(original)
        self.assertNotIn('Q7rT2vX9kLm3Np', canonical(rendered))

    def test_ordinary_identifiers_are_unchanged(self):
        for value in ('snake_case_name', 'id_0123456789abcdef01234567', 'ses_short', 'my_variable_name_here_ok',
                      'ses_' + 'G' * 12 + 'a' * 14):
            with self.subTest(value=value):
                self.assertEqual(sanitizer().text('use ' + value + ' now'), 'use ' + value + ' now')


if __name__ == '__main__':
    unittest.main()
