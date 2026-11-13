"""Round 6 (Opus): decisions that must cover the whole record, and chained addresses."""
import json
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import research
from sanitise import Policy, Sanitizer, canonical
from test_identity_refusal import event_rows
from test_research_poc import policy_data


def chat(*contents):
    body = {'model': 'invented-model',
            'messages': [{'role': 'user' if index % 2 == 0 else 'assistant', 'content': content}
                         for index, content in enumerate(contents)]}
    return {'type': 'request', 'body': json.dumps(body), 'headers': {'Authorization': 'invented'}}


class RecordWidePathDecisionTests(unittest.TestCase):
    def test_path_in_one_message_marks_a_name_in_another(self):
        rows = event_rows(chat('edit src\\app\\main.cs please', 'done', 'it says corp\\nerina frostwillow'))
        out = canonical([json.loads(row['payload']) for row in rows])
        self.assertNotIn('nerina', out)
        self.assertNotIn('frostwillow', out)

    def test_key_beside_a_triggering_value_is_replaced(self):
        clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        out = canonical(clean.payload({'Users\\Nerina Frostwillow': 'see src\\x.cs'}))
        self.assertNotIn('Nerina', out)

    def test_flag_does_not_leak_into_the_next_payload(self):
        clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        clean.payload({'a': 'see src\\x.cs'})
        self.assertFalse(clean.record_backslash_paths)
        self.assertEqual(clean.payload({'b': 'regex \\d+ stays'})['b'], 'regex \\d+ stays')


class ChainedAddressTests(unittest.TestCase):
    def test_address_chained_onto_another_is_replaced(self):
        clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        for text in ('mailto:ops@pricing.invented.example%2Cnerina.frostwillow@pricing.invented.example',
                     'a@b.io+zorvex.q@corp.invented.example', 'x@y.example-nerina.q@corp.invented.example'):
            with self.subTest(text=text):
                out = canonical(clean.payload({'t': text}))
                for fragment in ('nerina', 'zorvex', 'frostwillow'):
                    self.assertNotIn(fragment, out)


class AliasCostTests(unittest.TestCase):
    def test_paths_do_not_pay_one_reference_per_alias(self):
        clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        text = '\n'.join('C:\\Users\\u%d\\x%d.cs' % (index, index) for index in range(8000))
        started = time.perf_counter()
        clean.payload({'t': text})
        self.assertLess(time.perf_counter() - started, 2.0)



class GeminiRoundSixTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def emitted(self, payload, **options):
        return canonical(self.clean.payload(payload, **options))

    def test_multi_line_secret_on_a_path_line_is_not_split(self):
        for text in ('Loaded C:\\Users\\elara.smith\\id_rsa: -----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n'
                     'SuperSecretKeyMaterial12345\n-----END RSA PRIVATE KEY-----',
                     'api_key = "C:/Users/elara\nSuperSecretSecondLine123"',
                     'api_key = "CORP\\elara.smith\nSuperSecretSecondLine123"'):
            with self.subTest(text=text[:30]):
                out = self.emitted({'t': text})
                self.assertNotIn('SuperSecret', out)
                self.assertNotIn('elara', out)

    def test_credential_rule_cannot_strand_a_name_on_a_path_line(self):
        out = self.emitted({'t': 'auth: C:\\Users\\Frostwillow, Nerina\nnext line ok'})
        self.assertNotIn('Nerina', out)
        self.assertIn('next line ok', out)

    def test_stray_private_key_marker_fails_the_final_check(self):
        from sanitise import HoldError
        with self.assertRaises(HoldError):
            self.clean.assert_clean({'t': 'x'}, {'t': 'SuperSecret\n-----END RSA PRIVATE KEY-----'})

    def test_mixed_separator_path_with_an_unknown_extension(self):
        for text in ('open Users\\Nerina Frostwillow\\home/nerina.smith\nwhoami: CORP\\nerina',
                     'open Users\\Nerina Frostwillow\\proj/data.sqlite'):
            with self.subTest(text=text):
                out = self.emitted({'t': text})
                for fragment in ('Nerina', 'Frostwillow', 'nerina'):
                    self.assertNotIn(fragment, out)

    def test_chained_address_is_an_original_value(self):
        from sanitise import HoldError
        with self.assertRaises(HoldError) as context:
            self.clean.assert_clean({'password': 'a@b.io+elara.brightwater@invented.com'},
                                    {'password': '[WITHHELD]', 'text': '+elara.brightwater@invented.com1'})
        self.assertEqual(context.exception.reason, 'final_leak_check_original_value')

    def test_pattern_property_key_that_opens_identity_context(self):
        from sanitise import HoldError
        schema = {'type': 'object', 'patternProperties': {
            '^elara\\.brightwater_id': {'type': 'string', 'description': 'Invented id'}}}
        with self.assertRaises(HoldError):
            self.clean.payload({'parameters': schema}, schema_fields=('parameters',))

    def test_credential_key_names_are_linear_and_still_redacted(self):
        out = self.emitted({'t': 'x-auth: hunter22 and my-api_token=abcd1234'})
        self.assertNotIn('hunter22', out)
        self.assertNotIn('abcd1234', out)
        started = time.perf_counter()
        self.clean.payload({'t': 'a-' * 64000})
        self.clean.payload({'t': ('-a/' * 20 + '-a@b.co/') * 400 + ('-a/' * 20 + '-Example Holdings/') * 400})
        self.assertLess(time.perf_counter() - started, 2.0)


class SolRoundSevenTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def test_multi_line_credentials_survive_path_line_replacement_in_the_worker(self):
        for text in ('password = "C:\\invented\\keys\ninvented-secret-second-line"',
                     'see C:\\x\\y.txt\nAuthorization: Bearer abcdefghijklmnopqrstuv',
                     'key C:\\x\\id_rsa -----BEGIN OPENSSH PRIVATE KEY-----\ninvented-secret-body\n'
                     '-----END OPENSSH PRIVATE KEY-----'):
            with self.subTest(text=text[:30]):
                rows = event_rows(chat(text))
                out = canonical([json.loads(row['payload']) for row in rows])
                self.assertNotIn('invented-secret', out)
                self.assertNotIn('abcdefghijklmnop', out)

    def test_email_redaction_matches_the_reference_pattern(self):
        import random
        from sanitise import EMAIL_REDACT_PATTERN
        alphabet = list('ab.+%-_@xyz.io ')
        generator = random.Random(3)
        for _ in range(20000):
            text = ''.join(generator.choice(alphabet) for _ in range(generator.randint(1, 24)))
            want = EMAIL_REDACT_PATTERN.sub(lambda m: self.clean.refs.opaque('contact', m.group(0).lower()), text)
            self.assertEqual(self.clean._redact_emails(text), want, repr(text))

    def test_near_threshold_runs_stay_fast(self):
        started = time.perf_counter()
        self.clean.payload({'t': ('+' * 127 + ' ') * 2048})
        self.clean.payload({'t': ('a.' * 63 + 'a ') * 2048})
        self.assertLess(time.perf_counter() - started, 2.0)


class OpusRoundSevenTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def emitted(self, payload):
        return canonical(self.clean.payload(payload))

    def test_credential_value_on_the_line_after_a_path_line(self):
        for text in ('config at "C:\\cfg\\app.ini" api_key:\n  "q7Zr2Lm9Xc4Vb8Nn"',
                     'Loaded "C:\\keys\\k.pem": -----BEGIN PRIVATE KEY-----\n' + 'A' * 52 +
                     '\nq83Vb7Lp2Kx9Rr4Tt\n-----END PRIVATE KEY-----'):
            with self.subTest(text=text[:30]):
                out = self.emitted({'t': text})
                for secret in ('q7Zr2Lm9Xc4Vb8Nn', 'q83Vb7Lp2Kx9Rr4Tt', 'PRIVATE KEY'):
                    self.assertNotIn(secret, out)

    def test_original_address_with_a_diff_marker(self):
        from sanitise import HoldError
        with self.assertRaises(HoldError):
            self.clean.payload({'t': '-nerina.q@frostcorp.example\n\u5df2\u79fb\u9664nerina.q@frostcorp.example\u7684'})

    def test_alias_ending_a_relative_path(self):
        for text in ('see notes/nerina-frostwillow/meeting.example-holdings today',
                     'deploy/nerina/values.example-holdings'):
            with self.subTest(text=text):
                out = self.emitted({'t': text})
                for fragment in ('nerina', 'holdings', 'meeting', 'values'):
                    self.assertNotIn(fragment, out)

    def test_diff_markers_stay_outside_the_address_reference(self):
        out = json.loads(self.emitted({'t': 'diff\n-first@x.example\n+first@x.example'}))['t']
        removed, added = out.split('\n')[1:]
        self.assertEqual(removed[0], '-')
        self.assertEqual(added[0], '+')
        self.assertEqual(removed[1:], added[1:])

    def test_many_short_backslash_lines_stay_fast(self):
        started = time.perf_counter()
        self.clean.payload({'t': 'x\\y\n' * 200000, 'p': 'C:\\Users\\a\\b.cs'})
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_record_flag_is_reset_after_the_worker(self):
        event_rows(chat('edit src\\app\\main.cs please'))
        # event_rows builds its own sanitizer; check the worker path directly.
        clean = Sanitizer(Policy(policy_data(), b'k' * 48))
        clean.refs.bind_revision('rev_' + 'a' * 32)
        import parsing
        from test_identity_refusal import REVISION, RECORD_ROW
        research._event_rows(REVISION, None, RECORD_ROW, parsing.derive_events(chat('see src\\x.cs'), clean.refs), clean)
        self.assertFalse(clean.record_backslash_paths)


class SolRoundEightTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def emitted(self, payload):
        return canonical(self.clean.payload(payload))

    def test_raw_value_shaped_like_a_reference_is_still_a_credential(self):
        for text in ('password="file_aaaaaaaaaaaaaaaaaaaaaaaa\ninvented-secret-second-line"',
                     'Bearer file_aaaaaaaaaaaaaaaaaaaaaaaa.secret',
                     'token: file_aaaaaaaaaaaaaaaaaaaaaaaa'):
            with self.subTest(text=text[:30]):
                out = self.emitted({'t': text})
                self.assertNotIn('invented-secret', out)
                self.assertNotIn('file_aaaaaaaaaaaaaaaaaaaaaaaa', out)

    def test_generated_reference_after_a_keyword_is_accepted(self):
        out = json.loads(self.emitted({'t': 'Authorization: Bearer\nC:\\src\\x\\y.cs'}))['t']
        self.assertIn('Bearer\nfile_', out)

    def test_alias_reference_with_a_suffix_ending_a_relative_path(self):
        out = self.emitted({'t': 'notes/nerina-frostwillow/meeting.Alex Example_X'})
        self.assertNotIn('nerina', out)
        self.assertNotIn('meeting', out)

    def test_punctuation_only_mailbox_is_still_an_address(self):
        out = self.emitted({'t': '\u90ae\u7bb1+@invented.example '})
        self.assertNotIn('invented.example', out)

    def test_crlf_lines_are_merged(self):
        started = time.perf_counter()
        out = json.loads(self.emitted({'t': 'x\\y\r\n' * 100000, 'p': 'C:\\Users\\a\\b.cs'}))
        self.assertLess(time.perf_counter() - started, 2.0)
        self.assertEqual(out['t'].count('file_'), 1)


class GeminiRoundEightTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def outcome(self, payload, **options):
        from sanitise import HoldError
        try:
            return canonical(self.clean.payload(payload, **options))
        except HoldError as error:
            return 'HOLD:' + error.reason

    def test_address_after_an_at_sign_is_an_original_value(self):
        from sanitise import email_tokens
        self.assertEqual(list(email_tokens('@nerina.frostwillow@invented.com')), ['nerina.frostwillow@invented.com'])
        out = self.outcome({'t': '@nerina.frostwillow@invented.com\n\u5df2\u79fb\u9664nerina.frostwillow@invented.com\u7684'})
        self.assertNotIn('nerina', out)

    def test_dotted_and_slashed_aliases_inside_relative_paths(self):
        for text in ('see a/nerina/pricing.internal.example today', 'see notes/nerina.f_1/pricing.internal.example today',
                     'see nerina-frostwillow.example-holdings/pricing-service.cs today',
                     'see example-holdings/pricing-service.nerina-frostwillow.cs today',
                     'see deploy/nerina.frostwillow/pricing.internal.example today',
                     'notes/nerina-frostwillow/meeting.Alex Example_X'):
            with self.subTest(text=text):
                out = self.outcome({'t': text})
                self.assertFalse(out.startswith('HOLD'), out)
                for fragment in ('nerina', 'Example', 'pricing'):
                    self.assertNotIn(fragment, out)

    def test_hex_after_a_dotted_ref_still_processes(self):
        out = self.outcome({'t': 'commit refs/heads/v1.' + '0123456789abcdef' * 2})
        self.assertFalse(out.startswith('HOLD'), out)

    def test_path_punctuation_inside_a_windows_path(self):
        for payload in ({'t': 'open Users\\Nerina Frostwillow\\proj-/@scope/data.sqlite'},
                        {'t': 'open Users\\Nerina Frostwillow\\(local)/~nerina/data.sqlite'},
                        {'a': 'open Users\\Nerina Frostwillow\\' + 'A' * 20 + '+' + 'B' * 20 + '.json',
                         'b': 'whoami: CORP\\nerina'},
                        {'t': 'auth: CORP\\Frostwillow, Nerina\nopen Users\\Nerina Frostwillow\\' + 'A' * 20 + '+' +
                              'B' * 20 + '.json'}):
            with self.subTest(payload=str(payload)[:40]):
                out = self.outcome(payload)
                for fragment in ('Nerina', 'nerina', 'Frostwillow'):
                    self.assertNotIn(fragment, out)

    def test_every_pattern_property_key_must_be_structural(self):
        for key, child in (('^elara[.]brightwater_id$', {'type': 'string', 'description': 'Invented'}),
                           ('^elara[.]brightwater$', {'type': 'object', 'properties': {
                               'owner': {'type': 'string', 'description': 'Invented'}}})):
            with self.subTest(key=key):
                out = self.outcome({'parameters': {'type': 'object', 'patternProperties': {key: child}}},
                                   schema_fields=('parameters',))
                self.assertEqual(out, 'HOLD:ambiguous_identity_field')

    def test_quoted_secret_with_a_backslash_before_the_line_break(self):
        out = self.outcome({'t': 'see src\\app.cs\npassword = "C:\\Users\\elara\\\nSuperSecretSecondLine"'})
        self.assertNotIn('SuperSecret', out)
        self.assertNotIn('elara', out)


class OpusRoundEightTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def outcome(self, payload):
        from sanitise import HoldError
        try:
            return canonical(self.clean.payload(payload))
        except HoldError as error:
            return 'HOLD:' + error.reason

    def test_nested_secret_under_a_credential_section(self):
        for text in ('basic_auth:\n  password: hunter2-invented', 'oauth:\n  client_secret: s3cr3t-invented',
                     'proxy_auth:\n  password: hunter2-invented', 'db_credentials:\n  password: hunter2-invented',
                     'credentials:\n  password: hunter2-invented'):
            with self.subTest(text=text):
                out = self.outcome({'t': text})
                self.assertNotIn('hunter2', out)
                self.assertNotIn('s3cr3t', out)
        for text in ('x-auth: hunter22', 'token: user:pass', 'password:\n  x9invented'):
            with self.subTest(text=text):
                self.assertIn('[REDACTED_CREDENTIAL]', self.outcome({'t': text}))

    def test_backslash_straight_after_a_slash_starts_a_path(self):
        out = self.outcome({'t': 'see src/\\Nerina Frostwillow.docx today'})
        self.assertNotIn('Nerina', out)

    def test_key_block_without_both_markers_holds(self):
        out = self.outcome({'t': 'Loaded C:\\keys\\a.pem: -----BEGIN PRIVATE KEY-----\nq83Vb7Lp2Kx9Rr4TtZq=='})
        self.assertEqual(out, 'HOLD:final_leak_check_credential')

    def test_blank_and_alternating_lines_do_not_grow_the_text(self):
        started = time.perf_counter()
        for text in ('\\\n\n' * 100000, 'x\\y\na\n' * 100000, '\\\r\n' * 100000):
            out = json.loads(self.outcome({'t': text, 'p': 'C:\\Users\\a\\b.cs'}))
            self.assertLessEqual(len(out['t']), 2 * len(text) + 64)
        self.assertLess(time.perf_counter() - started, 3.0)



class SolRoundNineTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def test_padded_and_colon_ended_values_are_redacted(self):
        for text in ('password: aW52ZW50ZWQ=', 'token: abc:', 'secret=aW52ZW50ZWQ=='):
            with self.subTest(text=text):
                self.assertIn('[REDACTED_CREDENTIAL]', canonical(self.clean.payload({'t': text})))
        rows = event_rows(chat('password: aW52ZW50ZWQ='))
        self.assertNotIn('aW52ZW50ZWQ', canonical([json.loads(row['payload']) for row in rows]))

    def test_marker_behind_a_credential_key_holds(self):
        from sanitise import HoldError
        with self.assertRaises(HoldError):
            event_rows(chat('see src\\x.cs\nauth: -----BEGIN PRIVATE KEY-----\nInventedSecretBodyHere'))

    def test_spaced_alias_chain_is_linear(self):
        started = time.perf_counter()
        self.clean.payload({'t': '-Example Holdings/' * 4000})
        self.assertLess(time.perf_counter() - started, 0.5)



class GeminiRoundNineTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def outcome(self, payload):
        from sanitise import HoldError
        try:
            return canonical(self.clean.payload(payload))
        except HoldError as error:
            return 'HOLD:' + error.reason

    def test_nested_keys_with_spaces_equals_and_quotes(self):
        for text in ('basic_auth:\n  password = hunter2-invented', 'oauth:\n  client_secret : s3cr3t-invented',
                     'basic_auth:\n  "password": "hunter2-invented"',
                     'auth = "unclosed\\\npassword = "MySuperSecretPassword123"'):
            with self.subTest(text=text):
                out = self.outcome({'t': text})
                for secret in ('hunter2', 's3cr3t', 'MySuperSecret'):
                    self.assertNotIn(secret, out)

    def test_generated_reference_must_be_the_whole_value(self):
        for payload in ({'t': 'Authorization: Bearer Secr3t=a@b.co'}, {'t': 'Authorization: Bearer Secr3t=Alex Example'},
                        {'t': 'Authorization: Bearer /a/b/c.py:MySuperSecretToken'},
                        {'a': 'password = " SuperSecret', 'b': 'src/app.py"'}):
            with self.subTest(payload=str(payload)[:40]):
                self.assertEqual(self.outcome(payload), 'HOLD:final_leak_check_credential')

    def test_original_addresses_match_redaction(self):
        from sanitise import email_tokens
        self.assertIn('nerina.frostwillow@invented.com', list(email_tokens('a@b.io+@nerina.frostwillow@invented.com')))
        out = self.outcome({'t': 'a@b.io+@nerina.frostwillow@invented.com\n\u5df2\u79fb\u9664'
                                 'nerina.frostwillow@invented.com\u7684'})
        self.assertNotIn('nerina', out)

    def test_backslash_after_path_punctuation(self):
        for text in ('see ~\\Nerina.docx', 'see Users~\\Nerina.docx', 'see Saffron+\\Nerina.docx'):
            with self.subTest(text=text):
                self.assertNotIn('Nerina', self.outcome({'t': text}))



class OpusRoundNineTests(unittest.TestCase):
    def setUp(self):
        self.clean = Sanitizer(Policy(policy_data(), b'k' * 48))

    def test_padded_base64_and_kubernetes_secrets(self):
        for text in ('DB_PASSWORD=c2VjcmV0cGFzcw==', 'password: cGFzc3dvcmQxMjM=', 'client_secret=YWJjZGVmZ2hpams= more',
                     'data:\n  password: cGFzc3dvcmQxMjM=\n  token: dG9rZW4=', 'secret: hunter2:'):
            with self.subTest(text=text):
                out = canonical(self.clean.payload({'t': text}))
                for secret in ('c2VjcmV0', 'cGFzc3dv', 'YWJjZGVm', 'dG9rZW4', 'hunter2'):
                    self.assertNotIn(secret, out)
        rows = event_rows(chat('kubectl get secret -o yaml\ndata:\n  password: cGFzc3dvcmQxMjM=\n'))
        self.assertNotIn('cGFzc3dv', canonical([json.loads(row['payload']) for row in rows]))

    def test_credential_keywords_in_long_runs_are_linear(self):
        started = time.perf_counter()
        self.clean.payload({'t': 'x_token=1&' * 16000 + 'y= '})
        self.clean.payload({'t': 'auth:a' * 16000 + ': '})
        self.assertLess(time.perf_counter() - started, 0.5)

    def test_credential_split_across_strings_holds(self):
        from sanitise import HoldError
        for payload in ({'a': 'set password: "', 'b': 'hunter2invented /tmp/x/y.txt"'},
                        {'a': 'export API_KEY="', 'b': 'q8Zinvented src/x/y.py"'}, {'t': 'Bearer ab9=/x.txt'}):
            with self.subTest(payload=str(payload)[:40]):
                with self.assertRaises(HoldError):
                    self.clean.payload(payload)

    def test_alias_holding_a_slash_is_not_split_by_a_path(self):
        data = policy_data()
        data['aliases']['organisations'] = list(data['aliases']['organisations']) + ['example-holdings/zeus']
        clean = Sanitizer(Policy(data, b'k' * 48))
        out = json.loads(canonical(clean.payload({'t': 'see src/x.example-holdings/zeus today'})))['t']
        self.assertNotIn('zeus', out)

    def test_references_are_recorded_only_inside_a_payload(self):
        before = len(self.clean.refs.generated)
        for index in range(1000):
            self.clean.refs.opaque('obs', str(index))
        self.assertEqual(len(self.clean.refs.generated), before)


if __name__ == '__main__':
    unittest.main()
