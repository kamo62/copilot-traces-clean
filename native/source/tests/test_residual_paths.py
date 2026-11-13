"""Residual Windows path shapes must be redacted, not just rejected by the final check."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import time

from sanitise import residual_path_present, HoldError, Policy, RELATIVE_FILE_PATTERN, RESIDUAL_WINDOWS_PATH_PATTERN, Sanitizer
from test_research_poc import policy_data


class ResidualPathRedactionTests(unittest.TestCase):
    def setUp(self):
        self.sanitizer = Sanitizer(Policy(policy_data(), b'k' * 48))

    def assert_redacted(self, text):
        out = self.sanitizer.text(text)
        self.assertNotIn('\\', out, out)
        self.assertIsNone(RESIDUAL_WINDOWS_PATH_PATTERN.search(out), out)
        self.assertFalse(residual_path_present(out), out)
        self.assertIn('file_', out)
        return out

    def test_drive_less_backslash_path_is_redacted(self):
        self.assert_redacted(r'open src\utils\helpers.cs before the edit')

    def test_unc_path_is_redacted(self):
        self.assert_redacted(r'copy from \\fileserver\share\report.xlsx afterwards')

    def test_path_with_space_and_line_suffix_is_redacted(self):
        self.assert_redacted(r'see build\Release Output\app.dll:12 for the failure')

    def test_mixed_separator_path_leaves_no_relative_prefix(self):
        # Live shape: the residual rule redacted the backslash half and left
        # 'config/file_<ref>.json', which the final check then rejected.
        for text in (r'see config/app\settings.json', r'edit src/sub\file.cs now', r'open lib/a\b\c.py'):
            with self.subTest(text=text):
                out = self.assert_redacted(text)
                self.assertNotIn('/', out, out)

    def test_literal_escape_next_to_a_redacted_path_converges(self):
        # Live shape: embedded JSON text with a literal backslash-n before a path.
        # Redacting the path produced 'these\\n- file_<ref>.cs', a residual match.
        for text in ('see these\\n- src/foo.cs', 'indent   value\\t./lib/util/helpers.ts'):
            with self.subTest(text=text):
                out = self.sanitizer.text(text)
                self.assertIsNone(RESIDUAL_WINDOWS_PATH_PATTERN.search(out), out)
                self.assertIn('file_', out)

    def test_domain_user_keeps_no_name_fragment(self):
        # DOMAIN\\first.last matches the residual shape; the '.last' must not
        # survive as a file extension in the text or the file metadata.
        out = self.assert_redacted(r'signed in as INVENTED\alex.example today')
        self.assertNotIn('example', out)
        self.assertNotIn('example', repr(self.sanitizer.file_references))

    def test_deep_mixed_separator_path_converges(self):
        out = self.assert_redacted(r'see a\b/a\b/a\b/a\b/a\b/a\b/a\b/leaf.py now')
        self.assertNotIn('/', out, out)

    def test_long_backslash_free_token_is_linear(self):
        started = time.perf_counter()
        self.sanitizer.text('a' * 64000)
        self.sanitizer.text(('word ' * 12000) + 'x\\')
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_token_next_to_an_escape_leaves_no_residual(self):
        token = 'Ab3x' * 12
        for text in ('line\\n' + token + '.json done', 'line\\n' + 'Ab3=' * 12 + '.json done'):
            with self.subTest(text=text):
                out = self.sanitizer.text(text)
                self.assertIsNone(RESIDUAL_WINDOWS_PATH_PATTERN.search(out), out)
                self.assertNotIn('Ab3', out)

    def test_no_fragment_survives_on_either_side(self):
        # The path characters cannot tell where an attached folder name starts
        # or where a surname ends, so the whole whitespace-delimited token goes.
        cases = {
            'tmp at C:\\Users\\INVENT~1\\AppData\\Local\\Temp\\tmp123.tmp\nnext': ('INVENT', 'AppData'),
            'built C:\\Users\\Jos\u00e9\\source\\repos\\app\\Program.cs(12,5): error': ('Jos', 'repos', 'Program'),
            'share \\\\invented-fs\\Users$\\someone\\Documents\\notes.txt here': ('invented-fs', 'Users', 'someone'),
            'open Saffron+Payroll\\src\\ledger.cs today': ('Saffron', 'Payroll', 'ledger'),
            'as INVENTED\\elara.brightwater now': ('elara', 'brightwater', 'ter'),
            'as INVENTED\\elara.silva-jones now': ('elara', 'silva', 'jones'),
            'as INVENTED\\elara.van_der_merwe now': ('elara', 'merwe'),
            'tag #Team\\x.cs; @Owner\\y.py, Name;Dept\\z.ts': ('Team', 'Owner', 'Name', 'Dept'),
            # Gemini round 2: unreadable segments after a dotted folder, and
            # '@' / '+' inside a drive path.
            'tmp at C:\\Users\\alex.smith\\Jos\u00e9\\secret.cs\nnext': ('alex', 'smith', 'Jos', 'secret'),
            'share \\\\invented-fs\\dept.eng\\Users$\\notes.txt here': ('invented', 'dept', 'Users', 'notes'),
            'built C:\\Users\\invented_user\\node_modules\\@scope\\pkg\\index.js(12,5): error': ('invented', 'scope', 'index'),
            'built C:\\Users\\invented_user\\repos\\a+b\\app\\main.cpp(12,5): error': ('invented', 'repos', 'main'),
            ('word ' * 60) + 'DOMAIN\\alex.smith': ('alex', 'smith', 'DOMAIN'),
            ('word ' * 60) + 'src\\utils\\helpers.cs': ('utils', 'helpers'),
            # Sol round 3: a space inside a share name, and letters the old
            # case-insensitive pattern matched outside ASCII.
            'open \\\\invented-fs\\Saffron+ Payroll\\src\\ledger.cs today': ('invented', 'Saffron', 'Payroll', 'ledger'),
            'see Users\\Elara Invented\\notes.txt here': ('Users', 'Elara', 'Invented', 'notes'),
            'as DOMAIN\\Elara.\u0130nvented now': ('DOMAIN', 'Elara', '\u0130nvented'),
            'as DOMAIN\\\u017fara.\u212aelvin now': ('DOMAIN', '\u017fara', '\u212aelvin'),
            # Opus round 3: punctuation that ends a run, then a space, inside a
            # folder name; and a surname with spaces after the last dot.
            'copy \\\\invented-fs\\home\\Brightwater, Elara\\Documents\\cv.docx now': ('invented', 'Brightwater', 'Elara'),
            'open Clients\\Invented Co, Ltd\\Contracts\\msa.pdf': ('Clients', 'Invented', 'Ltd', 'msa'),
            'see \\\\invented-fs\\Sales & Marketing\\q3.xlsx': ('invented', 'Sales', 'Marketing'),
            'path Users\\Jos\u00e9 Inventado\\cv.docx': ('Users', 'Jos', 'Inventado'),
            'logged in as CORP\\elara.van der merwe today': ('CORP', 'elara', 'der', 'merwe'),
            '\\\\fs\\a.b\\Sales & Marketing Plan.docx': ('Sales', 'Marketing', 'Plan'),
            'signed in as CORP\\\u0130lker.Inventado today': ('CORP', 'lker', 'Inventado'),
            # Gemini round 3: a widened match reaching into the next one, and a
            # run that starts with a backslash after '$'.
            'tmp at C:\\Users\\alex.smith\\INVENT~1\\My Temp.tmp\nnext': ('alex', 'INVENT', 'Temp'),
            'tmp at C:\\Users\\alex.smith\\Saffron+Payroll\\My Ledger.cs\nnext': ('alex', 'Saffron', 'Ledger'),
            'share \\\\invented-fs\\dept.eng\\Users$\\My Notes.txt here': ('invented', 'Users', 'Notes'),
            'share \\\\invented-fs\\dept.eng\\My Share\\Users$\\notes.txt here': ('invented', 'Share', 'notes'),
            'tmp at C:\\Users\\alex.smith\\My Documents\\Jos\u00e9\\secret.cs\nnext': ('alex', 'Documents', 'Jos', 'secret'),
        }
        for text, fragments in cases.items():
            with self.subTest(text=text):
                out = self.assert_redacted(text)
                for fragment in fragments:
                    self.assertNotIn(fragment, out)

    def test_separator_before_a_path_is_a_boundary(self):
        for text in ('\u2502   src\\util\\helpers.cs', 'Docs \u203a guide\\intro.md', '+src\\app\\main.cs',
                     '#lib\\core\\types.ts', '[1]src\\x\\y.py'):
            with self.subTest(text=text):
                self.assert_redacted(text)

    def test_alias_with_a_space_is_not_split_by_path_rules(self):
        out = self.sanitizer.text('Example Holdings\\docs\\plan.md is ready')
        self.assertNotIn('Example', out)
        self.assertNotIn('Holdings', out)

    def test_key_with_spaces_does_not_rebuild_a_path(self):
        clean = self.sanitizer.payload({'src/My Folder/file.cs': 1})
        for key in clean:
            self.assertIsNone(RELATIVE_FILE_PATTERN.search(key), key)
            self.assertNotIn('Folder', key)

    def test_detection_covers_everything_the_old_pattern_matched(self):
        import random
        from sanitise import residual_path_present
        alphabet = list('ab.\\ _-()/:~$+\u00e9\u0130\u0131\u017f\u212aZ9\n')
        generator = random.Random(7)
        for _ in range(20000):
            text = ''.join(generator.choice(alphabet) for _ in range(generator.randint(1, 14)))
            if RESIDUAL_WINDOWS_PATH_PATTERN.search(text):
                self.assertTrue(residual_path_present(text), repr(text))

    def test_replaced_line_leaves_no_stale_file_metadata(self):
        from sanitise import canonical
        for text in ('open C:\\Users\\elara.smith, Invented\\Documents\\notes.txt',
                     'open C:\\Users\\elara.smith, Invented\\Documents\\notes.txt\rnext'):
            with self.subTest(text=text):
                out = canonical(self.sanitizer.payload({'text': text, 'nested': {text: [text]}}))
                for fragment in ('smith', 'elara', 'Invented', 'notes'):
                    self.assertNotIn(fragment, out)

    def test_folder_surname_is_never_an_extension(self):
        from sanitise import canonical
        out = canonical(self.sanitizer.payload({'path': 'C:\\Users\\elara.smith', 'file': '/home/x/elara.brightwater',
                                                'text': 'read /srv/app/main.py'}))
        for fragment in ('smith', 'brightwater', 'elara'):
            self.assertNotIn(fragment, out)
        self.assertIn('"extension":"py"', out)

    def test_same_person_on_another_line_without_an_extension(self):
        # Opus round 4: once a string holds a residual path, other backslash
        # lines in it go too; a share prefix and a forward-slash drive path
        # are paths without an extension.
        from sanitise import canonical
        cases = {
            'copied \\\\invented-fs\\home\\Elara Brightwater\nthen \\\\invented-fs\\home\\Elara Brightwater\\cv.docx': ('Elara', 'invented'),
            'logged in as CORP\\elara\nprofile CORP\\elara.brightwater': ('elara', 'CORP'),
            '    Directory: C:\\Users\\Elara Inventado\\source\\repos\nedit src\\app\\main.cs': ('Elara', 'Inventado', 'repos'),
            'at C:/Users/elara.inventado/proj/app.js:10': ('elara', 'inventado', 'proj'),
            'see \\\\invented-fs\\Elara Brightwater now': ('Elara', 'invented'),
            'PS C:\\Users\\elara.inventa> type src\\app\\main.cs': ('elara', 'inventa'),
            'open "./home\\elara.inventa" then x\\y.txt': ('elara', 'inventa'),
        }
        for text, fragments in cases.items():
            with self.subTest(text=text):
                out = canonical(self.sanitizer.payload({'text': text}))
                for fragment in fragments:
                    self.assertNotIn(fragment, out)

    def test_long_run_does_not_cut_a_path_address_or_alias_from_its_line(self):
        # Sol round 5: collapsing only the long run left the person's name,
        # an address local part or an alias surname on the same line.
        from sanitise import canonical
        cases = {
            'open Users\\Nerina Frostwillow\\' + 'a.' * 64 + 'log': ('Nerina', 'Frostwillow', 'Users'),
            'mail elara.brightwater@' + 'a.' * 70 + 'com now': ('elara', 'brightwater'),
            'a.' * 64 + 'Example Holdings ok': ('Example', 'Holdings'),
        }
        for text, fragments in cases.items():
            with self.subTest(text=text[:40]):
                for payload in ({'text': text}, {text: 1}, {'nested': [{'value': text}]}):
                    out = canonical(self.sanitizer.payload(payload))
                    for fragment in fragments:
                        self.assertNotIn(fragment, out)

    def test_sibling_line_survives_no_earlier_substitution(self):
        # Sol round 5: the drive-path rule removed the only path before the
        # sibling-line rule ran.
        from sanitise import canonical
        for newline in ('\n', '\r', '\r\n'):
            with self.subTest(newline=repr(newline)):
                text = 'Directory: Users\\Nerina Frostwillow' + newline + 'open C:\\src\\main.cs' + newline + 'next'
                out = canonical(self.sanitizer.payload({'text': text}))
                self.assertNotIn('Nerina', out)
                self.assertNotIn('Frostwillow', out)

    def test_full_payload_paths_are_linear(self):
        def run(count):
            text = ' '.join('see /srv/p%d/f%d.py' % (index, index) for index in range(count))
            started = time.perf_counter()
            self.sanitizer.payload({'text': text, 'dotted': 'a.' * count})
            return time.perf_counter() - started
        small, large = run(4000), run(16000)
        self.assertLess(large, small * 8 + 0.5)

    def test_drive_path_trigger_survives_its_own_substitution(self):
        # Opus round 5: a drive path ending a line was consumed by the Windows
        # rule, so the sibling line kept an extension-less identity; and drive
        # paths the Windows rule rejects were emitted verbatim.
        from sanitise import canonical
        cases = {
            'Opened C:\\Users\\elara\\Documents\\notes.txt\nwhoami: CORP\\elara': ('elara', 'CORP'),
            'Saved D:\\exports\\q3.xlsx\nOwner: INVENTED\\Elara Brightwater': ('Elara', 'INVENTED'),
            'C:\\Users\\Elara Brightwater: Access is denied.': ('Elara', 'Brightwater'),
            'Get-ChildItem C:\\Users\\Elara Brightwater\\Documents | Measure-Object': ('Elara', 'Brightwater'),
            'saved to Users\\Elara Brightwater\\' + 'Q' * 70 + '-' + 'z' * 70 + '.pdf now': ('Elara', 'Users'),
            'wrote elara.brightwater/' + 'Q' * 70 + '-' + 'z' * 70 + '.csv': ('elara', 'brightwater'),
        }
        for text, fragments in cases.items():
            with self.subTest(text=text[:50]):
                out = canonical(self.sanitizer.payload({'text': text}))
                for fragment in fragments:
                    self.assertNotIn(fragment, out)

    def test_slash_chains_and_many_original_values_are_linear(self):
        def run(count):
            started = time.perf_counter()
            self.sanitizer.payload({'chain': '-a/' * count,
                                    'hex': ' '.join('%032x' % (index * 7919 + 10 ** 30) for index in range(count // 40))})
            return time.perf_counter() - started
        small, large = run(4000), run(16000)
        self.assertLess(large, small * 8 + 0.5)

    def test_original_value_check_holds_beyond_its_budget(self):
        from unittest import mock
        import sanitise
        token = '%032x' % (10 ** 30 + 7)
        with mock.patch.object(sanitise, 'ORIGINAL_VALUE_CHECK_BUDGET', 0):
            with self.assertRaises(HoldError) as context:
                self.sanitizer.assert_clean({'text': 'hash ' + token}, {'text': 'clean output'})
        self.assertEqual(context.exception.reason, 'final_leak_check_budget')

    def test_value_without_word_boundaries_is_still_found(self):
        # Sol round 6: 'Q<value>Q' no longer matches the hex pattern, so only a
        # substring search finds it.
        token = 'a' * 32
        with self.assertRaises(HoldError) as context:
            self.sanitizer.assert_clean({'password': token, 'n': ['%032x' % (10 ** 30 + i) for i in range(2000)]},
                                        {'text': 'Q' + token + 'Q' + ': ' * 2500})
        self.assertEqual(context.exception.reason, 'final_leak_check_original_value')

    def test_name_cut_from_a_drive_path_line_does_not_survive(self):
        # Sol round 6: the drive rule consumed 'C:\Users\Frostwillow' and left
        # ', Nerina' on a line that no longer held a backslash.
        from sanitise import canonical
        text = 'Directory: C:\\Users\\Frostwillow, Nerina\nopen src\\app\\main.cs'
        for payload in ({'text': text}, {'nested': [{'v': text}]}, {text: 1}):
            with self.subTest(payload=type(next(iter(payload.values()))).__name__):
                out = canonical(self.sanitizer.payload(payload))
                self.assertNotIn('Nerina', out)
                self.assertNotIn('Frostwillow', out)

    def test_long_dotted_runs_are_linear(self):
        started = time.perf_counter()
        self.sanitizer.text('a.' * 256000)
        self.sanitizer.text('x a.b@c q\\w.e\n' * 50000)
        self.assertLess(time.perf_counter() - started, 3.0)

    def test_only_the_line_holding_the_path_is_replaced(self):
        out = self.sanitizer.text('first line stays\nbuild at src\\app\\main.cs failed\r\nlast line stays')
        self.assertTrue(out.startswith('first line stays\n'), out)
        self.assertTrue(out.endswith('\r\nlast line stays'), out)
        self.assertNotIn('main', out)

    def test_many_lines_with_paths_are_linear(self):
        started = time.perf_counter()
        self.sanitizer.text('a~\\b.c x\n' * 100000)
        self.assertLess(time.perf_counter() - started, 4.0)

    def test_many_backslash_components_are_linear(self):
        from sanitise import residual_path_present
        started = time.perf_counter()
        self.assertFalse(residual_path_present(('a\\' * 200000) + 'z'))
        self.sanitizer.text(('a\\' * 32000) + 'z')
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_long_hex_run_with_a_backslash_is_linear(self):
        started = time.perf_counter()
        self.sanitizer.text('x\\y ' + 'a1b2c3d4' * 128000)
        self.assertLess(time.perf_counter() - started, 1.0)

    def test_identity_shaped_backslash_pair_is_redacted(self):
        # Domain\user.name is not a file, but it is identifying; redacting it is
        # the conservative outcome and keeps the final check clean.
        self.assert_redacted(r'auth failed for DOMAIN\alex.smit')


if __name__ == '__main__':
    unittest.main()
