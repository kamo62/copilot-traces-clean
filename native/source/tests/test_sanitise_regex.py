"""Regression checks for the path redaction patterns used on untrusted log text."""
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))

from sanitise import WINDOWS_PATH_PATTERN


class WindowsPathPatternTests(unittest.TestCase):
    def test_long_backslash_run_does_not_backtrack(self):
        # An unclosed Windows path followed by a non-terminator previously took
        # >30s on a 387 KB record; 5,000 characters must stay effectively instant.
        text = 'C:\\' + 'a' * 5000 + ':b'
        started = time.time()
        WINDOWS_PATH_PATTERN.sub('X', text)
        self.assertLess(time.time() - started, 1.0)

    def test_long_backslash_run_without_terminator(self):
        text = 'C:\\' + 'a' * 5000
        started = time.time()
        WINDOWS_PATH_PATTERN.sub('X', text)
        self.assertLess(time.time() - started, 1.0)

    def test_ordinary_paths_still_match(self):
        cases = {
            r'C:\Users\alex\repos\app\src\Quote.cs:42': r'C:\Users\alex\repos\app\src\Quote.cs',
            r'C:\Program Files\App\file.txt': r'C:\Program Files\App\file.txt',
            r'see C:\temp\x.txt, then stop': r'C:\temp\x.txt',
            r'C:\path with (parens)\file.cs': r'C:\path with (parens)\file.cs',
        }
        for text, expected in cases.items():
            match = WINDOWS_PATH_PATTERN.search(text)
            self.assertIsNotNone(match, text)
            self.assertEqual(match.group('path'), expected)


if __name__ == '__main__':
    unittest.main()
