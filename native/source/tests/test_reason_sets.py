"""The export reader must know every reason the server can put in an event payload."""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import research
import research_reader


class ReasonSetTests(unittest.TestCase):
    def test_server_and_reader_exclusion_reasons_match(self):
        self.assertEqual(research.EXCLUSION_REASONS, research_reader.EXCLUSION_REASONS)


if __name__ == '__main__':
    unittest.main()
