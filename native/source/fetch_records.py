#!/usr/bin/env python3
"""Collect Enterprise records directly into the independent traces ClickHouse database."""
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent/'api'))
import archive
import collection

if __name__ == '__main__':
    archive.initialise()
    collection.fetch_records()
