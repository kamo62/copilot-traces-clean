#!/usr/bin/env python3
"""Serial, bounded research derivation worker.

It never blocks ingestion and never publishes. Publication requires a separate
admin acknowledgement and an explicitly evaluated release setting.
"""
import os
import time

import research


def main():
    interval = max(5, int(os.environ.get('COPILOT_RESEARCH_WORKER_INTERVAL_SECONDS', '30')))
    once = os.environ.get('COPILOT_RESEARCH_WORKER_ONCE', 'false').lower() == 'true'
    research.initialise()
    while True:
        try:
            result = research.process_once(page_size=int(os.environ.get('COPILOT_RESEARCH_PAGE_SIZE', '10')))
            # Status classes only; no record IDs, paths, prompts or provider responses.
            print('research worker: ' + ', '.join(str(result.get(key)) for key in ('status', 'revision_id', 'records', 'reason')
                  if result.get(key) is not None), flush=True)
            wait = interval if result.get('status') in ('processed', 'idle') else max(interval, 60)
        except Exception as failure:
            print('research worker: error ' + type(failure).__name__ + '; retained checkpoint and rows', flush=True)
            wait = max(interval, 60)
        if once:
            return
        time.sleep(wait)


if __name__ == '__main__':
    main()
