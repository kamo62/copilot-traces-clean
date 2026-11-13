#!/usr/bin/env python3
"""Offline comparison of an observed sequence with an independently captured expected sequence.

Inputs are exactly two operator-selected files. Nothing is discovered, fetched or written:

* expected: a small versioned reference contract (conversation-coverage-reference/1) holding the messages, tool
  calls and tool results of a controlled task, captured independently of the system under test. No live client
  format is established by this repository, so there are no client adapters; a live comparison still needs an
  authorised capture converted into this contract by the operator.
* observed: either raw Enterprise usage records (source capture, compared exactly) or a research-event/2 JSONL
  export (sanitised fidelity, compared structurally only). The two are different claims and are never merged.

Finish markers, tool success and assistant-reported outcomes are never used to decide that a session is complete.
The report excludes content bodies (positions, kinds, link states and SHA-256 digests only) but stays a restricted
artefact: labels, digests and positions can identify a session, so it is not research-safe or anonymous.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'native' / 'source' / 'api'))
sys.path.insert(0, str(ROOT / 'native' / 'source'))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import parsing  # noqa: E402
import research_reader  # noqa: E402
from import_records import records_from_bytes  # noqa: E402
from sanitise import Policy, RefFactory  # noqa: E402

CONTRACT = 'conversation-coverage-reference/1'
REPORT_VERSION = 'conversation-coverage-report/1'
CAPTURE_SOURCES = ('invented_reference', 'operator_asserted_capture')
OBSERVED_FORMATS = ('source-records', 'research-export')
MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_ITEMS = 2000
LABEL = re.compile(r'^[A-Za-z0-9 ._:/-]{1,80}$')
AGENT_HISTORY_PARTS = {'.claude', '.codex', '.copilot', 'github-copilot'}
COMPARABLE = ('message', 'tool_call', 'tool_result')
REPORT_HANDLING = ('restricted: content bodies are excluded, but task/client labels, input and event digests and '
                   'positions can still identify a session; not research-safe or anonymous')
LIMITS = (
    'Compares one operator-selected capture; no local agent history or server data is discovered or read.',
    'A match is evidence for this capture, client, version and task only; it is not proof of any other session.',
    'Finish/DONE markers, tool success and assistant-reported outcomes are not used to infer completeness.',
    'Live client comparison still requires an authorised capture converted into the reference contract.',
)


class InputError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def read_input(path):
    """One explicitly named regular file. Refuses symlinks and the known local agent-history directories."""
    candidate = Path(path)
    if candidate.is_symlink():
        raise InputError('Input must not be a symbolic link')
    resolved = candidate.resolve()
    if AGENT_HISTORY_PARTS & set(resolved.parts):
        raise InputError('Refusing a path inside a local agent-history directory; export an explicit reference copy elsewhere')
    if not resolved.is_file():
        raise InputError('Input must be an existing regular file')
    if resolved.stat().st_size > MAX_INPUT_BYTES:
        raise InputError('Input is larger than the 16 MiB bound')
    raw = resolved.read_bytes()
    return resolved, raw, hashlib.sha256(raw).hexdigest()


def load_expected(raw):
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError):
        raise InputError('Reference is not valid JSON') from None
    if not isinstance(data, dict) or set(data) != {'contract', 'capture', 'items'} or data['contract'] != CONTRACT:
        raise InputError('Reference must declare contract ' + CONTRACT)
    capture = data['capture']
    if (not isinstance(capture, dict) or set(capture) != {'source', 'client', 'client_version', 'task'} or
            capture['source'] not in CAPTURE_SOURCES or
            any(not isinstance(capture[key], str) or not LABEL.fullmatch(capture[key]) for key in ('client', 'client_version', 'task'))):
        raise InputError('Invalid capture description')
    items = data['items']
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise InputError('Reference needs 1 to ' + str(MAX_ITEMS) + ' items')
    expected, calls = [], {}
    for index, item in enumerate(items):
        kind = item.get('kind') if isinstance(item, dict) else None
        shape = {'message': {'kind', 'role', 'text'}, 'tool_call': {'kind', 'call_id', 'name', 'arguments'},
                 'tool_result': {'kind', 'call_id', 'content'}}.get(kind)
        if shape is None or set(item) != shape:
            raise InputError('Invalid reference item ' + str(index))
        if kind == 'message':
            if item['role'] not in ('user', 'assistant') or not isinstance(item['text'], str):
                raise InputError('Invalid reference message ' + str(index))
        else:
            if not isinstance(item['call_id'], str) or not item['call_id']:
                raise InputError('Invalid call_id ' + str(index))
            if kind == 'tool_call':
                if item['call_id'] in calls or not isinstance(item['name'], str) or not item['name'] or not isinstance(item['arguments'], dict):
                    raise InputError('Invalid or repeated tool call ' + str(index))
                calls[item['call_id']] = index
            elif item['call_id'] not in calls:
                raise InputError('Tool result ' + str(index) + ' has no earlier call in the reference')
        expected.append({'kind': kind, 'role': item.get('role'), 'text': item.get('text'), 'name': item.get('name'),
                         'args': item.get('arguments'), 'content': item.get('content'),
                         'call_id': item.get('call_id'), 'parent': calls.get(item.get('call_id')) if kind == 'tool_result' else None})
    return capture, expected


def _event_item(event, record_index):
    kind, payload = event['kind'], event.get('payload') or {}
    if kind == 'message' and event.get('role') in ('user', 'assistant'):
        item = {'kind': 'message', 'role': event['role'], 'text': payload.get('text')}
    elif kind == 'tool_call':
        args = payload.get('arguments') if payload.get('parse_status') == 'parsed' else payload.get('arguments_text')
        item = {'kind': 'tool_call', 'name': payload.get('name'), 'args': args}
    elif kind == 'tool_result':
        item = {'kind': 'tool_result', 'content': payload.get('content')}
    else:
        return None
    item.update(record=record_index, call_key=event.get('call_ref'), origin=event.get('origin'))
    return item


def load_source_records(raw):
    """Raw Enterprise records, in the order the operator supplied them. Unsanitised; exact comparison."""
    try:
        records = records_from_bytes(raw)
    except (ValueError, UnicodeError):
        raise InputError('Observed file is not a valid Enterprise record array') from None
    refs = RefFactory(Policy({'policy_version': 'coverage-tool', 'scope': 'coverage-tool'}, os.urandom(32)))
    items, ignored, unsupported, markers = [], {}, 0, 0
    for record_index, record in enumerate(records):
        parsed = parsing.derive_events(record, refs)
        local = {}
        for event in parsed['events']:
            item = _event_item(event, record_index)
            if item is None:
                if event['kind'] in ('withheld', 'unsupported', 'parse_error'):
                    unsupported += 1
                elif event['kind'] == 'completion' or (event['kind'] == 'response_meta' and
                        (event.get('payload') or {}).get('end_marker_observed')):
                    markers += 1
                else:
                    ignored[event['kind']] = ignored.get(event['kind'], 0) + 1
                continue
            parent = event.get('parent_event_local')
            item['parent'] = local.get(parent) if parent is not None else None
            local[event['event_index']] = len(items)
            items.append(item)
    return items, {'events_not_compared': ignored, 'unsupported_or_withheld_events': unsupported,
                   'end_markers_observed_not_used': markers, 'records': len(records)}, refs


def load_research_export(path):
    """Validated research-event JSONL (optionally .gz). Sanitised text cannot be compared; structure only."""
    items, ignored, unsupported, markers, by_event, previous = [], {}, 0, 0, {}, None
    for event in research_reader.iter_events(path):
        ordering = (event['observed_sequence'], event['event_id'])
        if previous is not None and ordering <= previous:
            raise InputError('Export is not in deterministic observed order')
        previous = ordering
        item = _event_item(event, 0)
        if item is None:
            if event['kind'] in ('withheld', 'unsupported', 'parse_error'):
                unsupported += 1
            elif event['kind'] == 'completion':
                markers += 1
            else:
                ignored[event['kind']] = ignored.get(event['kind'], 0) + 1
            continue
        item.update(event_id=event['event_id'], call_key=None)
        parent = event.get('parent_event_id')
        item['parent'] = by_event.get(parent) if parent else None
        by_event[event['event_id']] = len(items)
        items.append(item)
    return items, {'events_not_compared': ignored, 'unsupported_or_withheld_events': unsupported,
                   'end_markers_observed_not_used': markers}


def base_key(item, exact):
    kind = item['kind']
    if kind == 'message':
        return ('message', item['role'], canonical(item['text'])) if exact else ('message', item['role'])
    if kind == 'tool_call':
        args = item['args']
        return (('tool_call', item['name'], canonical(args)) if exact else
                ('tool_call', item['name'], tuple(sorted(args)) if isinstance(args, dict) else type(args).__name__))
    return ('tool_result', canonical(item['content'])) if exact else ('tool_result',)


def evidence_digest(item, exact):
    return digest(base_key(item, True)) if exact else None


def identity_state(expected, observed, expected_keys):
    """Explicit call identity: 'explicit' when equal, 'unknown' when the source carries none, False when it differs."""
    if expected_keys is None:
        return 'not_comparable'
    wanted = expected_keys[expected['call_id']]
    if observed.get('call_key') is None:
        return 'unknown'
    return 'explicit' if observed['call_key'] == wanted else False


def compare(expected, observed, exact, refs=None):
    expected_keys = None
    if exact:
        expected_keys = {item['call_id']: refs.opaque('call', item['call_id']) for item in expected if item['call_id']}
    index = {}
    for position, item in enumerate(observed):
        index.setdefault(base_key(item, exact), []).append(position)
    used, matched, rows, cursor = set(), {}, [], 0

    def find(item, start, stop):
        positions = index.get(base_key(item, exact), [])
        for place in positions[bisect.bisect_left(positions, start):]:
            if place >= stop:
                return None
            if place in used:
                continue
            state = identity_state(item, observed[place], expected_keys) if item['kind'] != 'message' else 'not_applicable'
            if state is not False:
                return place, state
        return None

    for number, item in enumerate(expected):
        found = find(item, cursor, len(observed))
        status = 'matched'
        if found:
            cursor = found[0] + 1
        else:
            found = find(item, 0, cursor)
            status = 'out_of_order' if found else 'missing'
        row = {'expected_index': number, 'kind': item['kind'], 'status': status, 'observed_index': None,
               'identity': None, 'link': None, 'expected_sha256': evidence_digest(item, exact), 'observed_sha256': None}
        if found:
            used.add(found[0])
            matched[number] = found[0]
            row.update(observed_index=found[0], identity=found[1],
                       observed_sha256=evidence_digest(observed[found[0]], exact))
            for key in ('event_id', 'record'):
                if key in observed[found[0]] and (exact or key == 'event_id'):
                    row['observed_' + key] = observed[found[0]][key]
        rows.append(row)
    for number, item in enumerate(expected):
        if item['kind'] != 'tool_result':
            continue
        row = rows[number]
        if row['observed_index'] is None:
            row['link'] = 'result_unmatched'
        elif item['parent'] not in matched:
            row['link'] = 'call_unmatched'
        else:
            parent, call_place = observed[row['observed_index']].get('parent'), matched[item['parent']]
            # Enterprise history repeats earlier calls, so the parent may be a repeated copy of the matched call.
            # In exact mode that copy must carry the same explicit call identity; export mode is structural only.
            same_call = parent is not None and (parent == call_place or (
                base_key(observed[parent], exact) == base_key(observed[call_place], exact) and
                observed[parent].get('call_key') == observed[call_place].get('call_key')))
            row['link'] = 'unknown_link' if parent is None else 'linked' if same_call else 'link_mismatch'
    matched_places = sorted(matched.values())
    first, last = (matched_places[0], matched_places[-1]) if matched_places else (None, None)
    matched_identities = {}
    for place in matched_places:
        matched_identities.setdefault(base_key(observed[place], exact), set()).add(observed[place].get('call_key'))
    extras = []
    for place, item in enumerate(observed):
        if place in used:
            continue
        # Structural keys cannot tell repeated history from genuinely extra items, so they are not classified.
        # Exact mode: a repeated tool call/result needs the same content AND the same explicit call identity;
        # an unknown identity or a different ID is never a duplicate. A message equal to a matched one is repeated
        # history only by source provenance (it was replayed as history); an equal output message is ambiguous.
        identities = matched_identities.get(base_key(item, exact))
        if not exact:
            classification = 'unclassified_structural'
        elif identities is None:
            classification = 'extra'
        elif item['kind'] == 'message':
            classification = 'repeated_exact_duplicate' if item.get('origin') == 'history' else 'unassessable_repeated_content'
        elif item.get('call_key') is None:
            classification = 'unassessable_unknown_identity'
        else:
            classification = 'repeated_exact_duplicate' if item['call_key'] in identities else 'extra'
        extras.append({'observed_index': place, 'kind': item['kind'], 'classification': classification,
                       'position': ('no_match_anchor' if first is None else 'before_first_match' if place < first
                                    else 'after_last_match' if place > last else 'between_matches')})
    return rows, extras, first, last


def report(expected_path, observed_path, observed_format):
    expected_file, expected_raw, expected_hash = read_input(expected_path)
    observed_file, observed_raw, observed_hash = read_input(observed_path)
    capture, expected = load_expected(expected_raw)
    exact = observed_format == 'source-records'
    if exact:
        observed, notes, refs = load_source_records(observed_raw)
    else:
        observed, notes = load_research_export(observed_file)
        refs = None
    rows, extras, first, last = compare(expected, observed, exact, refs)
    counts = {status: sum(1 for row in rows if row['status'] == status) for status in ('matched', 'out_of_order', 'missing')}
    links = {state: sum(1 for row in rows if row['link'] == state) for state in
             ('linked', 'unknown_link', 'link_mismatch', 'call_unmatched', 'result_unmatched')}
    counts.update(links)
    counts['extra_observed'] = sum(1 for extra in extras if extra['classification'] == 'extra')
    counts['repeated_exact_duplicates'] = sum(1 for extra in extras if extra['classification'] == 'repeated_exact_duplicate')
    counts['unclassified_structural'] = sum(1 for extra in extras if extra['classification'] == 'unclassified_structural')
    counts['unassessable_observed'] = sum(1 for extra in extras if extra['classification'].startswith('unassessable_'))
    counts['withheld_or_unsupported_observed'] = notes['unsupported_or_withheld_events']
    gaps = counts['out_of_order'] + counts['missing'] + sum(links[state] for state in
           ('unknown_link', 'link_mismatch', 'call_unmatched', 'result_unmatched'))
    if not observed:
        result = 'not_comparable'
    elif gaps:
        result = 'gaps_found'
    else:
        result = 'no_gaps_found_with_extra_observed' if counts['extra_observed'] else 'no_gaps_found'
    # `result` is the comparison of the supported events. The overall verdict is limited when observed events were
    # withheld/unsupported (they may hide reference items or extras) or could not be assessed; the exact result stays.
    verdict_limits = [name for name, present in (
        ('withheld_or_unsupported_observed_events', counts['withheld_or_unsupported_observed']),
        ('unassessable_observed_items', counts['unassessable_observed'])) if present]
    overall = 'coverage_limited' if verdict_limits and result.startswith('no_gaps_found') else result
    synthetic = capture['source'] == 'invented_reference'
    return {
        'report_version': REPORT_VERSION, 'contract': CONTRACT, 'result': result,
        'overall_verdict': overall, 'verdict_limits': verdict_limits,
        'report_handling': REPORT_HANDLING,
        'evidence_class': 'synthetic_reference' if synthetic else 'operator_asserted_capture_unverified',
        'live_client_comparison': 'not_applicable_synthetic' if synthetic else 'operator_asserted_not_verified_by_tool',
        'observed_kind': 'source_records' if exact else 'sanitised_research_export',
        'comparison_strength': 'exact_content' if exact else 'structural_only',
        'extra_items_assessable': exact,
        'inputs': {'expected': {'sha256': expected_hash, 'bytes': len(expected_raw), 'items': len(expected), 'capture': capture},
                   'observed': {'sha256': observed_hash, 'bytes': len(observed_raw), 'comparable_items': len(observed), **notes}},
        'counts': counts, 'items': rows, 'unmatched_observed': extras,
        'boundaries': {'first_expected_matched': bool(rows and rows[0]['status'] == 'matched'),
                       'last_expected_matched': bool(rows and rows[-1]['status'] == 'matched'),
                       'observed_before_first_match': 0 if first is None else first,
                       'observed_after_last_match': 0 if last is None else len(observed) - last - 1,
                       'session_boundaries_inferred': False},
        'unsupported_may_hide_missing_items': bool(notes['unsupported_or_withheld_events'] and counts['missing']),
        'limits': list(LIMITS),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Compare an observed sequence with an independent reference capture.')
    parser.add_argument('--expected', required=True, help='reference contract JSON (conversation-coverage-reference/1)')
    parser.add_argument('--observed', required=True, help='Enterprise record array or research-event/2 JSONL(.gz)')
    parser.add_argument('--observed-format', required=True, choices=OBSERVED_FORMATS)
    arguments = parser.parse_args(argv)
    try:
        result = report(arguments.expected, arguments.observed, arguments.observed_format)
    except (InputError, ValueError) as failure:
        print(json.dumps({'error': 'invalid_input', 'detail': str(failure)[:200]}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['overall_verdict'].startswith('no_gaps_found') else 1


if __name__ == '__main__':
    sys.exit(main())
