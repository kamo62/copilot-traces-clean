#!/usr/bin/env python3
"""Restricted offline privacy/utility evaluation of the existing sanitiser against explicitly labelled cases.

Inputs are operator-selected files only: a labelled cases file (privacy-eval-cases/1) and the disclosure policy.
The tool runs the existing deterministic sanitiser (no detector, no model, no network, nothing written) and reports
denominators, misses, over-removal, intentional holds (a wrong-reason hold counts against max_missed_holds),
argument-type preservation and errors. Labelled values and sanitised output are never printed, but the report stays
restricted: case IDs, labels and counts can identify the input, so it is not research-safe or anonymous.

It does not certify anonymity, approve a release or change any release setting. Thresholds are optional, explicit
and carry an operator-declared approval state that this tool cannot verify. Labelled held-out data derived from
employee content must stay restricted: such a cases file must carry provenance restricted_labelled_heldout, split
held_out and live outside this repository or under its ignored `private/` directory.
"""
import argparse
import copy
import json
import math
import os
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / 'native' / 'source' / 'api'))

from sanitise import HoldError, Policy, PolicyError, Sanitizer  # noqa: E402

CONTRACT = 'privacy-eval-cases/1'
REPORT_VERSION = 'privacy-eval-report/1'
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_CASES = 5000
LABEL = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
CATEGORY = re.compile(r'^[a-z_]{1,32}$')
JSON_TYPES = ('string', 'integer', 'number', 'boolean', 'array', 'object', 'null')
PROVENANCE = ('invented_synthetic', 'restricted_labelled_heldout')
THRESHOLD_STATES = ('proposed', 'operator_approved')
THRESHOLD_FIELDS = {'min_removal_rate': float, 'min_preservation_rate': float, 'max_unexpected_holds': int,
                    'max_missed_holds': int, 'max_type_changes': int, 'max_errors': int}
DISCLAIMERS = {
    'anonymity_guarantee': False, 'release_gate_changed': False, 'automatic_release': False,
    'detector_called': False, 'model_called': False, 'content_in_report': False,
    'report_handling': ('restricted: labelled values and output are excluded, but case IDs, dataset/policy labels and '
                        'counts can still identify the input; not research-safe or anonymous'),
    'real_world_privacy_benchmark': 'pending: this report covers only the labelled cases supplied',
}


class InputError(ValueError):
    pass


def read_json(path, name):
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise InputError(name + ' must be a regular file')
    if candidate.stat().st_size > MAX_INPUT_BYTES:
        raise InputError(name + ' is larger than the 8 MiB bound')
    try:
        def reject_constant(name):
            raise ValueError(name)  # NaN/Infinity are not JSON
        return json.loads(candidate.read_text(encoding='utf-8'), parse_constant=reject_constant), candidate.resolve()
    except (ValueError, UnicodeError):
        raise InputError(name + ' is not valid UTF-8 JSON') from None


def load_policy(path, key_path):
    data, _ = read_json(path, 'Policy')
    try:
        if key_path:
            return Policy.load(path, key_path)
        return Policy(data, os.urandom(32))  # Ephemeral key: references differ per run; detection checks do not need stability.
    except PolicyError as failure:
        raise InputError(str(failure)) from None


def _items(case, name, with_type=False):
    values = case.get(name, [])
    if not isinstance(values, list):
        raise InputError('Case ' + case['id'] + ': ' + name + ' must be a list')
    for item in values:
        if with_type:
            valid = (isinstance(item, dict) and set(item) == {'path', 'type'} and isinstance(item['path'], list) and item['path']
                     and all(isinstance(part, (str, int)) and not isinstance(part, bool) for part in item['path'])
                     and item['type'] in JSON_TYPES)
        else:
            valid = (isinstance(item, dict) and set(item) == {'value', 'category'} and isinstance(item['value'], str)
                     and len(item['value']) >= 3 and isinstance(item['category'], str) and CATEGORY.fullmatch(item['category']))
        if not valid:
            raise InputError('Case ' + case['id'] + ': invalid ' + name + ' entry')
    return values


def threshold_value_ok(value, kind):
    """Rates are finite numbers in [0, 1]; count limits are non-negative integers. Booleans are never numbers."""
    if kind is int:
        return type(value) is int and value >= 0
    return type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1


def load_cases(data, cases_path):
    if (not isinstance(data, dict) or set(data) != {'contract', 'dataset', 'thresholds', 'cases'} or data['contract'] != CONTRACT):
        raise InputError('Cases file must declare contract ' + CONTRACT)
    dataset = data['dataset']
    if (not isinstance(dataset, dict) or set(dataset) != {'label', 'provenance', 'split'} or
            not isinstance(dataset['label'], str) or not LABEL.fullmatch(dataset['label']) or
            dataset['provenance'] not in PROVENANCE or dataset['split'] not in ('development', 'held_out')):
        raise InputError('Invalid dataset description')
    if dataset['provenance'] == 'restricted_labelled_heldout':
        inside = REPO_ROOT in cases_path.parents
        if dataset['split'] != 'held_out' or (inside and REPO_ROOT / 'private' not in cases_path.parents):
            raise InputError('Restricted held-out cases must be split held_out and kept outside the repository or under its ignored private/ directory')
    thresholds = data['thresholds']
    if thresholds is not None:
        if (not isinstance(thresholds, dict) or not {'version', 'state', 'approved_by'} <= set(thresholds) or
                set(thresholds) - {'version', 'state', 'approved_by'} - set(THRESHOLD_FIELDS) or
                thresholds['state'] not in THRESHOLD_STATES or not isinstance(thresholds['version'], str) or
                not LABEL.fullmatch(thresholds['version']) or
                (thresholds['state'] == 'operator_approved') != (isinstance(thresholds['approved_by'], str) and
                                                                  bool(LABEL.fullmatch(thresholds['approved_by']))) or
                any(not threshold_value_ok(thresholds[key], kind) for key, kind in THRESHOLD_FIELDS.items() if key in thresholds) or
                not any(key in thresholds for key in THRESHOLD_FIELDS)):
            raise InputError('Invalid thresholds; they need a version, a state and operator label when approved')
    cases = data['cases']
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise InputError('Supply 1 to ' + str(MAX_CASES) + ' cases')
    seen = set()
    for case in cases:
        if (not isinstance(case, dict) or not isinstance(case.get('id'), str) or not LABEL.fullmatch(case['id']) or
                case['id'] in seen or set(case) - {'id', 'payload', 'must_remove', 'must_keep', 'expect_hold', 'argument_types'} or
                not isinstance(case.get('payload'), dict) or
                not (case.get('expect_hold') is None or isinstance(case['expect_hold'], str))):
            raise InputError('Invalid or duplicate case')
        seen.add(case['id'])
        _items(case, 'must_remove'), _items(case, 'must_keep'), _items(case, 'argument_types', True)
    return dataset, thresholds, cases


def _strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
    elif isinstance(value, str):
        yield value


def json_type(value):
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    return ('integer' if isinstance(value, int) else 'number' if isinstance(value, float) else 'string' if isinstance(value, str)
            else 'array' if isinstance(value, list) else 'object')


def _at(value, path):
    for part in path:
        if isinstance(part, int) and isinstance(value, list) and 0 <= part < len(value):
            value = value[part]
        elif isinstance(part, str) and isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return False, None
    return True, value


def evaluate_case(sanitiser, case):
    result = {'id': case['id'], 'outcome': 'sanitised', 'hold_reason': None, 'removal_misses': [], 'over_removed': [],
              'type_changes': [], 'hold_expectation': None}
    expected_hold = case.get('expect_hold')
    try:
        clean = sanitiser.payload(copy.deepcopy(case['payload']))
    except HoldError as failure:
        result.update(outcome='held', hold_reason=failure.reason)
        result['hold_expectation'] = ('not_expected' if expected_hold is None else
                                      'as_expected' if failure.reason.startswith(expected_hold) else 'wrong_reason')
        return result
    except Exception as failure:  # An evaluator must report an unexpected sanitiser failure, not stop or hide it.
        result.update(outcome='error', error_class=type(failure).__name__)
        return result
    if expected_hold is not None:
        result['hold_expectation'] = 'missed'
    text = '\n'.join(_strings(clean))
    for number, item in enumerate(case.get('must_remove', [])):
        if item['value'] in text:
            result['removal_misses'].append({'index': number, 'category': item['category']})
    for number, item in enumerate(case.get('must_keep', [])):
        if item['value'] not in text:
            result['over_removed'].append({'index': number, 'category': item['category']})
    for number, item in enumerate(case.get('argument_types', [])):
        found, value = _at(clean, item['path'])
        if not found or json_type(value) != item['type']:
            result['type_changes'].append({'index': number, 'reason': 'missing_path' if not found else 'type_changed'})
    return result


def _rate(part, whole):
    return round(part / whole, 6) if whole else None


def summarise(cases, outcomes):
    categories = {'removal': {}, 'preservation': {}}
    totals = {'cases': len(cases), 'sanitised': 0, 'held': 0, 'errors': 0, 'removal_items': 0, 'removal_items_in_held_cases': 0,
              'removal_misses': 0, 'preservation_items': 0, 'preservation_items_in_held_cases': 0, 'over_removed': 0,
              'type_items': 0, 'type_items_in_held_cases': 0, 'type_changes': 0, 'holds_expected': 0, 'holds_as_expected': 0,
              'holds_missed': 0, 'holds_wrong_reason': 0, 'unexpected_holds': 0, 'items_in_error_cases': 0}
    for case, outcome in zip(cases, outcomes):
        totals['holds_expected'] += case.get('expect_hold') is not None
        counts = {'removal_items': len(case.get('must_remove', [])), 'preservation_items': len(case.get('must_keep', [])),
                  'type_items': len(case.get('argument_types', []))}
        if outcome['outcome'] == 'error':
            totals['errors'] += 1
            totals['items_in_error_cases'] += sum(counts.values())
            continue
        if outcome['outcome'] == 'held':
            totals['held'] += 1
            for key, amount in counts.items():
                totals[key + '_in_held_cases'] += amount
            state = outcome['hold_expectation']
            totals['holds_as_expected'] += state == 'as_expected'
            totals['holds_wrong_reason'] += state == 'wrong_reason'
            totals['unexpected_holds'] += state == 'not_expected'
            continue
        totals['sanitised'] += 1
        totals['holds_missed'] += outcome['hold_expectation'] == 'missed'
        for key, amount in counts.items():
            totals[key] += amount
        totals['removal_misses'] += len(outcome['removal_misses'])
        totals['over_removed'] += len(outcome['over_removed'])
        totals['type_changes'] += len(outcome['type_changes'])
        for item in case.get('must_remove', []):
            categories['removal'].setdefault(item['category'], {'items': 0, 'misses': 0})['items'] += 1
        for item in case.get('must_keep', []):
            categories['preservation'].setdefault(item['category'], {'items': 0, 'over_removed': 0})['items'] += 1
        for miss in outcome['removal_misses']:
            categories['removal'][miss['category']]['misses'] += 1
        for miss in outcome['over_removed']:
            categories['preservation'][miss['category']]['over_removed'] += 1
    totals['holds_not_as_expected'] = totals['holds_missed'] + totals['holds_wrong_reason']
    totals['removal_rate'] = _rate(totals['removal_items'] - totals['removal_misses'], totals['removal_items'])
    totals['preservation_rate'] = _rate(totals['preservation_items'] - totals['over_removed'], totals['preservation_items'])
    return totals, {kind: dict(sorted(values.items())) for kind, values in categories.items()}


def apply_thresholds(thresholds, totals):
    if thresholds is None:
        return {'state': 'not_defined', 'all_met': None,
                'note': 'No thresholds were supplied; rates are informational and no pass/fail is claimed.'}
    checks = {}
    for key, minimum in (('min_removal_rate', 'removal_rate'), ('min_preservation_rate', 'preservation_rate')):
        if key in thresholds:
            checks[key] = totals[minimum] is not None and totals[minimum] >= thresholds[key]
    for key, actual in (('max_unexpected_holds', 'unexpected_holds'), ('max_missed_holds', 'holds_not_as_expected'),
                        ('max_type_changes', 'type_changes'), ('max_errors', 'errors')):
        if key in thresholds:
            checks[key] = totals[actual] <= thresholds[key]
    return {'version': thresholds['version'], 'state': thresholds['state'], 'approved_by': thresholds['approved_by'],
            'approval_label': ('proposed_not_operator_approved' if thresholds['state'] == 'proposed'
                               else 'operator_declared_approved_unverified'),
            'approval_verified_by_tool': False, 'criteria': {key: thresholds[key] for key in checks}, 'met': checks,
            'all_met': all(checks.values()),
            'note': 'Declared by the input file. Meeting thresholds on these cases is not release approval or an anonymity claim.'}


def evaluate(cases_path, policy_path, key_path=None):
    data, resolved = read_json(cases_path, 'Cases file')
    dataset, thresholds, cases = load_cases(data, resolved)
    policy = load_policy(policy_path, key_path)
    sanitiser = Sanitizer(policy)
    outcomes = [evaluate_case(sanitiser, case) for case in cases]
    totals, categories = summarise(cases, outcomes)
    return {
        'report_version': REPORT_VERSION, 'contract': CONTRACT, 'dataset': dataset,
        'evidence_class': ('synthetic_development_check' if dataset['provenance'] == 'invented_synthetic'
                           else 'restricted_labelled_heldout_unverified_labels'),
        'policy_version': policy.version, 'detector': 'not_evaluated_no_call_made',
        'reference_key': 'persistent_private_key' if key_path else 'ephemeral_per_run',
        'denominators': totals, 'by_category': categories,
        'thresholds': apply_thresholds(thresholds, totals),
        'cases': [{key: value for key, value in outcome.items() if value not in (None, [])} for outcome in outcomes],
        **DISCLAIMERS,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description='Content-free offline sanitiser evaluation on labelled cases.')
    parser.add_argument('--cases', required=True, help='privacy-eval-cases/1 JSON')
    parser.add_argument('--policy', required=True, help='disclosure policy JSON (the invented example for synthetic cases)')
    parser.add_argument('--pseudonym-key', help='optional private key file; otherwise an ephemeral key is used')
    arguments = parser.parse_args(argv)
    try:
        result = evaluate(arguments.cases, arguments.policy, arguments.pseudonym_key)
    except InputError as failure:
        print(json.dumps({'error': 'invalid_input', 'detail': str(failure)[:200]}), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 1 if result['thresholds']['all_met'] is False else 0


if __name__ == '__main__':
    sys.exit(main())
