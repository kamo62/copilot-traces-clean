#!/usr/bin/env python3
"""Read-only, counts-only utility replay; never export record text or record hashes.

Run inside the API container, with reviewed API copies in a private temporary
directory, for example:
  python -B /tmp/api-D/measure_sanitiser_utility.py --api-dir /tmp/api-D \
      --revision rev_REPLACE

Only SELECTs are issued. Metadata pages contain at most 200 records; original
JSON is fetched by primary key one record at a time. No detector is called.
Instrumentation subclasses the copied sanitiser, verifies each payload against
an uninstrumented instance, and returns that instance's unchanged behaviour.
Character counts describe inputs to whole-line passes, not a privacy score.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import re
import sys
import time


# Reads go through clickhouse.rows(), which already sends readonly=2 (no writes);
# ClickHouse refuses to change 'readonly' again inside the query.
SETTINGS = ' SETTINGS max_memory_usage=536870912,max_threads=1,max_block_size=1'
ENDPOINT_SQL = ("multiIf(match(r.endpoint,'/chat/completions([/?#]|$)'),'chat/completions',"
                "match(r.endpoint,'/responses([/?#]|$)'),'responses',"
                "match(r.endpoint,'/messages([/?#]|$)'),'messages','other')")
LOCATION = re.compile(r':line[ \t]*\d+\b|\.[A-Za-z0-9]{1,8}:\d+\b', re.I)
CODE = re.compile(r'^\s*(?:[+\-]\s*)?(?:(?:def|class|function|const|let|var|import|from|return|'
                  r'if|for|while|using|public|private|protected|namespace|package|export)\b|'
                  r'[A-Za-z_][\w.]*\s*=(?!=)|\d+\s*[|:]\s*\S)|[;{}]\s*$')
REFERENCE = re.compile(r'\b[a-z][a-z_]*_[a-f0-9]{24}(?:\.[A-Za-z0-9]{1,8})?\b')
WINDOWS = re.compile(r'\b(?:windows|win32|win64|powershell)\b|(?<![A-Za-z0-9])[A-Za-z]:[\\/]|'
                     r'\\\\[^\\\s]+\\', re.I)
POSIX = re.compile(r'\b(?:linux|unix|ubuntu|debian|darwin|macos|mac os|osx)\b|'
                   r'(?<![\w:/])/(?:home|Users|usr|opt|etc|var|mnt|tmp)/', re.I)
SOURCE_TEXT_FIELDS = {
    'message': ('text',), 'tool_call': ('name', 'arguments', 'arguments_text'),
    'tool_result': ('content',), 'tool_schema': ('name', 'description', 'parameters'),
    'error': ('message', 'error_type', 'code'),
    'response_meta': ('model', 'stop_reason', 'status', 'usage'), 'completion': ('finish_reason',),
}


def strings(value):
    """String values only: keys are measured separately from record text."""
    if isinstance(value, dict):
        for item in value.values():
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


def source_text_characters(event, research):
    """Decoded content fields, excluding generated refs and protocol/hold markers."""
    guarded = research._policy_guard(event.get('payload') or {}, event.get('role'))
    if not isinstance(guarded, dict):
        return 0

    def content_strings(value):
        if isinstance(value, dict):
            if value.get('withheld') is True:
                return
            for item in value.values():
                yield from content_strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from content_strings(item)
        elif isinstance(value, str):
            yield value
    return sum(len(text) for field in SOURCE_TEXT_FIELDS.get(event['kind'], ())
               for text in content_strings(guarded.get(field)))


def replacement_blocks(text, selected, line_break, kind):
    """Mirror _replace_lines' intervals, including blank gaps and growth fallback."""
    blocks, position, start, end = [], 0, None, None
    for match in line_break.finditer(text + '\n'):
        line = text[position:match.start()]
        if selected(line):
            if start is None:
                start = position
            end = match.start()
        elif start is not None and not line.strip():
            pass
        elif start is not None:
            blocks.append((start, end))
            start = None
        position = match.end()
    if start is not None:
        blocks.append((start, end))
    predicted_size = len(text) + len(blocks) * (len(kind) + 25) - sum(b - a for a, b in blocks)
    if predicted_size > 2 * len(text) + 64:
        return [(0, len(text))], True
    return blocks, False


def line_shapes(text, line_break):
    """Offsets and indicators only; fenced/syntax-shaped lines are a code proxy."""
    position, fence = 0, None
    for match in line_break.finditer(text + '\n'):
        line = text[position:match.start()]
        stripped = line.lstrip()
        marker = '```' if stripped.startswith('```') else '~~~' if stripped.startswith('~~~') else None
        code = bool(line.strip()) and marker is None and (fence is not None or bool(CODE.search(line)))
        if marker:
            fence = None if fence == marker else marker if fence is None else fence
        yield position, match.start(), bool(LOCATION.search(line)), code
        position = match.end()


def measured_sanitizer(module):
    """Make an instrumented subclass, without monkey-patching API modules."""
    class Measured(module.Sanitizer):
        def __init__(self, policy):
            super().__init__(policy)
            self.baseline = module.Sanitizer(policy)
            self.counts = Counter()
            self.event_counts = Counter()
            self.is_key = False
            self.events_verified = 0

        def _key(self, key):
            previous = self.is_key
            self.is_key = True
            try:
                return super()._key(key)
            finally:
                self.is_key = previous

        def _replace_lines(self, text, selected, kind):
            blocks, fallback = replacement_blocks(text, selected, module.LINE_BREAK, kind)
            metrics = Counter(blocks=len(blocks), fallbacks=int(fallback))
            # Count before the pass adds references. Copying the growing set on
            # every call would make instrumentation quadratic on wide payloads.
            for start, end in blocks:
                block = text[start:end]
                reference_chars = sum(len(match.group()) for match in REFERENCE.finditer(block)
                                      if match.group().partition('.')[0] in self.refs.generated)
                metrics['characters'] += len(block)
                metrics['literal_characters'] += len(block) - reference_chars
            result = super()._replace_lines(text, selected, kind)
            expected_size = (len(kind) + 25 if fallback else
                             len(text) + len(blocks) * (len(kind) + 25) - sum(b - a for a, b in blocks))
            if len(result) != expected_size:
                raise RuntimeError('instrumentation_interval_mismatch')
            prefix = ('key_' if self.is_key else '') + kind + '_'
            block_index = 0
            for start, end, location, code in line_shapes(text, module.LINE_BREAK):
                while block_index < len(blocks) and start > blocks[block_index][1]:
                    block_index += 1
                if block_index < len(blocks) and blocks[block_index][0] <= start <= end <= blocks[block_index][1]:
                    metrics['lines'] += 1
                    metrics['location_lines'] += int(location)
                    metrics['code_shaped_lines'] += int(code)
            for key, value in metrics.items():
                self.counts[prefix + key] += value
                self.event_counts[prefix + key] += value
            return result

        def payload(self, payload, schema_fields=()):
            self.baseline.refs.bind_revision(self.refs.scope)
            self.baseline.refs.identity_scope = self.refs.identity_scope
            self.baseline.record_backslash_paths = self.record_backslash_paths
            expected = self.baseline.payload(payload, schema_fields=schema_fields)
            result = super().payload(payload, schema_fields=schema_fields)
            if module.canonical(expected) != module.canonical(result):
                raise RuntimeError('instrumentation_payload_mismatch')
            self.events_verified += 1
            return result
    return Measured


def distribution(values):
    """Unweighted sample distribution, including records with zero replacements."""
    values = sorted(values)
    if not values:
        return {'total': 0, 'median': 0, 'p90': 0}
    middle = len(values) // 2
    median = values[middle] if len(values) % 2 else (values[middle - 1] + values[middle]) / 2
    return {'total': sum(values), 'median': median, 'p90': values[math.ceil(.9 * len(values)) - 1]}


def summarise(records):
    result = {'records': len(records)}
    keys = {key for row in records for key in row} - {'endpoint', 'record_type', 'os_shape'}
    for key in sorted(keys):
        result[key] = distribution([row.get(key, 0) for row in records])
    characters = sum(row.get('input_characters', 0) for row in records)
    if any('input_characters' in row for row in records):
        result['line_character_share'] = (sum(row.get('file_characters', 0) + row.get('id_characters', 0)
                                              for row in records) / characters if characters else 0)
        result['literal_line_character_share'] = (
            sum(row.get('file_literal_characters', 0) + row.get('id_literal_characters', 0) for row in records) /
            characters if characters else 0)
    source_characters = sum(row.get('source_text_characters', 0) for row in records)
    if any('line_characters' in row for row in records) and source_characters:
        result['source_text_line_share'] = sum(row.get('line_characters', 0) for row in records) / source_characters
        result['source_text_nonreference_line_share'] = sum(row.get('literal_line_characters', 0) for row in records) / source_characters
    return result


def weighted_summary(records, population):
    """Inverse sampling-fraction estimates; quantiles use the weighted ECDF."""
    weights = {(row['endpoint'], row['record_type']): int(row['records']) for row in population}
    samples = Counter((row['endpoint'], row['record_type']) for row in records)
    values = [(row, weights[(row['endpoint'], row['record_type'])] / samples[(row['endpoint'], row['record_type'])])
              for row in records]
    total_weight = sum(weight for _, weight in values)

    def quantile(key, fraction):
        cumulative = 0
        for value, weight in sorted((row.get(key, 0), weight) for row, weight in values):
            cumulative += weight
            if cumulative >= fraction * total_weight:
                return value
        return 0

    result = {}
    for key in ('window_flag', 'line_loss_record', 'input_characters', 'file_characters', 'id_characters',
                'line_characters', 'literal_line_characters', 'line_character_fraction', 'source_text_characters'):
        if not any(key in row for row in records):
            continue
        total = sum(row.get(key, 0) * weight for row, weight in values)
        result[key] = {'estimated_population_total': total, 'mean': total / total_weight,
                       'median': quantile(key, .5), 'p90': quantile(key, .9)}
    input_total = result.get('input_characters', {}).get('estimated_population_total', 0)
    if 'line_characters' in result:
        result['line_character_share'] = result['line_characters']['estimated_population_total'] / input_total if input_total else 0
        result['literal_line_character_share'] = result['literal_line_characters']['estimated_population_total'] / input_total if input_total else 0
        source_total = result.get('source_text_characters', {}).get('estimated_population_total', 0)
        if source_total:
            result['source_text_line_share'] = result['line_characters']['estimated_population_total'] / source_total
            result['source_text_nonreference_line_share'] = result['literal_line_characters']['estimated_population_total'] / source_total
    return result


def read_rows(db, sql):
    # Queries are internal constants with validated IDs, not an arbitrary SQL CLI.
    if not re.match(r'^\s*(SELECT|WITH)\b', sql, re.I) or ';' in sql:
        raise ValueError('read_only_query_required')
    return db.rows(sql + SETTINGS)


def population_sql(revision):
    return ("SELECT " + ENDPOINT_SQL + " AS endpoint,if(r.type IN ('request','response'),r.type,'other') AS record_type,"
            "count() AS records FROM (SELECT record_id FROM research_processing FINAL PREWHERE revision_id='" +
            revision + "' WHERE status='processed') AS p INNER JOIN (SELECT id,type,endpoint FROM records FINAL "
            "PREWHERE id IN (SELECT record_id FROM research_processing FINAL PREWHERE revision_id='" + revision +
            "' WHERE status='processed')) AS r ON p.record_id=r.id GROUP BY endpoint,record_type ORDER BY endpoint,record_type")


def sample_sql(revision, endpoint, record_type, size):
    if endpoint not in ('chat/completions', 'responses', 'messages', 'other') or record_type not in ('request', 'response', 'other'):
        raise ValueError('invalid_stratum')
    if not 1 <= size <= 200:
        raise ValueError('sample_page_exceeded')
    return ("SELECT r.id,p.event_count FROM (SELECT record_id,event_count FROM research_processing FINAL "
            "PREWHERE revision_id='" + revision + "' WHERE status='processed') AS p INNER JOIN "
            "(SELECT id,type,endpoint FROM records FINAL PREWHERE id IN (SELECT record_id FROM research_processing "
            "FINAL PREWHERE revision_id='" + revision + "' WHERE status='processed')) AS r ON p.record_id=r.id WHERE " +
            ENDPOINT_SQL + "='" + endpoint + "' AND if(r.type IN ('request','response'),r.type,'other')='" + record_type +
            "' ORDER BY sipHash64(concat('measurement-D-2026-10-31:',r.id)),r.id LIMIT " + str(size))


def measure_record(row, revision, module, research, parsing, policy, endpoint, record_type):
    record = json.loads(row['record_json'])
    meter = measured_sanitizer(module)(policy)
    meter.refs.bind_revision(revision['revision_id'])
    meter.refs.identity_scope = str(row['user_id'])
    parsed = parsing.derive_events(record, meter.refs)
    events = parsed['events']
    flags = [meter.holds_backslash_paths(event.get('payload') or {}) for event in events]
    meter.record_backslash_paths = any(flags)
    windows, posix = False, False
    for event in events:
        for text in strings(event.get('payload') or {}):
            windows = windows or bool(WINDOWS.search(text))
            posix = posix or bool(POSIX.search(text))
    counts = Counter(events=len(events), window_flag=int(any(flags)), input_characters=0)
    for index, event in enumerate(events):
        meter.event_counts.clear()
        counts['source_text_characters'] += source_text_characters(event, research)
        payload = dict(event.get('payload') or {})
        frame_indexes = payload.pop('source_frame_event_indices', [])
        if frame_indexes:
            payload['source_frame_refs'] = [meter.refs.opaque('event', revision['revision_id'] + ':' + row['id'] + ':' + str(i))
                                            for i in frame_indexes if type(i) is int and 0 <= i < len(events)]
        guarded = research._policy_guard(payload, event.get('role'))
        counts['input_characters'] += sum(map(len, strings(guarded)))
        location_input, code_input = False, False
        for text in strings(guarded):
            for _, _, location, code in line_shapes(text, module.LINE_BREAK):
                location_input = location_input or location
                code_input = code_input or code
        counts['location_input_events'] += int(location_input)
        counts['code_shaped_input_events'] += int(code_input)
        meter.payload(guarded, schema_fields=('parameters',) if event['kind'] == 'tool_schema' else ())
        lost_location = sum(meter.event_counts[k + '_location_lines'] for k in ('file', 'id'))
        lost_code = sum(meter.event_counts[k + '_code_shaped_lines'] for k in ('file', 'id'))
        line_loss = sum(meter.event_counts[k + '_characters'] for k in ('file', 'id'))
        counts['location_loss_events'] += int(bool(lost_location))
        counts['code_shaped_loss_events'] += int(bool(lost_code))
        counts['line_loss_events'] += int(bool(line_loss))
        counts[event['kind'] + '_events'] += 1
        counts[event['kind'] + '_line_loss_events'] += int(bool(line_loss))
        counts[event['kind'] + '_location_loss_events'] += int(bool(lost_location))
        counts[event['kind'] + '_code_shaped_loss_events'] += int(bool(lost_code))
        counts['context_only_loss_events'] += int(bool(meter.event_counts['file_characters']) and any(flags) and not flags[index])
        counts['history_message_events'] += int(event['kind'] == 'message' and event['origin'] == 'history')
    counts.update(meter.counts)
    counts['verified_payloads'] = meter.events_verified
    counts['line_characters'] = counts['file_characters'] + counts['id_characters']
    counts['literal_line_characters'] = counts['file_literal_characters'] + counts['id_literal_characters']
    counts['line_character_fraction'] = counts['line_characters'] / counts['input_characters'] if counts['input_characters'] else 0
    counts['literal_line_character_fraction'] = counts['literal_line_characters'] / counts['input_characters'] if counts['input_characters'] else 0
    counts['line_loss_record'] = int(counts['line_characters'] > 0)
    counts['location_loss_record'] = int(counts['location_loss_events'] > 0)
    counts['code_shaped_loss_record'] = int(counts['code_shaped_loss_events'] > 0)
    return {'endpoint': endpoint, 'record_type': record_type,
            'os_shape': 'mixed' if windows and posix else 'windows_only' if windows else 'posix_only' if posix else 'neither',
            **counts}


def measure_record_text(row, revision, module, research, parsing, policy, endpoint, record_type):
    refs = module.RefFactory(policy)
    refs.bind_revision(revision['revision_id'])
    refs.identity_scope = str(row['user_id'])
    parsed = parsing.derive_events(json.loads(row['record_json']), refs)
    return {'endpoint': endpoint, 'record_type': record_type,
            'events': len(parsed['events']),
            'source_text_characters': sum(source_text_characters(event, research) for event in parsed['events'])}


def run(args):
    if not re.fullmatch(r'rev_[a-f0-9]{16,64}', args.revision) or not 1 <= args.sample_per_stratum <= 200:
        raise ValueError('invalid_revision_or_sample_size')
    if Path('/app/api').is_dir():
        sys.path.insert(0, '/app/api')
    sys.path.insert(0, str(Path(args.api_dir).resolve()))
    sys.dont_write_bytecode = True
    import clickhouse as db
    import parsing
    import research
    import sanitise
    config = research.ResearchConfig()
    if config.policy is None or config.policy.detector_enabled or config.detector is not None:
        raise RuntimeError('local_policy_required_detector_forbidden')
    revisions = read_rows(db, "SELECT revision_id,config_json,schema_version,parser_version,sanitiser_version,selection_max_seq,membership_sha256 FROM "
                          "research_revisions FINAL PREWHERE revision_id='" + args.revision + "' LIMIT 1")
    if len(revisions) != 1 or revisions[0]['sanitiser_version'] != sanitise.SANITISER_VERSION or revisions[0]['parser_version'] != parsing.PARSER_VERSION:
        raise RuntimeError('revision_version_mismatch')
    expected_revision, _ = research.config_revision(config, revisions[0]['selection_max_seq'], revisions[0]['membership_sha256'])
    if expected_revision != args.revision:
        raise RuntimeError('revision_configuration_mismatch')
    population = read_rows(db, population_sql(args.revision))
    observations, strata, started = [], [], time.monotonic()
    for stratum in population:
        sample = read_rows(db, sample_sql(args.revision, stratum['endpoint'], stratum['record_type'], args.sample_per_stratum))
        measured = []
        for meta in sample:
            if not re.fullmatch(r'[a-f0-9]{64}', meta['id']):
                raise RuntimeError('invalid_record_key')
            rows = read_rows(db, "SELECT id,user_id,content_sha256,record_json FROM records FINAL PREWHERE id='" + meta['id'] + "' LIMIT 1")
            if len(rows) != 1:
                raise RuntimeError('source_member_missing')
            if hashlib.sha256(rows[0]['record_json'].encode()).hexdigest() != rows[0]['content_sha256']:
                raise RuntimeError('source_checksum_mismatch')
            measure = measure_record_text if args.text_budget_only else measure_record
            result = measure(rows[0], revisions[0], sanitise, research, parsing, config.policy,
                             stratum['endpoint'], stratum['record_type'])
            if result['events'] != int(meta['event_count']):
                raise RuntimeError('stored_event_count_mismatch')
            measured.append(result)
        observations.extend(measured)
        strata.append({'endpoint': stratum['endpoint'], 'record_type': stratum['record_type'],
                       'population': int(stratum['records']), **summarise(measured)})
    os_groups = defaultdict(list)
    for observation in observations:
        if 'os_shape' in observation:
            os_groups[observation['os_shape']].append(observation)
    report = {'revision_id': args.revision, 'method': '200-or-fewer bottom-sipHash64 records per endpoint/type; fixed lane-D salt',
            'mode': 'parser_text_budget_only' if args.text_budget_only else 'verified_whole_line_replay',
            'population_records': sum(int(row['records']) for row in population), 'sample': summarise(observations),
            'strata': strata, 'os_shapes': {key: summarise(value) for key, value in sorted(os_groups.items())},
            'population_weighted_estimates': weighted_summary(observations, population),
            'source_modules_sha256': {name: hashlib.sha256(Path(module.__file__).read_bytes()).hexdigest()
                                      for name, module in (('sanitise', sanitise), ('parsing', parsing), ('research', research))},
            'wall_seconds_including_database_reads_and_double_sanitisation': time.monotonic() - started}
    if not args.text_budget_only:
        weighted_flags = sum(stratum['population'] * stratum['window_flag']['total'] / stratum['records'] for stratum in strata)
        report['population_weighted_window_flag_share'] = weighted_flags / sum(int(row['records']) for row in population)
    return report


class _ContentFreeParser(argparse.ArgumentParser):
    # argparse echoes the offending value; a pasted record ID or credential
    # would reach the logs.
    def error(self, message):
        print(json.dumps({'measurement_failed': 'invalid_arguments'}))
        raise SystemExit(2)


def main(argv=None):
    parser = _ContentFreeParser(description=__doc__)
    parser.add_argument('--api-dir', default=str(Path(__file__).resolve().parents[1] / 'api'))
    parser.add_argument('--revision', required=True)
    parser.add_argument('--sample-per-stratum', type=int, default=200)
    parser.add_argument('--text-budget-only', action='store_true',
                        help='Recount decoded source-text denominators only; no sanitiser/detector calls.')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(run(args), sort_keys=True))
    except Exception as failure:
        # Exception messages/tracebacks can contain restricted SQL or data.
        print(json.dumps({'measurement_failed': type(failure).__name__}))
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
