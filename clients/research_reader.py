#!/usr/bin/env python3
"""Incremental JSONL/gzip validator. Reassemble by observation/conversation and parent refs.

Use --manifest for a complete download: it checks the checksum and count across
all concatenated uncompressed pages. Without it, this validates one partial page.
A temporary SQLite index holds only pseudonymous references, never message text.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
from contextlib import closing

REQUIRED = {'schema_version', 'revision_id', 'event_id', 'observation_ref', 'conversation_ref',
            'observed_sequence', 'origin', 'kind', 'role', 'parent_event_id', 'call_ref', 'result_ref',
            'parse_status', 'linkage_status', 'coverage_status', 'timing', 'parser_version', 'links', 'payload'}
KINDS = {'observation', 'message', 'tool_call', 'tool_result', 'tool_schema', 'response_meta',
         'completion', 'error', 'source_frame', 'unsupported', 'withheld', 'empty', 'parse_error'}
PARSE = {'parsed', 'partial', 'invalid_json', 'empty', 'malformed', 'unsupported', 'incomplete', 'withheld', 'consecutive_json'}
COVERAGE = {'observed', 'complete', 'unknown', 'partial', 'incomplete', 'unsupported', 'withheld'}
# Sanitised events may reach the server's event ceiling (2 MiB by default).
# Keep the reader ceiling at or above it; override for a differently sized export.
MAX_LINE_BYTES = int(os.environ.get('COPILOT_READER_MAX_LINE_BYTES', str(4 * 1024 * 1024)))
SUPPORTED_SCHEMAS = {'research-event/1', 'research-event/2'}
REPEAT_FIELD = 'content_repeat_of'
EXCLUSION_REASONS = {'system_context', 'unsupported_attachment', 'private_context', 'reasoning_context',
    'source_event_count_exceeded', 'source_record_oversized', 'record_event_bytes_exceeded',
    'source_member_missing', 'source_checksum_mismatch',
    'unsupported_provider_shape', 'invalid_json', 'invalid_argument_fragment', 'invalid_choices_shape',
    'invalid_choice_shape', 'invalid_delta_shape', 'invalid_stream_frame', 'unrecognised_stream_assembly',
    'unrecognised_stream_event', 'unsupported_anthropic_delta', 'invalid_openai_content_delta',
    'invalid_openai_function_fragment', 'invalid_openai_tool_calls_shape', 'invalid_openai_function_call_shape',
    'invalid_response_output_item', 'invalid_source_frame', 'empty_source_frame', 'provider_truncated',
    'source_summary_present', 'partial_stream', 'ambiguous_identity_field', 'embedded_credential_container',
    'detector_uncertain', 'detector_invalid_output', 'detector_invalid_span', 'detector_output_too_large',
    'detector_redirect_rejected', 'detector_unavailable', 'detector_overlapping_spans',
    'detector_entity_at_chunk_boundary', 'final_leak_check_alias', 'final_leak_check_credential',
    'final_leak_check_credential_field', 'final_leak_check_identifier', 'final_leak_check_original_value',
    'final_leak_check_path', 'unsupported_content', 'policy_withheld', 'processing_failure'}


def validate_event(event):
    if not isinstance(event, dict) or set(event) - REQUIRED - {'link'} or REQUIRED - set(event):
        raise ValueError('Unexpected event shape')
    if event['schema_version'] not in SUPPORTED_SCHEMAS:
        raise ValueError('Unknown event schema')
    for key, prefix in (('revision_id', 'rev'), ('event_id', 'event'), ('observation_ref', 'obs'),
                        ('conversation_ref', 'conv'), ('parent_event_id', 'event'),
                        ('call_ref', 'call'), ('result_ref', 'result')):
        value = event[key]
        if value is None and key in ('conversation_ref', 'parent_event_id', 'call_ref', 'result_ref'):
            continue
        if not isinstance(value, str) or not re.fullmatch(prefix + r'_[a-f0-9]{16,64}', value):
            raise ValueError('Invalid scoped reference')
    if type(event['observed_sequence']) is not int or event['observed_sequence'] < 0:
        raise ValueError('Invalid sequence')
    if (event['origin'] not in ('history', 'output', 'source_stream', 'metadata') or
            event['kind'] not in KINDS or event['parse_status'] not in PARSE or
            event['coverage_status'] not in COVERAGE or event['linkage_status'] not in ('explicit', 'unknown', 'none') or
            event['role'] not in (None, 'system', 'developer', 'user', 'assistant', 'tool', 'function') or
            not isinstance(event['payload'], dict)):
        raise ValueError('Invalid typed event')
    if event['timing'] != {'exact_timestamps_released': False, 'precision': 'withheld'}:
        raise ValueError('Invalid timing disclosure')
    if not isinstance(event['parser_version'], str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', event['parser_version']):
        raise ValueError('Invalid parser version')
    if not isinstance(event['links'], list):
        raise ValueError('Invalid links')
    for link in event['links'] + ([event['link']] if event.get('link') is not None else []):
        if (not isinstance(link, dict) or set(link) != {'type', 'ref', 'method', 'confidence', 'raw_value_exported'} or
                link['confidence'] != 'explicit' or link['raw_value_exported'] is not False or
                any(not isinstance(link[k], str) for k in ('type', 'ref', 'method')) or
                not re.fullmatch(r'(?:call|result|conv|resp)_[a-f0-9]{16,64}', link['ref'])):
            raise ValueError('Invalid event link')
    frame_refs = event['payload'].get('source_frame_refs', [])
    if (not isinstance(frame_refs, list) or any(not isinstance(ref, str) or
            not re.fullmatch(r'event_[a-f0-9]{16,64}', ref) for ref in frame_refs)):
        raise ValueError('Invalid source frame references')
    if 'fragment_count' in event['payload'] and (type(event['payload']['fragment_count']) is not int or
                                                  event['payload']['fragment_count'] < len(frame_refs)):
        raise ValueError('Invalid source fragment count')
    if REPEAT_FIELD in event['payload']:
        ref = event['payload'][REPEAT_FIELD]
        allowed = {'text', 'block_type', 'authorship', 'intent_label', 'intent_status', 'observed_file_references', REPEAT_FIELD}
        if (event['schema_version'] != 'research-event/2' or event['kind'] != 'message' or event['origin'] != 'history' or
                event['role'] not in ('user', 'assistant') or event['conversation_ref'] is None or
                event['parse_status'] != 'parsed' or event['coverage_status'] not in ('unknown', 'observed', 'complete') or
                set(event['payload']) - allowed or not isinstance(event['payload'].get('text'), str) or
                not event['payload']['text'] or '[WITHHELD]' in event['payload']['text'] or
                event['payload'].get('block_type') != 'text' or event['payload'].get('authorship') != 'unknown' or
                event['payload'].get('intent_label') is not None or event['payload'].get('intent_status') != 'unknown' or
                (ref is not None and (not isinstance(ref, str) or not re.fullmatch(r'event_[a-f0-9]{16,64}', ref) or
                                     ref == event['event_id']))):
            raise ValueError('Invalid content-repeat annotation')
    return event


def _coverage_reason(event):
    reason = event['payload'].get('reason')
    if reason in EXCLUSION_REASONS:
        return reason
    return 'policy_withheld' if event['kind'] == 'withheld' else 'unsupported_content'


def _nested_exclusions(payload):
    found = {}

    def visit(value, root=False):
        if isinstance(value, dict):
            if not root and value.get('withheld') is True:
                reason = value.get('reason')
                reason = reason if reason in EXCLUSION_REASONS else 'policy_withheld'
                found[reason] = found.get(reason, 0) + 1
                return
            for item in value.values(): visit(item)
        elif isinstance(value, list):
            for item in value: visit(item)
        elif value == '[WITHHELD]':
            found['policy_withheld'] = found.get('policy_withheld', 0) + 1

    visit(payload, True)
    return found


def iter_events(path, digest=None):
    """Only LF separates physical lines; U+2028/U+0085 remain inside JSON strings."""
    opener = gzip.open if Path(path).suffix == '.gz' else open
    with opener(path, 'rb') as handle:
        while True:
            line = handle.readline(MAX_LINE_BYTES + 1)
            if not line:
                return
            if len(line) > MAX_LINE_BYTES or not line.endswith(b'\n'):
                raise ValueError('Oversized or interrupted JSONL line')
            if digest is not None:
                digest.update(line)
            try:
                event = json.loads(line.decode('utf-8'), parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))
            except (ValueError, UnicodeError):
                raise ValueError('Invalid UTF-8 JSON line') from None
            yield validate_event(event)


def read_export(path, manifest=None):
    digest = hashlib.sha256()
    previous = None
    count, unlinked, kinds = 0, 0, set()
    observations = {}
    frame_consumers = {}
    exclusions = {}
    repeat_count, repeat_eligible = 0, 0
    with tempfile.TemporaryDirectory(prefix='research-reader-refs-') as directory:
        with closing(sqlite3.connect(str(Path(directory) / 'refs.sqlite'))) as index:
            index.execute('CREATE TABLE refs(id TEXT PRIMARY KEY,parent TEXT,conversation TEXT,kind TEXT,frames TEXT)')
            for event in iter_events(path, digest):
                ordering = (event['observed_sequence'], event['event_id'])
                if previous is not None and (event['revision_id'] != revision or ordering <= previous):
                    raise ValueError('Mixed revision or non-deterministic order')
                revision, previous = event['revision_id'], ordering
                repeat_hash = None
                if REPEAT_FIELD in event['payload']:
                    if not repeat_eligible:
                        index.execute('CREATE TABLE repeats(id TEXT PRIMARY KEY,conversation TEXT,observation TEXT,'
                                      'role TEXT,sequence INTEGER,repeat_of TEXT,repeat_hash TEXT)')
                    semantic = {key: value for key, value in event['payload'].items() if key != REPEAT_FIELD}
                    repeat_hash = hashlib.sha256(json.dumps(semantic, sort_keys=True, ensure_ascii=False,
                                                           allow_nan=False, separators=(',', ':')).encode()).hexdigest()
                    repeat_eligible += 1
                    repeat_count += event['payload'][REPEAT_FIELD] is not None
                try:
                    index.execute('INSERT INTO refs VALUES(?,?,?,?,?)',
                                  (event['event_id'], event['parent_event_id'], event['conversation_ref'],
                                   event['kind'], json.dumps(event['payload'].get('source_frame_refs', []))))
                    if repeat_hash is not None:
                        index.execute('INSERT INTO repeats VALUES(?,?,?,?,?,?,?)',
                                      (event['event_id'], event['conversation_ref'], event['observation_ref'],
                                       event['role'], event['observed_sequence'], event['payload'][REPEAT_FIELD], repeat_hash))
                except sqlite3.IntegrityError:
                    raise ValueError('Duplicate event ID') from None
                count += 1
                unlinked += event['conversation_ref'] is None
                kinds.add(event['kind'])
                coverage = observations.setdefault(event['observation_ref'], {'events': 0, 'source_frames': 0,
                    'source_frame_mapped': 0, 'source_frame_withheld': 0, 'source_frame_unsupported': 0,
                    'event_mapped': 0, 'event_withheld': 0, 'event_unsupported': 0, 'nested_excluded_units': 0,
                    'partial_or_unknown': 0})
                coverage['events'] += 1
                coverage['source_frames'] += event['kind'] == 'source_frame'
                if event['kind'] == 'source_frame':
                    frame_consumers[event['event_id']] = {'observation_ref': event['observation_ref'],
                        'parse_status': event['parse_status'], 'consumer_kinds': set()}
                for frame_ref in event['payload'].get('source_frame_refs', []):
                    if frame_ref in frame_consumers:
                        frame_consumers[frame_ref]['consumer_kinds'].add(event['kind'])
                is_withheld = event['coverage_status'] == 'withheld' or event['kind'] == 'withheld'
                is_unsupported = event['coverage_status'] == 'unsupported' or event['kind'] in ('unsupported', 'parse_error')
                coverage['event_withheld'] += is_withheld
                coverage['event_unsupported'] += is_unsupported
                coverage['event_mapped'] += not is_withheld and not is_unsupported and event['kind'] != 'source_frame'
                coverage['partial_or_unknown'] += event['coverage_status'] in ('partial', 'unknown', 'incomplete')
                if is_withheld or is_unsupported:
                    reason = _coverage_reason(event)
                    excluded = exclusions.setdefault(event['observation_ref'], {})
                    excluded[reason] = excluded.get(reason, 0) + 1
                nested = _nested_exclusions(event['payload'])
                coverage['nested_excluded_units'] += sum(nested.values())
                if nested:
                    excluded = exclusions.setdefault(event['observation_ref'], {})
                    for reason, amount in nested.items():
                        excluded[reason] = excluded.get(reason, 0) + amount
            for frame in frame_consumers.values():
                coverage = observations[frame['observation_ref']]
                kinds = frame['consumer_kinds']
                if (frame['parse_status'] not in ('parsed', 'consecutive_json', 'incomplete') or not kinds or
                        'unsupported' in kinds or 'parse_error' in kinds):
                    coverage['source_frame_unsupported'] += 1
                elif kinds <= {'withheld'}:
                    coverage['source_frame_withheld'] += 1
                else:
                    coverage['source_frame_mapped'] += 1
            conversations = index.execute('SELECT count(DISTINCT conversation) FROM refs').fetchone()[0]
            summary = {'events': count, 'observations': len(observations),
                       'source_frames': sum(item['source_frames'] for item in observations.values()),
                       'nested_excluded_units': sum(item['nested_excluded_units'] for item in observations.values()),
                       'revision_id': revision if count else None,
                       'conversations': conversations, 'unlinked_events': unlinked, 'kinds': sorted(kinds)}
            unresolved_repeats = 0
            if repeat_eligible:
                invalid_repeats = index.execute('SELECT count(*) FROM repeats r JOIN refs present ON r.repeat_of=present.id '
                    'LEFT JOIN repeats p ON r.repeat_of=p.id WHERE p.id IS NULL OR p.repeat_of IS NOT NULL OR '
                    'r.repeat_hash!=p.repeat_hash OR r.conversation!=p.conversation OR r.role!=p.role OR '
                    'r.observation=p.observation OR (p.sequence,p.id)>=(r.sequence,r.id)').fetchone()[0]
                if invalid_repeats:
                    raise ValueError('Invalid content-repeat target')
                unresolved_repeats = index.execute('SELECT count(*) FROM repeats r LEFT JOIN refs p ON r.repeat_of=p.id '
                    'WHERE r.repeat_of IS NOT NULL AND p.id IS NULL').fetchone()[0]
                summary.update(content_repeat_events=repeat_count, repeat_eligible_events=repeat_eligible,
                               unresolved_content_repeat_refs=unresolved_repeats,
                               content_repeat_validation='incomplete' if unresolved_repeats else 'complete')
            if manifest is not None:
                data = json.loads(Path(manifest).read_text(encoding='utf-8')) if not isinstance(manifest, dict) else manifest
                counts = data.get('counts', {})
                coverage_mismatch = data.get('schema_version') == 'research-event/2' and (
                    counts.get('observations') != len(observations) or
                    counts.get('source_frames') != summary['source_frames'] or
                    counts.get('source_frames_mapped') != sum(item['source_frame_mapped'] for item in observations.values()) or
                    counts.get('source_frames_withheld') != sum(item['source_frame_withheld'] for item in observations.values()) or
                    counts.get('source_frames_unsupported') != sum(item['source_frame_unsupported'] for item in observations.values()) or
                    counts.get('nested_excluded_units') != summary['nested_excluded_units'] or
                    data.get('per_observation_coverage') != [
                        {'observation_ref': ref, **observations[ref]} for ref in sorted(observations)] or
                    data.get('per_observation_exclusions') != [
                        {'observation_ref': ref, 'reasons': exclusions[ref]} for ref in sorted(exclusions)])
                if (data.get('export_sha256') != digest.hexdigest() or counts.get('events') != count or coverage_mismatch):
                    raise ValueError('Incomplete export or manifest checksum/count mismatch')
                if count and data.get('revision_id') != revision:
                    raise ValueError('Manifest revision mismatch')
                repeat_counts = data.get('dedupe', {}).get('counts', {})
                if unresolved_repeats or (repeat_eligible and not repeat_counts) or (repeat_counts and (
                        repeat_counts.get('eligible_events') != repeat_eligible or
                        repeat_counts.get('content_repeat_events') != repeat_count or
                        repeat_counts.get('retained_eligible_events') != repeat_eligible - repeat_count or
                        repeat_counts.get('payloads_suppressed') != 0)):
                    raise ValueError('Incomplete content-repeat coverage')
                absent = index.execute('SELECT count(*) FROM refs r LEFT JOIN refs p ON r.parent=p.id '
                                       'WHERE r.parent IS NOT NULL AND p.id IS NULL').fetchone()[0]
                if absent:
                    raise ValueError('Explicit parent outside complete pinned export')
                absent_frames = index.execute('SELECT count(*) FROM refs r,json_each(r.frames) f '
                    'LEFT JOIN refs frame ON frame.id=f.value WHERE frame.id IS NULL OR frame.kind!=\'source_frame\'').fetchone()[0]
                if absent_frames:
                    raise ValueError('Source frame reference outside complete pinned export')
                held = data.get('held_observations', [])
                if data.get('schema_version') == 'research-event/2' and (
                        not isinstance(held, list) or len(held) != counts.get('records_withheld') or
                        any(not isinstance(row, dict) or set(row) != {'observation_ref', 'reason'} or
                            not isinstance(row['reason'], str) or not re.fullmatch(r'obs_[a-f0-9]{16,64}', row['observation_ref'])
                            for row in held) or len({row['observation_ref'] for row in held}) != len(held)):
                    raise ValueError('Invalid held observation coverage')
                summary['manifest_checksum_verified'] = True
            # Missing tool calls can be valid observed-history gaps. Do not invent/reject them.
            return summary


def main():
    parser = argparse.ArgumentParser(description='Validate research JSONL incrementally.')
    parser.add_argument('export')
    parser.add_argument('--manifest')
    arguments = parser.parse_args()
    print(json.dumps(read_export(arguments.export, arguments.manifest), sort_keys=True))


if __name__ == '__main__':
    main()
