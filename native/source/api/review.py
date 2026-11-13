"""Admin-only research review: bounded original/derived comparison, coverage counts and operator annotations.

Everything here is restricted to the admin role. Annotations are an append-only sidecar in ClickHouse, keyed to a
revision and an observation reference. They never touch raw records, derived events or released export bytes, and
neither annotation labels nor the free-text note are part of any research export.
"""
from datetime import datetime, timezone
import hashlib
import json
import re
import threading
import time

import archive
import clickhouse as db
import research

TAXONOMY_VERSION = 'annotation-taxonomy/1'
OBSERVATION_REF = re.compile(r'^obs_[a-f0-9]{16,64}$')
EVENT_REF = research.EVENT_ID
REVIEWER = re.compile(r'^[A-Za-z0-9._-]{1,64}$')
PROCESSING_STATES = ('pending', 'processed', 'held', 'retry_pending', 'retry_exhausted', 'failed')
MAX_EVIDENCE = 20
MAX_NOTE = 500
MAX_OBSERVATIONS = 100
MAX_COMPARE_EVENTS = 100
ORIGINAL_DISPLAY_BYTES = 256 * 1024
DERIVED_DISPLAY_BYTES = 256 * 1024
AGGREGATE_SETTINGS = ' SETTINGS max_threads=1,max_execution_time=30'
WRITE_LOCK = threading.Lock()

# Code-owned taxonomy. Labels describe what a reviewer observed in the cited events. None of them asserts that
# engineering work was completed or rates a developer, and a user-role message does not prove who authored it.
TAXONOMY = {
    'task_intent': {
        'labels': ('code_help', 'feature_work', 'bug_fix', 'testing', 'review', 'documentation', 'presentation',
                   'email', 'other', 'unknown'),
        'evidence': 'at least one cited user-role message',
    },
    'context_retrieval': {
        'labels': ('file_read', 'search', 'mixed', 'none_observed', 'unknown'),
        'evidence': 'at least one cited tool call or tool result',
    },
    'orchestration': {
        'labels': ('single_step', 'multi_step', 'retry_observed', 'unknown'),
        'evidence': 'at least one cited tool call or tool result',
    },
    'outcome': {
        'labels': ('assistant_reported_done', 'tool_success_observed', 'tool_error_observed', 'no_outcome_observed',
                   'unknown'),
        'evidence': 'label-specific: assistant_reported_done needs a cited assistant message; tool_success_observed and '
                    'tool_error_observed need a cited tool result',
    },
}
def _assistant_message(event):
    return event['kind'] == 'message' and event['role'] == 'assistant'


def _tool_result(event):
    return event['kind'] == 'tool_result'


def _any_content_event(event):
    return event['kind'] in ('message', 'tool_call', 'tool_result')


EVIDENCE_RULES = {
    'task_intent': lambda event: event['kind'] == 'message' and event['role'] == 'user',
    'context_retrieval': lambda event: event['kind'] in ('tool_call', 'tool_result'),
    'orchestration': lambda event: event['kind'] in ('tool_call', 'tool_result'),
    'outcome': lambda event: _tool_result(event) or _assistant_message(event),
}
# Label-specific rules override the dimension rule. They still record a reviewer's assertion, never verified truth.
LABEL_EVIDENCE_RULES = {
    ('outcome', 'assistant_reported_done'): _assistant_message,
    ('outcome', 'tool_success_observed'): _tool_result,
    ('outcome', 'tool_error_observed'): _tool_result,
    ('outcome', 'no_outcome_observed'): _any_content_event,
    ('context_retrieval', 'none_observed'): _any_content_event,
}
LABEL_EVIDENCE_TEXT = {
    'assistant_reported_done': 'a cited assistant message (a self-report, not verification)',
    'tool_success_observed': 'a cited tool result',
    'tool_error_observed': 'a cited tool result',
    'no_outcome_observed': 'a cited message, tool call or tool result from the reviewed observation',
    'none_observed': 'a cited message, tool call or tool result from the reviewed observation',
}
KNOWN_GAPS = (
    'Conversation coverage is unknown; a processed revision is not a complete developer session.',
    'Source records over 2 MiB and derived events over 512 KiB are held, not segmented.',
    'OTLP client batches are not derived into research events.',
    'Annotations are operator assertions on cited events; they are not performance, completion or intent scores.',
)


def initialise():
    db.execute("""CREATE TABLE IF NOT EXISTS research_annotations (
      annotation_id String, revision_id String, observation_ref String, dimension LowCardinality(String),
      label LowCardinality(String), review_state LowCardinality(String), evidence_json String,
      reviewer String, note String CODEC(ZSTD(3)), taxonomy_version String, created_at String, version UInt64
    ) ENGINE=MergeTree ORDER BY (revision_id,observation_ref,dimension,version)""")


def taxonomy():
    return {'taxonomy_version': TAXONOMY_VERSION,
            'dimensions': {name: {'labels': list(spec['labels']), 'evidence_requirement': spec['evidence'],
                                  'label_evidence_requirements': {label: LABEL_EVIDENCE_TEXT[label] for label in spec['labels']
                                                                  if label in LABEL_EVIDENCE_TEXT}}
                           for name, spec in TAXONOMY.items()},
            'review_states': ['unreviewed', 'reviewed'],
            'note': 'A dimension with no stored annotation is unreviewed. Labels are reviewer assertions on cited '
                    'events, not completed-work, intent-model or employee-performance claims.'}


def _revision(value):
    if not isinstance(value, str) or not research.REVISION_ID.fullmatch(value):
        raise ValueError('Invalid revision')
    return value


def _observation(value):
    if not isinstance(value, str) or not OBSERVATION_REF.fullmatch(value):
        raise ValueError('Invalid observation')
    return value


def _require_processed(revision_id, observation_ref):
    if not research._revision_row(revision_id):
        raise LookupError('Revision not found')
    rows = db.rows('SELECT record_id,status,failure_class,event_count,pipeline_id FROM research_processing FINAL WHERE revision_id=' +
                   db.literal(revision_id) + ' AND observation_ref=' + db.literal(observation_ref) + ' LIMIT 1')
    if not rows:
        raise LookupError('Observation not found')
    return rows[0]


def _processed_events(revision_id, observation_ref, event_ids):
    """Current-pipeline events of this observation among the cited IDs; superseded rows cannot be evidence."""
    literals = ','.join(db.literal(value) for value in event_ids)
    return db.rows('SELECT e.event_id AS event_id,e.kind AS kind,e.role AS role FROM (SELECT event_id,kind,role,record_id,pipeline_id '
                   'FROM research_events FINAL WHERE revision_id=' + db.literal(revision_id) + ' AND observation_ref=' +
                   db.literal(observation_ref) + ' AND event_id IN (' + literals + ')) AS e INNER JOIN (SELECT record_id,pipeline_id '
                   'FROM research_processing FINAL WHERE revision_id=' + db.literal(revision_id) + ' AND observation_ref=' +
                   db.literal(observation_ref) + " AND status='processed') AS p ON e.record_id=p.record_id AND "
                   'e.pipeline_id=p.pipeline_id LIMIT ' + str(MAX_EVIDENCE))


def validate_annotation(body):
    """Shape and vocabulary only; evidence existence is checked against ClickHouse by store_annotation."""
    required = {'revision_id', 'observation_ref', 'dimension', 'label', 'evidence_event_ids', 'reviewer'}
    if not isinstance(body, dict) or not required <= set(body) or set(body) - required - {'note'}:
        raise ValueError('Unexpected annotation fields')
    dimension, label = body['dimension'], body['label']
    if type(dimension) is not str or dimension not in TAXONOMY or type(label) is not str or label not in TAXONOMY[dimension]['labels']:
        raise ValueError('Unknown dimension or label')
    reviewer = body['reviewer']
    if type(reviewer) is not str or not REVIEWER.fullmatch(reviewer):
        raise ValueError('Invalid reviewer label')
    note = body.get('note', '')
    if type(note) is not str or len(note) > MAX_NOTE or any(ord(char) < 32 and char not in '\n\t' for char in note):
        raise ValueError('Invalid note')
    evidence = body['evidence_event_ids']
    if (not isinstance(evidence, list) or len(evidence) > MAX_EVIDENCE or
            any(type(item) is not str or not EVENT_REF.fullmatch(item) for item in evidence) or len(set(evidence)) != len(evidence)):
        raise ValueError('Invalid evidence references')
    if label != 'unknown' and not evidence:
        raise ValueError('A label other than unknown requires supporting event references')
    return {'revision_id': _revision(body['revision_id']), 'observation_ref': _observation(body['observation_ref']),
            'dimension': dimension, 'label': label, 'evidence_event_ids': sorted(evidence), 'reviewer': reviewer,
            'note': note.strip()}


def current_annotations(revision_id, observation_ref):
    return db.rows('SELECT annotation_id,dimension,label,review_state,evidence_json,reviewer,note,taxonomy_version,created_at '
                   'FROM research_annotations WHERE revision_id=' + db.literal(revision_id) + ' AND observation_ref=' +
                   db.literal(observation_ref) + ' ORDER BY version DESC LIMIT 1 BY dimension LIMIT ' + str(len(TAXONOMY)))


def _public_annotation(row):
    return {'annotation_id': row['annotation_id'], 'dimension': row['dimension'], 'label': row['label'],
            'review_state': row['review_state'], 'evidence_event_ids': json.loads(row['evidence_json']),
            'reviewer': row['reviewer'], 'note': row['note'], 'taxonomy_version': row['taxonomy_version'],
            'created_at': row['created_at']}


def store_annotation(body):
    clean = validate_annotation(body)
    revision_id, observation_ref = clean['revision_id'], clean['observation_ref']
    status = _require_processed(revision_id, observation_ref)
    if status['status'] != 'processed':
        raise ValueError('Only a processed observation has events that can be cited')
    if clean['evidence_event_ids']:
        found = {row['event_id']: row for row in _processed_events(revision_id, observation_ref, clean['evidence_event_ids'])}
        if set(found) != set(clean['evidence_event_ids']):
            raise ValueError('Evidence must be current events of this observation')
        rule = LABEL_EVIDENCE_RULES.get((clean['dimension'], clean['label']), EVIDENCE_RULES[clean['dimension']])
        if clean['label'] != 'unknown' and not any(rule(row) for row in found.values()):
            raise ValueError('Cited events do not satisfy the evidence requirement for this dimension')
    evidence_json = json.dumps(clean['evidence_event_ids'], separators=(',', ':'))
    with WRITE_LOCK:
        latest = [row for row in current_annotations(revision_id, observation_ref) if row['dimension'] == clean['dimension']]
        if latest and (latest[0]['label'], latest[0]['evidence_json'], latest[0]['reviewer'], latest[0]['note'],
                       latest[0]['taxonomy_version']) == (clean['label'], evidence_json, clean['reviewer'], clean['note'],
                                                          TAXONOMY_VERSION):
            return _public_annotation(latest[0])
        version = time.time_ns()
        row = {'annotation_id': 'ann_' + hashlib.sha256('\x00'.join((revision_id, observation_ref, clean['dimension'],
                                                                      str(version))).encode()).hexdigest()[:32],
               'revision_id': revision_id, 'observation_ref': observation_ref, 'dimension': clean['dimension'],
               'label': clean['label'], 'review_state': 'reviewed', 'evidence_json': evidence_json,
               'reviewer': clean['reviewer'], 'note': clean['note'], 'taxonomy_version': TAXONOMY_VERSION,
               'created_at': datetime.now(timezone.utc).isoformat(), 'version': version}
        db.insert('research_annotations', [row])
    return _public_annotation(row)


def annotations(revision_id, observation_ref):
    revision_id, observation_ref = _revision(revision_id), _observation(observation_ref)
    _require_processed(revision_id, observation_ref)
    history = db.rows('SELECT annotation_id,dimension,label,review_state,evidence_json,reviewer,note,taxonomy_version,created_at '
                      'FROM research_annotations WHERE revision_id=' + db.literal(revision_id) + ' AND observation_ref=' +
                      db.literal(observation_ref) + ' ORDER BY version DESC LIMIT 50')
    current = {row['dimension']: _public_annotation(row) for row in current_annotations(revision_id, observation_ref)}
    return {'revision_id': revision_id, 'observation_ref': observation_ref, 'taxonomy_version': TAXONOMY_VERSION,
            'current': {name: current.get(name, {'dimension': name, 'review_state': 'unreviewed', 'label': None})
                        for name in TAXONOMY},
            'history': [_public_annotation(row) for row in history], 'history_limit': 50,
            'exported_to_research': False}


def _processed_join(revision_id):
    return ('(SELECT record_id,pipeline_id FROM research_processing FINAL WHERE revision_id=' + db.literal(revision_id) +
            " AND status='processed') AS p ON e.record_id=p.record_id AND e.pipeline_id=p.pipeline_id")


def summary(revision_id, environ=None):
    revision_id = _revision(revision_id)
    revision = db.rows('SELECT revision_id,created_at,status,policy_version,parser_version,schema_version,detector_model,'
                       'expected_records,pending_records,processed_records,held_records,retry_pending_records,'
                       'retry_exhausted_records,failed_records,event_count,conversation_count,complete,updated_at '
                       'FROM research_revisions FINAL WHERE revision_id=' + db.literal(revision_id))
    if not revision:
        raise LookupError('Revision not found')
    processing = db.rows('SELECT status,failure_class,count() AS observations FROM research_processing FINAL WHERE revision_id=' +
                         db.literal(revision_id) + ' GROUP BY status,failure_class ORDER BY status,failure_class LIMIT 200' +
                         AGGREGATE_SETTINGS)
    events = db.rows('SELECT e.kind AS kind,e.coverage_status AS coverage_status,count() AS events FROM (SELECT kind,coverage_status,'
                     'record_id,pipeline_id FROM research_events FINAL WHERE revision_id=' + db.literal(revision_id) +
                     ') AS e INNER JOIN ' + _processed_join(revision_id) + ' GROUP BY kind,coverage_status ORDER BY kind,'
                     'coverage_status LIMIT 200' + AGGREGATE_SETTINGS)
    reviewed = db.rows('SELECT dimension,label,count() AS observations FROM (SELECT observation_ref,dimension,label FROM '
                       'research_annotations WHERE revision_id=' + db.literal(revision_id) + ' ORDER BY version DESC LIMIT 1 '
                       'BY observation_ref,dimension) GROUP BY dimension,label ORDER BY dimension,label LIMIT 200' +
                       AGGREGATE_SETTINGS)
    released = bool(db.rows("SELECT revision_id FROM research_releases FINAL WHERE revision_id=" + db.literal(revision_id) +
                            " AND status='released' LIMIT 1"))

    def total(rule):
        return sum(int(row['events']) for row in events if rule(row))
    return {
        'revision': revision[0], 'released': released,
        'hold': {'release_blocked': research.ResearchConfig(environ).release_blockers(),
                 'unresolved_members': sum(int(revision[0][key]) for key in
                     ('pending_records', 'retry_pending_records', 'retry_exhausted_records', 'failed_records'))},
        'observation_dispositions': processing,
        'held_observations': sum(int(row['observations']) for row in processing if row['status'] == 'held'),
        'oversize_held_observations': sum(int(row['observations']) for row in processing
                                         if row['failure_class'] == 'source_record_oversized'),
        'current_events_by_kind_and_coverage': events,
        'withheld_events': total(lambda row: row['kind'] == 'withheld' or row['coverage_status'] == 'withheld'),
        'unsupported_events': total(lambda row: row['kind'] in ('unsupported', 'parse_error') or
                                    row['coverage_status'] == 'unsupported'),
        'partial_or_unknown_events': total(lambda row: row['coverage_status'] in ('partial', 'unknown', 'incomplete')),
        'annotation_counts': reviewed, 'annotation_taxonomy_version': TAXONOMY_VERSION,
        'known_gaps': list(KNOWN_GAPS)}


def observations(revision_id, after='', limit=50, status=None):
    revision_id = _revision(revision_id)
    if after and not OBSERVATION_REF.fullmatch(after):
        raise ValueError('Invalid cursor')
    if type(limit) is not int or not 1 <= limit <= MAX_OBSERVATIONS:
        raise ValueError('Invalid page size')
    if status is not None and status not in PROCESSING_STATES:
        raise ValueError('Invalid status')
    rows = db.rows('SELECT observation_ref,status,failure_class,event_count,attempt_count,retry_epoch,updated_at FROM '
                   'research_processing FINAL WHERE revision_id=' + db.literal(revision_id) + ' AND observation_ref>' +
                   db.literal(after) + (' AND status=' + db.literal(status) if status else '') +
                   ' ORDER BY observation_ref LIMIT ' + str(limit) + AGGREGATE_SETTINGS)
    return {'revision_id': revision_id, 'observations': rows, 'content_included': False,
            'next_after': rows[-1]['observation_ref'] if len(rows) == limit else None}


def compare(revision_id, observation_ref, from_index=0):
    """One explicitly selected observation: bounded original record beside its bounded derived events."""
    revision_id, observation_ref = _revision(revision_id), _observation(observation_ref)
    if type(from_index) is not int or from_index < 0:
        raise ValueError('Invalid event offset')
    status = _require_processed(revision_id, observation_ref)
    record_id = status['record_id']
    sizes = db.rows('SELECT length(record_json) AS bytes FROM records FINAL PREWHERE id=' + db.literal(record_id) +
                    ' SETTINGS max_threads=1,max_block_size=1')
    if not sizes:
        raise LookupError('Source record not found')
    size = int(sizes[0]['bytes'])
    if size > ORIGINAL_DISPLAY_BYTES:
        original = {'included': False, 'reason': 'over_display_bound', 'bytes': size, 'display_bound_bytes': ORIGINAL_DISPLAY_BYTES,
                    'record_id': record_id,  # exact raw ID, admin-only, to fetch it through the restricted raw-record API
                    'note': 'Use GET /v1/review/records/{record_id} with the admin key for the complete original.'}
    else:
        original = {'included': True, 'bytes': size, **archive.review_record(record_id)}
    derived = {'status': status['status'], 'failure_class': status['failure_class'] or None,
               'events': [], 'omitted_events': [], 'event_count_total': int(status['event_count']),
               'from_index': from_index, 'next_from_index': None, 'truncated': False}
    if status['status'] == 'processed':
        scope = ('revision_id=' + db.literal(revision_id) + ' AND record_id=' + db.literal(record_id) + ' AND pipeline_id=' +
                 db.literal(status['pipeline_id']) + ' AND event_index>=' + str(from_index))
        sizes = db.rows('SELECT event_index,event_id,length(payload) AS payload_bytes FROM research_events FINAL WHERE ' + scope +
                        ' ORDER BY event_index LIMIT ' + str(MAX_COMPARE_EVENTS + 1) + ' SETTINGS max_threads=1')
        chosen, total, consumed = [], 0, 0
        for row in sizes[:MAX_COMPARE_EVENTS]:
            size = int(row['payload_bytes']) + 4096
            if size > DERIVED_DISPLAY_BYTES:
                # A single event over the display bound is never loaded; it is named and the cursor moves past it.
                derived['omitted_events'].append({'event_index': int(row['event_index']), 'event_id': row['event_id'],
                                                  'reason': 'over_display_bound', 'payload_bytes': int(row['payload_bytes'])})
            elif total + size > DERIVED_DISPLAY_BYTES:
                break
            else:
                total += size
                chosen.append(int(row['event_index']))
            consumed += 1
        if chosen:
            rows = db.rows('SELECT revision_id,event_id,schema_version,conversation_ref,observation_ref,origin,kind,role,source_seq,'
                           'event_index,parent_event_id,call_ref,result_ref,link_json,parse_status,linkage_status,coverage_status,'
                           'parser_version,payload FROM research_events FINAL WHERE ' + scope + ' AND event_index IN (' +
                           ','.join(str(index) for index in chosen) + ') ORDER BY event_index LIMIT ' + str(len(chosen)) +
                           ' SETTINGS max_threads=1')
            derived['events'] = [research._export_event(row) for row in rows]
        derived['truncated'] = consumed < len(sizes)
        derived['next_from_index'] = int(sizes[consumed]['event_index']) if derived['truncated'] else None
    return {'revision_id': revision_id, 'observation_ref': observation_ref, 'original': original, 'derived': derived,
            'annotations': annotations(revision_id, observation_ref)['current'],
            'note': 'The derived events are sanitised and typed; the original is restricted raw evidence. Neither establishes '
                    'a complete conversation.'}
