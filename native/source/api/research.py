"""Versioned curated research revision, publication gate and bounded exports."""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import signal
import threading
import time

import clickhouse as db
import conversations
import dedupe
from parsing import PARSER_VERSION, derive_events
from sanitise import (AssistedSpanDetector, DetectorCache, HoldError, Policy, PolicyError, SANITISER_VERSION,
                      Sanitizer, canonical)

SCHEMA_VERSION = 'research-event/2'
EXPORT_SCHEMA_URL = '/v1/research/schema'
CURSOR = re.compile(r'^[A-Za-z0-9_-]{20,2048}$')
REVISION_ID = re.compile(r'^rev_[a-f0-9]{16,64}$')
EVENT_ID = re.compile(r'^event_[a-f0-9]{16,64}$')
MAX_PAGE = 500


def _byte_limit(name, default, minimum, maximum):
    """Resolve a bounded byte limit from the environment.

    Observed Enterprise bodies reach several MiB, so the old fixed 2 MiB source
    and 512 KiB event ceilings held a measurable share of real records. The
    limits stay explicit and bounded rather than unbounded, and a malformed
    value fails fast instead of silently holding everything.
    """
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(name + ' must be an integer byte count') from None
    if not minimum <= value <= maximum:
        raise ValueError(name + ' must be between ' + str(minimum) + ' and ' + str(maximum))
    return value


def _seconds_limit(name, default, minimum, maximum):
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(name + ' must be an integer second count') from None
    if not minimum <= value <= maximum:
        raise ValueError(name + ' must be between ' + str(minimum) + ' and ' + str(maximum))
    return value


MAX_SOURCE_BYTES = _byte_limit('COPILOT_RESEARCH_MAX_SOURCE_BYTES', 8 * 1024 * 1024, 64 * 1024, 64 * 1024 * 1024)
MAX_EVENT_BYTES = _byte_limit('COPILOT_RESEARCH_MAX_EVENT_BYTES', 2 * 1024 * 1024, 16 * 1024, 16 * 1024 * 1024)
MAX_PAGE_BYTES = _byte_limit('COPILOT_RESEARCH_MAX_PAGE_BYTES', 8 * 1024 * 1024, 256 * 1024, 64 * 1024 * 1024)
MAX_RECORD_EVENT_BYTES = _byte_limit('COPILOT_RESEARCH_MAX_RECORD_EVENT_BYTES', 128 * 1024 * 1024,
                                     1024 * 1024, 256 * 1024 * 1024)
RECORD_WALL_BACKSTOP_FACTOR = 4
MAX_RECORD_SECONDS = _seconds_limit('COPILOT_RESEARCH_MAX_RECORD_SECONDS', 30, 1, 300)
if MAX_PAGE_BYTES < MAX_EVENT_BYTES:
    raise ValueError('COPILOT_RESEARCH_MAX_PAGE_BYTES must be at least COPILOT_RESEARCH_MAX_EVENT_BYTES')
if MAX_RECORD_EVENT_BYTES < MAX_EVENT_BYTES:
    raise ValueError('COPILOT_RESEARCH_MAX_RECORD_EVENT_BYTES must be at least COPILOT_RESEARCH_MAX_EVENT_BYTES')
MAX_EVENTS_PER_RECORD = 10000
MAX_ATTEMPTS = 3
LEGACY_PARSER_VERSION = 'unknown-legacy'
MEMBER_PAGE = 1000
EXCLUSION_REASONS = {
    'system_context', 'unsupported_attachment', 'private_context', 'reasoning_context', 'source_event_count_exceeded',
    'source_record_oversized', 'record_event_bytes_exceeded', 'source_member_missing', 'source_checksum_mismatch',
    'unsupported_provider_shape',
    'invalid_json', 'invalid_argument_fragment', 'invalid_choices_shape', 'invalid_choice_shape', 'invalid_delta_shape',
    'invalid_stream_frame', 'unrecognised_stream_assembly', 'unrecognised_stream_event', 'unsupported_anthropic_delta',
    'invalid_openai_content_delta', 'invalid_openai_function_fragment', 'invalid_openai_tool_calls_shape',
    'invalid_openai_function_call_shape', 'invalid_response_output_item', 'invalid_source_frame', 'empty_source_frame',
    'provider_truncated', 'source_summary_present', 'partial_stream', 'ambiguous_identity_field',
    'embedded_credential_container', 'detector_uncertain', 'detector_invalid_output', 'detector_invalid_span',
    'detector_output_too_large', 'detector_redirect_rejected', 'detector_unavailable', 'detector_overlapping_spans',
    'detector_entity_at_chunk_boundary', 'final_leak_check_alias', 'final_leak_check_credential',
    'final_leak_check_credential_field', 'final_leak_check_identifier', 'final_leak_check_original_value',
    'final_leak_check_path', 'unsupported_content', 'policy_withheld', 'processing_failure',
}
EXPORT_PAGE_SETTINGS = ' SETTINGS max_threads=1,max_block_size=1024'

EVENT_SCHEMA = {
    '$schema': 'https://json-schema.org/draft/2020-12/schema',
    '$id': EXPORT_SCHEMA_URL,
    'title': 'Copilot Traces research event',
    'description': 'One sanitised research event per JSONL line. Exact timestamps, original IDs and source data are not exported. Conversation coverage is unknown.',
    'type': 'object',
    'additionalProperties': False,
    'required': ['schema_version', 'revision_id', 'event_id', 'observation_ref', 'conversation_ref',
                 'observed_sequence', 'origin', 'kind', 'role', 'parent_event_id', 'call_ref', 'result_ref',
                 'parse_status', 'linkage_status', 'coverage_status', 'timing', 'parser_version', 'links', 'payload'],
    'properties': {
        'schema_version': {'const': SCHEMA_VERSION},
        'parser_version': {'type': 'string', 'pattern': '^[A-Za-z0-9._-]{1,64}$'},
        'revision_id': {'type': 'string', 'pattern': '^rev_[a-f0-9]{16,64}$'},
        'event_id': {'type': 'string', 'pattern': '^event_[a-f0-9]{16,64}$'},
        'observation_ref': {'type': 'string', 'pattern': '^obs_[a-f0-9]{16,64}$'},
        'conversation_ref': {'type': ['string', 'null'], 'pattern': '^conv_[a-f0-9]{16,64}$'},
        'observed_sequence': {'type': 'integer', 'minimum': 0},
        'origin': {'type': 'string', 'enum': ['history', 'output', 'source_stream', 'metadata']},
        'kind': {'type': 'string', 'enum': ['observation', 'message', 'tool_call', 'tool_result', 'tool_schema',
                 'response_meta', 'completion', 'error', 'source_frame', 'unsupported', 'withheld', 'empty',
                 'parse_error']},
        'role': {'enum': [None, 'system', 'developer', 'user', 'assistant', 'tool', 'function']},
        'parent_event_id': {'type': ['string', 'null'], 'pattern': '^event_[a-f0-9]{16,64}$'},
        'call_ref': {'type': ['string', 'null'], 'pattern': '^call_[a-f0-9]{16,64}$'},
        'result_ref': {'type': ['string', 'null'], 'pattern': '^result_[a-f0-9]{16,64}$'},
        'parse_status': {'type': 'string', 'enum': ['parsed', 'partial', 'invalid_json', 'empty', 'malformed', 'unsupported',
                         'incomplete', 'withheld', 'consecutive_json']},
        'linkage_status': {'type': 'string', 'enum': ['explicit', 'unknown', 'none']},
        'coverage_status': {'type': 'string', 'enum': ['observed', 'complete', 'unknown', 'partial', 'incomplete',
                           'unsupported', 'withheld']},
        'timing': {'type': 'object', 'additionalProperties': False,
                   'required': ['exact_timestamps_released', 'precision'],
                   'properties': {'exact_timestamps_released': {'const': False},
                                  'precision': {'const': 'withheld'}}},
        'link': {'type': ['object', 'null'], 'additionalProperties': False,
                 'properties': {'type': {'type': 'string'}, 'ref': {'type': 'string'},
                                'method': {'type': 'string'}, 'confidence': {'const': 'explicit'},
                                'raw_value_exported': {'const': False}}},
        'links': {'type': 'array', 'items': {'type': 'object'}},
        'payload': {'type': 'object', 'properties': {
            'content_repeat_of': {'type': ['string', 'null'], 'pattern': '^event_[a-f0-9]{16,64}$',
                                  'description': 'Optional revision-pinned sanitised-history equality annotation. Full payload retained; not provider message identity.'}}},
    },
}


class ConfigError(ValueError):
    pass


class _RecordDeadline(BaseException):
    # Do not let parser/detector handlers turn the interrupt into another
    # outcome or retry. Only the worker's record boundary catches it.
    pass


_BUDGET = {'active': False}


def _interrupt_record(signum, frame):
    # Disarm both timers before raising, and fire at most once per record: a
    # second, already pending signal, or one landing during cleanup, is ignored
    # instead of escaping teardown with the other timer still armed.
    if not _BUDGET['active']:
        return
    _BUDGET['active'] = False
    signal.setitimer(signal.ITIMER_REAL, 0)
    signal.setitimer(signal.ITIMER_PROF, 0)
    raise _RecordDeadline()


@contextmanager
def _record_time_budget():
    """Interrupt even CPython regex work in the serial POSIX worker.

    The budget counts CPU time (ITIMER_PROF): the research worker runs under a
    fractional CPU quota, so wall-clock time would hold records by host load
    while the revision identity stays the same. A wall-clock backstop of four
    times the budget still bounds blocking waits (an assisted-detector call).
    Only derivation is timed: disarm before event/status acknowledgements so an
    interrupt cannot leave partially published events or interrupt checkpointing.
    Refuse unsupported callers rather than silently running without a budget.
    """
    if threading.current_thread() is not threading.main_thread() or not hasattr(signal, 'setitimer'):
        raise ConfigError('Per-record time budget requires a POSIX main-thread worker')
    if (signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0) or
            signal.getitimer(signal.ITIMER_PROF) != (0.0, 0.0)):
        raise ConfigError('Per-record time budget requires unused real-time and profiling timers')
    previous_alarm = signal.signal(signal.SIGALRM, _interrupt_record)
    try:
        previous_prof = signal.signal(signal.SIGPROF, _interrupt_record)
        try:
            try:
                _BUDGET['active'] = True
                signal.setitimer(signal.ITIMER_PROF, MAX_RECORD_SECONDS)
                signal.setitimer(signal.ITIMER_REAL, MAX_RECORD_SECONDS * RECORD_WALL_BACKSTOP_FACTOR)
                yield
            finally:
                # From here the handler is a no-op; if a timer fired before this
                # line, the handler has already disarmed both.
                _BUDGET['active'] = False
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.setitimer(signal.ITIMER_PROF, 0)
        finally:
            signal.signal(signal.SIGPROF, previous_prof)
    finally:
        # A timer can fire while being cancelled; the previous handlers must
        # still come back.
        signal.signal(signal.SIGALRM, previous_alarm)


class ResearchConfig:
    """Load restricted policy/key and explicit operational settings."""

    def __init__(self, environ=None):
        env = os.environ if environ is None else environ
        self.api_key = env.get('COPILOT_RESEARCH_API_KEY', '')
        self.policy_file = env.get('COPILOT_RESEARCH_POLICY_FILE', '/run/research/research-policy.json')
        self.key_file = env.get('COPILOT_RESEARCH_PSEUDONYM_KEY_FILE', '/run/research/research-pseudonym-key')
        self.policy = None
        self.policy_error = None
        try:
            self.policy = Policy.load(self.policy_file, self.key_file)
        except PolicyError as failure:
            self.policy_error = str(failure)
        self.retention_raw = env.get('COPILOT_RESEARCH_RETENTION_RAW', '').strip()
        self.retention_curated = env.get('COPILOT_RESEARCH_RETENTION_CURATED', '').strip()
        self.release_setting = env.get('COPILOT_RESEARCH_RELEASE_SETTING', 'held').strip() or 'held'
        # Conversation identity is implemented and fixture-tested but off by
        # default: it has never run on real records. Opt in explicitly.
        self.identity_enabled = env.get('COPILOT_RESEARCH_IDENTITY_ENABLED', 'false').lower() == 'true'
        self.dedupe_enabled = env.get('COPILOT_RESEARCH_DEDUPE_ENABLED', 'false').lower() == 'true'
        self.detector = None
        self.detector_error = None
        policy_requires = bool(self.policy and self.policy.detector_enabled)
        env_enabled = env.get('COPILOT_RESEARCH_DETECTOR_ENABLED', 'false').lower() == 'true'
        approved = env.get('COPILOT_RESEARCH_DETECTOR_APPROVED', 'false').lower() == 'true'
        if policy_requires and not env_enabled:
            self.detector_error = 'detector_required_by_policy_but_disabled'
        elif env_enabled:
            if not policy_requires:
                self.detector_error = 'detector_not_enabled_by_policy'
            elif not approved:
                self.detector_error = 'detector_endpoint_not_approved'
            else:
                try:
                    endpoint = env.get('COPILOT_RESEARCH_DETECTOR_URL', '')
                    model = env.get('COPILOT_RESEARCH_DETECTOR_MODEL', '')
                    key_path = env.get('COPILOT_RESEARCH_DETECTOR_KEY_FILE', '')
                    key = Path(key_path).read_text().strip() if key_path else ''
                    self.detector = AssistedSpanDetector(endpoint, model, key, self.policy.detector_policy_version,
                                                         cache=DetectorCache(db))
                except (OSError, PolicyError):
                    self.detector_error = 'detector_configuration_invalid'
        self._sanitiser = None

    @property
    def sanitisation_available(self):
        return self.policy is not None and self.detector_error is None

    @property
    def detector_model(self):
        return self.detector.model if self.detector else 'disabled'

    def sanitiser(self):
        if not self.sanitisation_available:
            raise ConfigError('Restricted policy, pseudonym key or detector configuration is unavailable')
        if self._sanitiser is None:
            self._sanitiser = Sanitizer(self.policy, self.detector)
        return self._sanitiser

    def safe_status(self):
        return {
            'research_bearer_configured': len(self.api_key) >= 32,
            'policy_loaded': self.policy is not None,
            'policy_version': self.policy.version if self.policy else None,
            'policy_error': self.policy_error,
            'detector_enabled': self.detector is not None,
            'detector_model': self.detector_model,
            'detector_error': self.detector_error,
            'retention_raw': self.retention_raw or None,
            'retention_curated': self.retention_curated or None,
            'release_setting': self.release_setting,
            'identity_enabled': self.identity_enabled,
            'dedupe_enabled': self.dedupe_enabled,
            'release_blocked': self.release_blockers(),
            'limits': {'max_source_bytes': MAX_SOURCE_BYTES, 'max_event_bytes': MAX_EVENT_BYTES,
                       'max_record_event_bytes': MAX_RECORD_EVENT_BYTES, 'max_page_bytes': MAX_PAGE_BYTES,
                       'max_record_seconds': MAX_RECORD_SECONDS},
        }

    def release_blockers(self):
        blockers = []
        if self.policy is None:
            blockers.append('restricted_policy_or_pseudonym_key_missing')
        if self.detector_error:
            blockers.append(self.detector_error)
        if self.retention_raw != 'manual' or self.retention_curated != 'manual':
            blockers.append('explicit_manual_retention_not_configured')
        if self.release_setting != 'evaluated':
            blockers.append('release_setting_not_evaluated')
        return blockers


def now():
    return datetime.now(timezone.utc).isoformat()


def initialise():
    for ddl in (
        """CREATE TABLE IF NOT EXISTS research_revisions (
          revision_id String, created_at String, status LowCardinality(String),
          policy_version String, parser_version String, sanitiser_version String, schema_version String,
          detector_model String, detector_policy_version String, selection_max_seq UInt64,
          expected_records UInt64, membership_sha256 FixedString(64), processed_records UInt64,
          held_records UInt64, retry_pending_records UInt64, retry_exhausted_records UInt64, failed_records UInt64,
          event_count UInt64, conversation_count UInt64, complete UInt8, config_json String,
          updated_at String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY revision_id""",
        """CREATE TABLE IF NOT EXISTS research_processing (
          revision_id String, record_id FixedString(64), observation_ref String, pipeline_id String, status LowCardinality(String),
          failure_class String, event_count UInt64, attempt_count UInt8, retry_epoch UInt8, updated_at String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,record_id)""",
        """CREATE TABLE IF NOT EXISTS research_attempts (
          revision_id String, record_id FixedString(64), retry_epoch UInt8, attempt UInt8, outcome LowCardinality(String),
          failure_class String, updated_at String, version UInt64
        ) ENGINE=MergeTree ORDER BY (revision_id,record_id,attempt)""",
        """CREATE TABLE IF NOT EXISTS research_members (
          revision_id String, record_id FixedString(64), source_seq UInt64,
          content_sha256 FixedString(64), version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,source_seq,record_id)""",
        """CREATE TABLE IF NOT EXISTS research_events (
          revision_id String, event_id String, record_id FixedString(64), observation_ref String, conversation_ref String,
          schema_version String, pipeline_id String, source_seq UInt64, event_index UInt32, origin LowCardinality(String),
          kind LowCardinality(String), parser_version String, role String, parent_event_id String, call_ref String, result_ref String,
          link_json String, parse_status LowCardinality(String), linkage_status LowCardinality(String),
          coverage_status LowCardinality(String), observed_at String, payload String CODEC(ZSTD(3)),
          content_sha256 FixedString(64), version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,source_seq,event_index,event_id)""",
        """CREATE TABLE IF NOT EXISTS research_releases (
          revision_id String, status LowCardinality(String), released_at String, release_setting String,
          review_ack UInt8, policy_version String, parser_version String, schema_version String,
          detector_model String, detector_policy_version String, event_count UInt64, record_count UInt64,
          export_sha256 FixedString(64), manifest_json String,
          event_bytes_limit UInt64, page_bytes_limit UInt64, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY revision_id""",
        """CREATE TABLE IF NOT EXISTS research_detector_cache (
          cache_key String, model String, policy_version String, spans String,
          created_at String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY cache_key""",
    ):
        db.execute(ddl)
    db.execute('ALTER TABLE research_events ADD COLUMN IF NOT EXISTS conversation_ref String AFTER observation_ref')
    db.execute("ALTER TABLE research_events ADD COLUMN IF NOT EXISTS schema_version String DEFAULT 'research-event/1' AFTER conversation_ref")
    db.execute("ALTER TABLE research_events ADD COLUMN IF NOT EXISTS parser_version String DEFAULT '' AFTER kind")
    db.execute("ALTER TABLE research_revisions ADD COLUMN IF NOT EXISTS sanitiser_version String DEFAULT '' AFTER parser_version")
    db.execute("ALTER TABLE research_processing ADD COLUMN IF NOT EXISTS attempt_count UInt8 DEFAULT 0")
    db.execute("ALTER TABLE research_processing ADD COLUMN IF NOT EXISTS retry_epoch UInt8 DEFAULT 0")
    db.execute("ALTER TABLE research_processing ADD COLUMN IF NOT EXISTS observation_ref String DEFAULT '' AFTER record_id")
    db.execute('ALTER TABLE research_processing ADD COLUMN IF NOT EXISTS dedupe_eligible UInt8 DEFAULT 0')
    db.execute("ALTER TABLE research_attempts ADD COLUMN IF NOT EXISTS retry_epoch UInt8 DEFAULT 0")
    db.execute("ALTER TABLE research_revisions ADD COLUMN IF NOT EXISTS membership_sha256 FixedString(64) DEFAULT '' AFTER expected_records")
    db.execute('ALTER TABLE research_revisions ADD COLUMN IF NOT EXISTS pending_records UInt64 DEFAULT 0 AFTER membership_sha256')
    db.execute("ALTER TABLE research_revisions ADD COLUMN IF NOT EXISTS retry_pending_records UInt64 DEFAULT 0 AFTER held_records")
    db.execute("ALTER TABLE research_revisions ADD COLUMN IF NOT EXISTS retry_exhausted_records UInt64 DEFAULT 0 AFTER retry_pending_records")
    db.execute("ALTER TABLE research_releases ADD COLUMN IF NOT EXISTS event_bytes_limit UInt64 DEFAULT 0")
    db.execute("ALTER TABLE research_releases ADD COLUMN IF NOT EXISTS page_bytes_limit UInt64 DEFAULT 0")
    conversations.initialise()
    dedupe.initialise()


def _checkpoint(key, value=None):
    if value is not None:
        db.insert('checkpoints', [{'key': key, 'value': json.dumps(value), 'version': time.time_ns()}])
        return value
    rows = db.rows('SELECT value FROM checkpoints FINAL WHERE key=' + db.literal(key))
    return json.loads(rows[0]['value']) if rows else None


def _revision_row(revision_id):
    rows = db.rows('SELECT * EXCEPT version FROM research_revisions FINAL WHERE revision_id=' + db.literal(revision_id))
    return rows[0] if rows else None


def config_revision(config, selection_max_seq, membership_sha256=''):
    payload = {
        'schema_version': SCHEMA_VERSION, 'parser_version': PARSER_VERSION, 'sanitiser_version': SANITISER_VERSION,
        'policy_version': config.policy.version, 'policy_scope': config.policy.scope,
        'reference_scope_mode': config.policy.reference_scope_mode,
        'policy_fingerprint': config.policy.fingerprint,
        'key_fingerprint': __import__('hmac').new(config.policy.pseudonym_key, b'research-key-fingerprint', hashlib.sha256).hexdigest(),
        'detector_endpoint': config.detector.endpoint if config.detector else None,
        'detector_model': config.detector_model, 'detector_policy_version': config.policy.detector_policy_version,
        'selection_max_seq': int(selection_max_seq),
        'membership_sha256': membership_sha256,
        'identity_enabled': bool(getattr(config, 'identity_enabled', False)),
        'limits': {'max_source_bytes': MAX_SOURCE_BYTES, 'max_event_bytes': MAX_EVENT_BYTES,
                   'max_record_event_bytes': MAX_RECORD_EVENT_BYTES, 'max_page_bytes': MAX_PAGE_BYTES,
                   'max_record_seconds': MAX_RECORD_SECONDS},
    }
    # Off means exactly the old revision identity/export. Enabling annotations,
    # or changing their algorithm/budgets, requires a new immutable revision.
    if getattr(config, 'dedupe_enabled', False):
        payload['dedupe'] = dedupe.configuration(MAX_EVENT_BYTES, MAX_PAGE_BYTES)
    digest = hashlib.sha256(canonical(payload).encode()).hexdigest()
    return 'rev_' + digest[:32], payload


def _reset_retry_exhausted(revision_id):
    rows = db.rows('SELECT record_id,observation_ref,retry_epoch FROM research_processing FINAL WHERE revision_id=' +
                   db.literal(revision_id) + " AND status='retry_exhausted' ORDER BY record_id")
    for row in rows:
        db.insert('research_processing', [{
            'revision_id': revision_id, 'record_id': row['record_id'], 'observation_ref': row['observation_ref'],
            'pipeline_id': '', 'status': 'pending', 'failure_class': '', 'event_count': 0,
            'attempt_count': 0, 'retry_epoch': int(row.get('retry_epoch', 0)) + 1,
            'updated_at': now(), 'version': time.time_ns()}])


def create_revision(environ=None):
    config = ResearchConfig(environ)
    if not config.sanitisation_available:
        raise ConfigError('Sanitisation policy is unavailable; revision held')
    maximum = int(db.rows('SELECT ifNull(max(seq),0) AS seq FROM records FINAL')[0]['seq'])
    membership_sha256 = _source_membership_digest(maximum)
    revision_id, config_payload = config_revision(config, maximum, membership_sha256)
    existing = _revision_row(revision_id)
    if existing:
        if existing['status'] == 'incomplete':
            resetting = dict(existing)
            resetting.update(status='resetting', complete=0, updated_at=now(), version=time.time_ns())
            db.insert('research_revisions', [resetting])
            _reset_retry_exhausted(revision_id)
            _checkpoint('research_worker:' + revision_id, {'seq': 0, 'retry_at': now()})
            existing.update(status='deriving', complete=0, updated_at=now(), version=time.time_ns())
            db.insert('research_revisions', [existing])
            return _revision_row(revision_id)
        return existing
    expected = 0
    cursor = (0, '')
    while True:
        members = _source_members_page(maximum, cursor)
        if not members:
            break
        version = time.time_ns()
        db.insert('research_members', [{'revision_id': revision_id, 'record_id': member['id'],
                                       'source_seq': int(member['seq']), 'content_sha256': member['content_sha256'],
                                       'version': version + index} for index, member in enumerate(members)])
        refs = config.sanitiser().refs
        refs.bind_revision(revision_id)
        db.insert('research_processing', [{'revision_id': revision_id, 'record_id': member['id'],
                                          'observation_ref': refs.opaque('obs', member['id']),
                                          'pipeline_id': '', 'status': 'pending', 'failure_class': '',
                                          'event_count': 0, 'attempt_count': 0, 'retry_epoch': 0, 'updated_at': now(),
                                          'version': version + MEMBER_PAGE + index}
                                          for index, member in enumerate(members)])
        expected += len(members)
        cursor = (int(members[-1]['seq']), members[-1]['id'])
    if _source_membership_digest(maximum) != membership_sha256:
        raise HoldError('source_membership_changed_while_snapshotting')
    _checkpoint('research_worker:' + revision_id, {'seq': 0, 'updated_at': now()})
    row = {'revision_id': revision_id, 'created_at': now(), 'status': 'deriving',
           'policy_version': config.policy.version, 'parser_version': PARSER_VERSION, 'sanitiser_version': SANITISER_VERSION,
           'schema_version': SCHEMA_VERSION, 'detector_model': config.detector_model,
           'detector_policy_version': config.policy.detector_policy_version,
           'selection_max_seq': maximum, 'expected_records': expected, 'membership_sha256': membership_sha256,
           'pending_records': expected, 'processed_records': 0, 'held_records': 0, 'retry_pending_records': 0,
           'retry_exhausted_records': 0, 'failed_records': 0, 'event_count': 0, 'conversation_count': 0,
           'complete': 0, 'config_json': canonical(config_payload), 'updated_at': now(),
           'version': time.time_ns()}
    db.insert('research_revisions', [row])
    return _revision_row(revision_id)


def _source_members_page(maximum, cursor):
    sequence, identifier = cursor
    return db.rows('SELECT id,seq,content_sha256 FROM records FINAL WHERE seq<=' + str(int(maximum)) +
                   ' AND (seq>' + str(int(sequence)) + ' OR (seq=' + str(int(sequence)) +
                   ' AND id>' + db.literal(identifier) + ')) ORDER BY seq,id LIMIT ' + str(MEMBER_PAGE))


def _source_membership_digest(maximum):
    digest = hashlib.sha256()
    count, cursor = 0, (0, '')
    while True:
        rows = _source_members_page(maximum, cursor)
        if not rows:
            break
        for row in rows:
            digest.update(canonical([row['id'], int(row['seq']), row['content_sha256']]).encode())
            digest.update(b'\n')
        count += len(rows)
        cursor = (int(rows[-1]['seq']), rows[-1]['id'])
    return digest.hexdigest()


def _latest(statuses):
    placeholders = ','.join(db.literal(value) for value in statuses)
    rows = db.rows('SELECT * EXCEPT version FROM research_revisions FINAL WHERE status IN (' + placeholders + ') ORDER BY created_at DESC LIMIT 1')
    return rows[0] if rows else None


def _worker_revision(config, environ=None):
    resetting = _latest(['resetting'])
    if resetting:
        key = 'research_worker:' + resetting['revision_id']
        _reset_retry_exhausted(resetting['revision_id'])
        _checkpoint(key, {'seq': 0, 'retry_at': now()})
        resetting.update(status='deriving', complete=0, updated_at=now(), version=time.time_ns())
        db.insert('research_revisions', [resetting])
        return resetting
    revision = _latest(['deriving'])
    if revision:
        expected_id, _ = config_revision(config, revision['selection_max_seq'], revision['membership_sha256'])
        if expected_id == revision['revision_id']:
            return revision
        stale = dict(revision)
        stale.update(_live_dispositions([revision['revision_id']]).get(revision['revision_id'], {}))
        stale.update(status='incomplete', complete=0, updated_at=now(), version=time.time_ns())
        db.insert('research_revisions', [stale])
        return create_revision(environ)
    any_revision = _latest(['deriving', 'curated', 'incomplete', 'released', 'resetting'])
    if any_revision:
        return None
    return create_revision(environ)


def _event_rows(revision, config, record_row, parsed, sanitizer):
    refs = sanitizer.refs
    refs.bind_revision(revision['revision_id'])
    record_id = record_row['id']
    pipeline_id = hashlib.sha256((revision['revision_id'] + '\x00' + record_id + '\x00' +
                                  record_row['content_sha256'] + '\x00' + revision['config_json']).encode()).hexdigest()[:32]
    observation_ref = refs.opaque('obs', record_id)
    ids = []
    for event in parsed['events']:
        ids.append(refs.opaque('event', revision['revision_id'] + ':' + record_id + ':' + str(event['event_index'])))
    if len(parsed['events']) > MAX_EVENTS_PER_RECORD:
        raise HoldError('source_event_count_exceeded')
    # A Windows path anywhere in the record marks every event: the same person
    # or share can appear in another message without an extension.
    sanitizer.record_backslash_paths = any(sanitizer.holds_backslash_paths(event.get('payload') or {})
                                           for event in parsed['events'])
    try:
        return _sanitised_event_rows(revision, record_row, parsed, sanitizer, ids, observation_ref, pipeline_id,
                                     record_id, refs)
    finally:
        sanitizer.record_backslash_paths = False


def _sanitised_event_rows(revision, record_row, parsed, sanitizer, ids, observation_ref, pipeline_id, record_id, refs):
    rows = []
    total_event_bytes = 0
    for event in parsed['events']:
        source_frame_indexes = event.get('payload', {}).get('source_frame_event_indices', [])
        raw_payload = dict(event.get('payload') or {})
        raw_payload.pop('source_frame_event_indices', None)
        if source_frame_indexes:
            raw_payload['source_frame_refs'] = [ids[index] for index in source_frame_indexes
                                                if type(index) is int and 0 <= index < len(ids)]
        payload = sanitizer.payload(_policy_guard(raw_payload, event.get('role')),
                                    schema_fields=('parameters',) if event['kind'] == 'tool_schema' else ())
        parent = event.get('parent_event_local')
        parent_id = ids[parent] if parent is not None and 0 <= parent < len(ids) else None
        link = event.get('link')
        row = {
            'revision_id': revision['revision_id'], 'event_id': ids[event['event_index']],
            'record_id': record_id, 'observation_ref': observation_ref,
            'conversation_ref': parsed.get('conversation_ref') or '', 'schema_version': revision['schema_version'],
            'pipeline_id': pipeline_id,
            'source_seq': int(record_row['seq']), 'event_index': int(event['event_index']),
            'origin': event['origin'], 'kind': event['kind'], 'parser_version': PARSER_VERSION, 'role': event.get('role') or '',
            'parent_event_id': parent_id or '', 'call_ref': event.get('call_ref') or '',
            'result_ref': event.get('result_ref') or '',
            'link_json': canonical(parsed.get('links', []) if event['kind'] == 'observation' else ([link] if link else [])),
            'parse_status': event['parse_status'], 'linkage_status': event['linkage_status'],
            'coverage_status': event['coverage_status'], 'observed_at': datetime.fromtimestamp(
                int(record_row['timestamp']) / 1000, timezone.utc).isoformat(),
            'payload': canonical(payload), 'content_sha256': hashlib.sha256(canonical(payload).encode()).hexdigest(),
            'version': time.time_ns(),
        }
        encoded = canonical(row).encode()
        # Reserve the fixed HMAC width for post-derivation identity resolution.
        size = len(encoded) + (29 if not row['conversation_ref'] else 0)
        if event['kind'] == 'observation' and row['linkage_status'] == 'unknown':
            size += 1  # 'explicit' is one byte longer than 'unknown'.
        if size > MAX_EVENT_BYTES:
            raise HoldError('sanitised_event_oversized')
        total_event_bytes += size
        if total_event_bytes > MAX_RECORD_EVENT_BYTES:
            # Bounded per-record output: hold explicitly instead of risking the
            # worker's memory limit when one large source yields many events.
            raise HoldError('record_event_bytes_exceeded')
        rows.append(row)
    return rows, pipeline_id


def _policy_guard(value, inherited_role=None):
    """One recursive exclusion boundary for all provider parser routes."""
    if inherited_role in ('system', 'developer'):
        return {'withheld': True, 'reason': 'system_context'}
    if isinstance(value, list):
        return [_policy_guard(item, inherited_role) for item in value]
    if not isinstance(value, dict):
        return value
    role = value.get('role', inherited_role)
    if role in ('system', 'developer'):
        return {'withheld': True, 'reason': 'system_context'}
    kind = str(value.get('type') or '').lower()
    if kind in {'image', 'image_url', 'input_image', 'document', 'audio', 'file', 'attachment',
                'thinking', 'reasoning', 'redacted_thinking', 'signature', 'encrypted_content'}:
        return {'withheld': True, 'reason': 'unsupported_attachment' if kind in
                {'image', 'image_url', 'input_image', 'document', 'audio', 'file', 'attachment'}
                else 'private_context'}
    private_keys = {'document', 'attachment', 'image', 'audio', 'instructions',
                    'system', 'thinking', 'reasoning', 'signature', 'encrypted_content', 'redacted_thinking'}
    return {key: ({'withheld': True, 'reason': 'unsupported_attachment'} if str(key).lower() in private_keys
                  else _policy_guard(item, role)) for key, item in value.items()}


def process_once(environ=None, page_size=10):
    config = ResearchConfig(environ)
    if not config.sanitisation_available:
        return {'status': 'held', 'reason': config.policy_error or config.detector_error}
    revision = _worker_revision(config, environ)
    if not revision:
        return {'status': 'idle', 'reason': 'no deriving revision'}
    revision_id = revision['revision_id']
    key = 'research_worker:' + revision_id
    state = _checkpoint(key) or {'seq': 0}
    rows = []
    if not state.get('conversation'):
        # Claim members without touching records: joining the content column
        # here forces a full read and exceeds the database's per-query budget.
        rows = db.rows('SELECT m.record_id AS id,m.source_seq AS seq,m.content_sha256 AS expected_sha256 '
                       'FROM research_members AS m FINAL WHERE m.revision_id=' + db.literal(revision_id) +
                       " AND m.record_id NOT IN (SELECT record_id FROM research_processing FINAL "
                       "WHERE revision_id=" + db.literal(revision_id) + " AND status IN ('processed','held','failed','retry_exhausted')) "
                       'ORDER BY m.source_seq,m.record_id LIMIT ' + str(max(1, min(int(page_size), 100))))
    if not rows:
        if getattr(config, 'identity_enabled', False):
            for _ in range(max(1, min(int(page_size), 100))):
                if _conversation_step(revision, state):
                    break
                state = _checkpoint(key) or state
            else:
                return {'status': 'processed', 'stage': 'conversation_identity', 'revision_id': revision_id}
        if getattr(config, 'dedupe_enabled', False):
            for _ in range(max(1, min(int(page_size), 100))):
                if dedupe.step(revision, _checkpoint):
                    break
            else:
                return {'status': 'processed', 'stage': 'content_repeat_annotations', 'revision_id': revision_id}
        return _finalise(revision, config)
    sanitiser = config.sanitiser()
    sanitiser.refs.bind_revision(revision_id)
    for meta in rows:
        observation_ref = sanitiser.refs.opaque('obs', meta['id'])
        retry_state = db.rows('SELECT attempt_count,retry_epoch FROM research_processing FINAL WHERE revision_id=' +
                              db.literal(revision_id) + ' AND record_id=' + db.literal(meta['id']))
        retry_state = retry_state[0] if retry_state else {'attempt_count': 0, 'retry_epoch': 0}
        attempt_count = int(retry_state.get('attempt_count', 0))
        retry_epoch = int(retry_state.get('retry_epoch', 0))
        size_rows = db.rows('SELECT length(record_json) AS bytes FROM records FINAL PREWHERE id=' +
                            db.literal(meta['id']) + ' SETTINGS max_threads=1,max_block_size=1')
        if size_rows and int(size_rows[0].get('bytes') or 0) > MAX_SOURCE_BYTES:
            _save_status(revision_id, meta['id'], 'held', 'source_record_oversized', 0, '', 0, observation_ref, retry_epoch)
            _checkpoint(key, {'seq': int(meta['seq']), 'updated_at': now()})
            continue
        record_rows = db.rows('SELECT id,seq,event_id,user_id,timestamp,type,request_id,endpoint,content_sha256,record_json '
                              'FROM records FINAL PREWHERE id=' + db.literal(meta['id']) +
                              ' SETTINGS max_threads=1,max_block_size=1')
        if not record_rows:
            _save_status(revision_id, meta['id'], 'failed', 'source_member_missing', 0, '', 0, observation_ref, retry_epoch)
            _checkpoint(key, {'seq': int(meta['seq']), 'updated_at': now()})
            continue
        record_row = record_rows[0]
        source_bytes = record_row['record_json'].encode('utf-8')
        if len(source_bytes) > MAX_SOURCE_BYTES:
            _save_status(revision_id, record_row['id'], 'held', 'source_record_oversized', 0, '', 0, observation_ref, retry_epoch)
            _checkpoint(key, {'seq': int(record_row['seq']), 'updated_at': now()})
            continue
        if (hashlib.sha256(source_bytes).hexdigest() != record_row['content_sha256'] or
                record_row['content_sha256'] != meta['expected_sha256']):
            _save_status(revision_id, record_row['id'], 'failed', 'source_checksum_mismatch', 0, '', 0, observation_ref, retry_epoch)
            _checkpoint(key, {'seq': int(record_row['seq']), 'updated_at': now()})
            continue
        try:
            with _record_time_budget():
                record = json.loads(record_row['record_json'])
                sanitiser.refs.bind_revision(revision_id)
                # Prefer the stored column: source bodies are not guaranteed to
                # carry user_id, and a mismatched scope silently breaks identity.
                identity_user = record_row.get('user_id')
                if identity_user is None:
                    identity_user = record.get('user_id', '')
                sanitiser.refs.identity_scope = str(identity_user)
                parsed = derive_events(record, sanitiser.refs)
                event_rows, pipeline_id = _event_rows(revision, config, record_row, parsed, sanitiser)
                if not event_rows:
                    raise HoldError('no_events_derived')
            db.insert('research_events', event_rows)
            if getattr(config, 'identity_enabled', False):
                conversations.register(revision_id, record_row, parsed, pipeline_id, sanitiser.refs)
            _save_status(revision_id, record_row['id'], 'processed', '', len(event_rows), pipeline_id, attempt_count,
                         observation_ref, retry_epoch, dedupe_eligible=(
                             int(dedupe.eligible_observation(parsed)) if getattr(config, 'dedupe_enabled', False) else None))
        except _RecordDeadline:
            # The signal may arrive during a pre-scan before the sanitizer's
            # own try/finally starts. Do not carry record-local flags onward.
            sanitiser.record_backslash_paths = False
            sanitiser.refs.recording = False
            _save_status(revision_id, record_row['id'], 'held', 'record_time_budget_exceeded', 0, '', 0,
                         observation_ref, retry_epoch)
        except HoldError as failure:
            _save_status(revision_id, record_row['id'], 'held', failure.reason, 0, '', 0, observation_ref, retry_epoch)
        except ConfigError:
            raise
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            _save_status(revision_id, record_row['id'], 'held', 'unsupported_provider_shape', 0, '', 1, observation_ref, retry_epoch)
        except Exception as failure:
            if isinstance(failure, OSError):
                attempt = attempt_count + 1
                outcome = 'retry_exhausted' if attempt >= MAX_ATTEMPTS else 'retry_pending'
                _save_status(revision_id, record_row['id'], outcome, 'storage_or_cache_unavailable', 0, '', attempt,
                             observation_ref, retry_epoch)
                db.insert('research_attempts', [{'revision_id': revision_id, 'record_id': record_row['id'],
                           'retry_epoch': retry_epoch, 'attempt': attempt, 'outcome': outcome,
                           'failure_class': 'storage_or_cache_unavailable',
                           'updated_at': now(), 'version': time.time_ns()}])
                if outcome == 'retry_pending':
                    return {'status': outcome, 'revision_id': revision_id, 'records': int(meta['seq'])}
            else:
                _save_status(revision_id, record_row['id'], 'failed', 'processing_' + type(failure).__name__.lower(),
                             0, '', 1, observation_ref, retry_epoch)
        _checkpoint(key, {'seq': int(record_row['seq']), 'updated_at': now()})
    return {'status': 'processed', 'revision_id': revision_id, 'records': len(rows)}


def _conversation_step(revision, state):
    """One bounded graph edge or observation rewrite per checkpointed step."""
    progress = dict(state.get('conversation') or {'phase': 'reconcile', 'cursor': [0, ''], 'changed': False})
    if progress['phase'] == 'done':
        return True
    if not progress.get('run'):
        # One label generation per reconciliation pass. Persist it before any
        # label write so a restart resumes the same generation.
        progress['run'] = 'convrun_' + secrets.token_hex(8)
        _checkpoint('research_worker:' + revision['revision_id'], {**state, 'conversation': progress})
    run = progress['run']
    rows = conversations.next_record(revision['revision_id'], progress['cursor'])
    if rows:
        entry = rows[0]
        if conversations.current(entry):
            if progress['phase'] == 'reconcile':
                # Persist the dirty bit BEFORE label writes. A crash after an
                # acknowledged write must not skip another propagation pass.
                progress['changed'] = True
                _checkpoint('research_worker:' + revision['revision_id'], {**state, 'conversation': progress})
                changed = conversations.reconcile(entry, run)
                progress['changed'] = bool(state.get('conversation', {}).get('changed') or changed)
            else:
                _apply_conversation(revision, entry, conversations.conversation_for(entry, run))
        progress['cursor'] = [int(entry['source_seq']), entry['record_id']]
    elif progress['phase'] == 'reconcile':
        progress.update(phase='reconcile' if progress['changed'] else 'apply', cursor=[0, ''], changed=False)
    else:
        progress['phase'] = 'done'
    _checkpoint('research_worker:' + revision['revision_id'], {**state, 'conversation': progress})
    return progress['phase'] == 'done'


def _apply_conversation(revision, entry, conversation_ref):
    # Compare against the stored rows rather than the parsed explicit ref. A
    # later pass can decide a record should be unlinked, and the old early
    # return on '' == '' left the previously written conversation in place.
    target = conversation_ref or ''
    rows = db.rows('SELECT * FROM research_events FINAL WHERE revision_id=' + db.literal(revision['revision_id']) +
                   ' AND source_seq=' + str(int(entry['source_seq'])) + ' AND record_id=' + db.literal(entry['record_id']) +
                   ' AND pipeline_id=' + db.literal(entry['pipeline_id']) + ' ORDER BY event_index LIMIT ' +
                   str(MAX_EVENTS_PER_RECORD + 1) + ' SETTINGS max_threads=1,max_block_size=1,max_result_bytes=' +
                   str(MAX_RECORD_EVENT_BYTES + MAX_EVENTS_PER_RECORD * 1024) + ",result_overflow_mode='throw'")
    if not rows or len(rows) > MAX_EVENTS_PER_RECORD:
        raise ConfigError('Conversation event rewrite is missing or over budget')
    total = 0
    changed = []
    for row in rows:
        linkage = row['linkage_status']
        if row['kind'] == 'observation':
            linkage = 'explicit' if target else 'unknown'
        if (row['conversation_ref'] or '') == target and linkage == row['linkage_status']:
            continue
        row['conversation_ref'] = target
        row['linkage_status'] = linkage
        row['version'] = time.time_ns()
        size = len(canonical(row).encode())
        total += size
        if size > MAX_EVENT_BYTES or total > MAX_RECORD_EVENT_BYTES:
            # Stop finalisation; do not publish partially rewritten observations.
            raise ConfigError('Conversation event rewrite exceeds derivation budget')
        changed.append(row)
    if changed:
        db.insert('research_events', changed)


def _save_status(revision_id, record_id, status, failure_class, event_count, pipeline_id, attempt_count,
                 observation_ref, retry_epoch=0, dedupe_eligible=None):
    row = {
        'revision_id': revision_id, 'record_id': record_id, 'observation_ref': observation_ref,
        'pipeline_id': pipeline_id, 'status': status,
        'failure_class': failure_class, 'event_count': int(event_count), 'attempt_count': attempt_count,
        'retry_epoch': retry_epoch, 'updated_at': now(),
        'version': time.time_ns()}
    if dedupe_eligible is not None:
        row['dedupe_eligible'] = int(dedupe_eligible)
    db.insert('research_processing', [row])


def _counts(revision_id):
    grouped = {row['status']: row for row in db.rows(
        'SELECT status,count() AS records,sum(event_count) AS events FROM research_processing FINAL WHERE revision_id=' +
        db.literal(revision_id) + ' GROUP BY status')}
    processed = int(grouped.get('processed', {}).get('records', 0))
    held = int(grouped.get('held', {}).get('records', 0))
    retry_pending = int(grouped.get('retry_pending', {}).get('records', 0))
    retry_exhausted = int(grouped.get('retry_exhausted', {}).get('records', 0))
    pending = int(grouped.get('pending', {}).get('records', 0))
    failed = int(grouped.get('failed', {}).get('records', 0))
    events = int(grouped.get('processed', {}).get('events', 0))
    conversations = int(db.rows('SELECT uniqExactIf(e.conversation_ref,e.conversation_ref!=\'\') AS c '
                               'FROM (SELECT * FROM research_events FINAL WHERE revision_id=' + db.literal(revision_id) +
                               ') AS e INNER JOIN (SELECT record_id,pipeline_id FROM research_processing FINAL WHERE revision_id=' +
                               db.literal(revision_id) + " AND status='processed') AS p ON e.record_id=p.record_id "
                               'AND e.pipeline_id=p.pipeline_id')[0]['c'])
    return {'pending_records': pending, 'processed_records': processed, 'held_records': held, 'retry_pending_records': retry_pending,
            'retry_exhausted_records': retry_exhausted, 'failed_records': failed,
            'event_count': events, 'conversation_count': conversations}


def _finalise(revision, config):
    revision_id = revision['revision_id']
    counts = _counts(revision_id)
    expected = int(revision['expected_records'])
    total = sum(counts[key] for key in ('pending_records', 'processed_records', 'held_records', 'retry_pending_records',
                                        'retry_exhausted_records', 'failed_records'))
    complete = 1 if total == expected and not any(counts[key] for key in
                ('pending_records', 'retry_pending_records', 'retry_exhausted_records', 'failed_records')) else 0
    status = 'curated' if complete else 'incomplete'
    row = dict(revision)
    row.update(counts, status=status, complete=complete, updated_at=now(), version=time.time_ns())
    row.setdefault('sanitiser_version', '')
    db.insert('research_revisions', [{key: row[key] for key in (
        'revision_id', 'created_at', 'status', 'policy_version', 'parser_version', 'sanitiser_version', 'schema_version',
        'detector_model', 'detector_policy_version', 'selection_max_seq', 'expected_records',
        'pending_records', 'processed_records', 'held_records', 'retry_pending_records', 'retry_exhausted_records',
        'failed_records', 'membership_sha256', 'event_count', 'conversation_count',
        'complete', 'config_json', 'updated_at', 'version')}])
    _checkpoint('research_worker:' + revision_id, {'seq': int(revision['selection_max_seq']),
                'finalized_at': now(), 'complete': complete})
    return {'status': 'finalised', 'revision_id': revision_id, 'complete': complete, **counts}


def _release_row(revision_id):
    rows = db.rows('SELECT * EXCEPT version FROM research_releases FINAL WHERE revision_id=' + db.literal(revision_id) +
                   " AND status='released'")
    return rows[0] if rows else None


def _verify_membership(revision):
    digest = hashlib.sha256()
    count, cursor = 0, (0, '')
    while True:
        members = db.rows('SELECT m.record_id,m.source_seq,m.content_sha256,r.content_sha256 AS current_sha256,'
                          'lower(hex(SHA256(r.record_json))) AS body_sha256 '
                          'FROM research_members AS m FINAL LEFT JOIN records AS r FINAL ON r.id=m.record_id '
                          'WHERE m.revision_id=' + db.literal(revision['revision_id']) + ' AND '
                          '(m.source_seq>' + str(cursor[0]) + ' OR (m.source_seq=' + str(cursor[0]) +
                          ' AND m.record_id>' + db.literal(cursor[1]) + ')) '
                          'ORDER BY m.source_seq,m.record_id LIMIT ' + str(MEMBER_PAGE))
        if not members:
            break
        for row in members:
            digest.update(canonical([row['record_id'], int(row['source_seq']), row['content_sha256']]).encode())
            digest.update(b'\n')
            if (not row.get('current_sha256') or row['current_sha256'] != row['content_sha256'] or
                    row.get('body_sha256') != row['content_sha256']):
                raise HoldError('source_membership_or_checksum_changed')
        count += len(members)
        cursor = (int(members[-1]['source_seq']), members[-1]['record_id'])
    if count != int(revision['expected_records']) or digest.hexdigest() != revision['membership_sha256']:
        raise HoldError('source_membership_or_checksum_changed')
    disposition = db.rows('SELECT count() AS n FROM research_processing FINAL WHERE revision_id=' +
                          db.literal(revision['revision_id']))
    unmatched = db.rows('SELECT count() AS n FROM research_members AS m FINAL LEFT JOIN research_processing AS p FINAL '
                        'ON p.revision_id=m.revision_id AND p.record_id=m.record_id WHERE m.revision_id=' +
                        db.literal(revision['revision_id']) + " AND p.record_id=''")
    orphan_dispositions = db.rows('SELECT count() AS n FROM research_processing AS p FINAL LEFT JOIN research_members AS m FINAL '
                                  'ON m.revision_id=p.revision_id AND m.record_id=p.record_id WHERE p.revision_id=' +
                                  db.literal(revision['revision_id']) + " AND m.record_id=''")
    if (int(disposition[0]['n']) != count or int(unmatched[0]['n']) or int(orphan_dispositions[0]['n'])):
        raise HoldError('source_disposition_membership_mismatch')
    mismatch = db.rows('SELECT count() AS n FROM (SELECT p.record_id,p.event_count,count(e.event_id) AS actual '
                        'FROM research_processing AS p FINAL LEFT JOIN research_events AS e FINAL '
                        'ON e.revision_id=p.revision_id AND e.record_id=p.record_id AND e.pipeline_id=p.pipeline_id '
                        'WHERE p.revision_id=' + db.literal(revision['revision_id']) + " AND p.status='processed' "
                        'GROUP BY p.record_id,p.event_count HAVING p.event_count!=actual)')
    if int(mismatch[0]['n']):
        raise HoldError('processed_event_count_mismatch')
    orphaned = db.rows('SELECT count() AS n FROM research_events AS e FINAL LEFT JOIN research_processing AS p FINAL '
                       'ON p.revision_id=e.revision_id AND p.record_id=e.record_id '
                       "WHERE e.revision_id=" + db.literal(revision['revision_id']) + " AND p.record_id=''")
    if int(orphaned[0]['n']):
        raise HoldError('orphan_research_events')
    superseded = db.rows('SELECT count() AS n FROM research_events AS e FINAL INNER JOIN research_processing AS p FINAL '
                         'ON p.revision_id=e.revision_id AND p.record_id=e.record_id '
                         'WHERE e.revision_id=' + db.literal(revision['revision_id']) +
                         " AND (p.status!='processed' OR p.pipeline_id!=e.pipeline_id)")
    return {'superseded_event_rows': int(superseded[0]['n'])}


def release_revision(revision_id, acknowledge_review, environ=None):
    if not REVISION_ID.fullmatch(str(revision_id)):
        raise ValueError('Invalid revision')
    config = ResearchConfig(environ)
    blockers = config.release_blockers()
    if blockers:
        raise HoldError('release_blocked:' + ','.join(blockers))
    if acknowledge_review is not True:
        raise HoldError('release_review_not_acknowledged')
    revision = _revision_row(revision_id)
    if not revision:
        raise LookupError('Revision not found')
    if int(revision['complete']) != 1 or revision['status'] != 'curated':
        raise HoldError('revision_not_complete')
    if int(revision['failed_records']) != 0:
        raise HoldError('revision_has_processing_failures')
    if int(revision.get('pending_records', 0)) or int(revision.get('retry_pending_records', 0)) or int(revision.get('retry_exhausted_records', 0)):
        raise HoldError('revision_has_retry_work')
    integrity = _verify_membership(revision)
    if int(revision['expected_records']) == 0 or int(revision['processed_records']) == 0 or int(revision['event_count']) == 0:
        raise HoldError('revision_empty')
    if int(revision['event_count']) != _counts(revision_id)['event_count']:
        raise HoldError('revision_event_count_mismatch')
    expected_id, _ = config_revision(config, revision['selection_max_seq'], revision['membership_sha256'])
    if expected_id != revision_id:
        raise HoldError('revision_configuration_changed')
    if config.detector_model != revision['detector_model']:
        raise HoldError('detector_configuration_changed')
    if _release_row(revision_id):
        return _release_row(revision_id)
    manifest = _build_manifest(revision, config, integrity['superseded_event_rows'])
    digest = hashlib.sha256(canonical(manifest).encode()).hexdigest()
    row = {'revision_id': revision_id, 'status': 'released', 'released_at': now(),
           'release_setting': config.release_setting, 'review_ack': 1,
           'policy_version': revision['policy_version'], 'parser_version': revision['parser_version'],
           'schema_version': revision['schema_version'], 'detector_model': revision['detector_model'],
           'detector_policy_version': revision['detector_policy_version'],
           'event_count': int(revision['event_count']), 'record_count': int(revision['processed_records']),
           'export_sha256': manifest['export_sha256'], 'manifest_json': canonical(manifest),
           'event_bytes_limit': MAX_EVENT_BYTES, 'page_bytes_limit': MAX_PAGE_BYTES, 'version': time.time_ns()}
    db.insert('research_releases', [row])
    return _release_row(revision_id)


def _export_query(revision_id, cursor=None, limit=MAX_PAGE, metadata=False, annotate=False):
    where = 'revision_id=' + db.literal(revision_id)
    if cursor:
        where += (' AND (source_seq,event_index,event_id)>(' + str(cursor['s']) + ',' +
                  str(cursor['i']) + ',' + db.literal(cursor['e']) + ')')
    select = ('e.event_id,length(e.payload) AS payload_bytes,'
              "JSONExtractRaw(rv.config_json,'dedupe') AS dedupe_config_json" if metadata else
              'e.revision_id AS revision_id,e.event_id,e.schema_version,e.conversation_ref,e.observation_ref,e.origin,e.kind,e.role,e.source_seq,'
              'e.event_index,e.parent_event_id,e.call_ref,e.result_ref,e.link_json,e.parse_status,e.linkage_status,'
              'e.coverage_status,if(e.parser_version=\'\',rv.parser_version,e.parser_version) AS parser_version,e.payload')
    if annotate:
        # Explicit aliases: the joined subquery has columns of the same names,
        # and ClickHouse would otherwise return them as 'e.record_id'.
        select += (',e.record_id AS record_id,e.pipeline_id AS pipeline_id,e.content_sha256 AS content_sha256,'
                   "JSONExtractString(rv.config_json,'dedupe','algorithm_version') AS dedupe_version,"
                   "JSONExtractRaw(rv.config_json,'dedupe') AS dedupe_config_json")
    return ('SELECT ' + select + ' FROM (SELECT revision_id,event_id,schema_version,conversation_ref,observation_ref,origin,kind,'
            'role,source_seq,event_index,parent_event_id,call_ref,result_ref,link_json,parse_status,linkage_status,'
            'coverage_status,parser_version,payload,record_id,pipeline_id' + (',content_sha256' if annotate else '') +
            ' FROM research_events FINAL WHERE ' + where +
            ') AS e INNER JOIN (SELECT record_id,pipeline_id FROM research_processing FINAL WHERE revision_id=' +
            db.literal(revision_id) + " AND status='processed') AS p ON e.record_id=p.record_id AND e.pipeline_id=p.pipeline_id "
            'INNER JOIN (SELECT revision_id,parser_version' + (',config_json' if metadata or annotate else '') +
            ' FROM research_revisions FINAL) AS rv ON e.revision_id=rv.revision_id'
            ' ORDER BY e.source_seq,e.event_index,e.event_id LIMIT ' + str(limit) + EXPORT_PAGE_SETTINGS)


def _export_event(row):
    links = json.loads(row['link_json']) if row['link_json'] else []
    if isinstance(links, dict): links = [links]
    link = links[0] if links else None
    payload = json.loads(row['payload'])
    if dedupe.FIELD in row:
        payload[dedupe.FIELD] = row[dedupe.FIELD]
    return {
        'schema_version': row.get('schema_version') or 'research-event/1',
        'parser_version': row.get('parser_version') or row.get('revision_parser_version') or LEGACY_PARSER_VERSION,
        'revision_id': row['revision_id'],
        'event_id': row['event_id'], 'observation_ref': row['observation_ref'],
        'conversation_ref': row['conversation_ref'] or None,
        'observed_sequence': int(row['source_seq']) * 1000000 + int(row['event_index']),
        'origin': row['origin'], 'kind': row['kind'], 'role': row['role'] or None,
        'parent_event_id': row['parent_event_id'] or None,
        'call_ref': row['call_ref'] or None, 'result_ref': row['result_ref'] or None,
        'parse_status': row['parse_status'], 'linkage_status': row['linkage_status'],
        'coverage_status': row['coverage_status'],
        'timing': {'exact_timestamps_released': False, 'precision': 'withheld'},
        'link': link, 'links': links, 'payload': payload,
    }


def jsonl_bytes(events):
    return b''.join((json.dumps(event, ensure_ascii=False, allow_nan=False, separators=(',', ':')) + '\n').encode('utf-8')
                    for event in events)


def _cursor_key(environ=None):
    config = ResearchConfig(environ)
    if config.policy is None:
        raise ConfigError('Restricted policy/key is unavailable; export held')
    return config.policy.pseudonym_key


def _encode_cursor(revision_id, row, key):
    body = {'r': revision_id, 's': int(row['source_seq']), 'i': int(row['event_index']), 'e': row['event_id']}
    body['m'] = hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()[:32]
    return base64.urlsafe_b64encode(canonical(body).encode()).decode().rstrip('=')


def _decode_cursor(value, revision_id, key):
    if value is None:
        return None
    if not CURSOR.fullmatch(value):
        raise ValueError('Invalid cursor')
    try:
        padded = value + '=' * (-len(value) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if (not isinstance(data, dict) or set(data) != {'r', 's', 'i', 'e', 'm'} or
                data.get('r') != revision_id or type(data.get('s')) is not int or
                type(data.get('i')) is not int or not EVENT_ID.fullmatch(str(data.get('e'))) or
                not isinstance(data.get('m'), str)):
            raise ValueError
        body = {name: data[name] for name in ('r', 's', 'i', 'e')}
        expected = hmac.new(key, canonical(body).encode(), hashlib.sha256).hexdigest()[:32]
        if not hmac.compare_digest(expected, data['m']):
            raise ValueError
        return body
    except (ValueError, TypeError, json.JSONDecodeError):
        raise ValueError('Invalid cursor') from None


# Budgets in force before limits became configurable, for releases that predate
# pinning and whose revision config records none.
LEGACY_EVENT_BYTES = 512 * 1024
LEGACY_PAGE_BYTES = 4 * 1024 * 1024


def _release_limits(release):
    """Budgets the revision was derived and released under, never today's config."""
    try:
        event = int(release.get('event_bytes_limit') or 0)
        page = int(release.get('page_bytes_limit') or 0)
    except (TypeError, ValueError):
        event = page = 0
    if event and page:
        return event, page
    limits = {}
    revision_id = str(release.get('revision_id') or '')
    if REVISION_ID.fullmatch(revision_id):
        revision = _revision_row(revision_id)
        try:
            limits = (json.loads((revision or {}).get('config_json') or '{}').get('limits') or {})
        except (ValueError, TypeError):
            limits = {}

    def pick(name, fallback):
        try:
            return int(limits.get(name) or 0) or fallback
        except (TypeError, ValueError):
            return fallback

    return (event or pick('max_event_bytes', LEGACY_EVENT_BYTES),
            page or pick('max_page_bytes', LEGACY_PAGE_BYTES))


def _bounded_rows(revision_id, cursor, limit, event_limit=MAX_EVENT_BYTES, page_limit=MAX_PAGE_BYTES):
    metadata = db.rows(_export_query(revision_id, cursor, limit + 1, metadata=True))
    count, total = 0, 0
    for row in metadata[:limit]:
        size = int(row['payload_bytes']) + 4096  # Envelope overhead, not source content.
        if size > event_limit + 4096:
            raise HoldError('stored_event_oversized')
        # Always emit at least one event per page. A page budget smaller than a
        # single event would otherwise return zero rows and break the cursor.
        if total + size > page_limit and count:
            break
        total += size
        count += 1
    active = any(row.get('dedupe_config_json') for row in metadata[:count])
    rows = db.rows(_export_query(revision_id, cursor, count, annotate=active)) if count else []
    if len(rows) != count:
        raise OSError('Pinned research rows unavailable')
    dedupe.annotate(rows, _checkpoint)
    return rows, len(metadata) > count


def export_page(revision_id, cursor=None, limit=MAX_PAGE):
    if not REVISION_ID.fullmatch(str(revision_id)):
        raise ValueError('Invalid revision')
    if type(limit) is not int or not 1 <= limit <= MAX_PAGE:
        raise ValueError('Invalid page size')
    release = _release_row(revision_id)
    if not release:
        raise HoldError('revision_not_released')
    key = _cursor_key()
    decoded = _decode_cursor(cursor, revision_id, key)
    rows, more = _bounded_rows(revision_id, decoded, limit, *_release_limits(release))
    events = [_export_event(row) for row in rows]
    body = jsonl_bytes(events)
    page = {'revision_id': revision_id, 'events': events, 'event_count': len(events),
            'page_sha256': hashlib.sha256(body).hexdigest(), 'next_cursor': _encode_cursor(revision_id, rows[-1], key) if more else None,
            'complete': not more}
    if not more:
        release = _release_row(revision_id)
        page['manifest_sha256'] = hashlib.sha256(release['manifest_json'].encode()).hexdigest()
        page['manifest_url'] = '/v1/research/manifest?revision=' + revision_id
    return page, body


def export_jsonl(revision_id, cursor=None, limit=MAX_PAGE, compress=False):
    page, body = export_page(revision_id, cursor, limit)
    if compress:
        body = gzip.compress(body, mtime=0)
        content_type = 'application/gzip'
    else:
        content_type = 'application/x-ndjson; charset=utf-8'
    headers = {'X-Research-Revision': revision_id, 'X-Research-Page-SHA256': page['page_sha256'],
               'X-Research-Complete': 'true' if page['complete'] else 'false'}
    if page['next_cursor']:
        headers['X-Research-Next-Cursor'] = page['next_cursor']
    if page['complete']:
        headers['X-Research-Manifest-SHA256'] = page['manifest_sha256']
    return body, content_type, headers


# The revision row is written at creation and again only by _finalise, so while
# a revision is in one of these states its stored counts are the creation-time
# values (every record pending, none processed).
IN_PROGRESS_STATUSES = ('deriving', 'resetting')
DISPOSITION_FIELDS = (('pending', 'pending_records'), ('processed', 'processed_records'), ('held', 'held_records'),
                      ('retry_pending', 'retry_pending_records'), ('retry_exhausted', 'retry_exhausted_records'),
                      ('failed', 'failed_records'))


def _live_dispositions(revision_ids):
    """Current disposition counts of the given revisions from one bounded aggregate."""
    if not revision_ids:
        return {}
    grouped = {}
    for row in db.rows('SELECT revision_id,status,count() AS records,sum(event_count) AS events FROM research_processing FINAL '
                       'WHERE revision_id IN (' + ','.join(db.literal(value) for value in revision_ids) + ') '
                       'GROUP BY revision_id,status ORDER BY revision_id,status LIMIT ' + str(16 * len(revision_ids)) +
                       ' SETTINGS max_threads=1,max_execution_time=30'):
        grouped.setdefault(row['revision_id'], {})[row['status']] = row
    live = {}
    for revision_id, statuses in grouped.items():
        counts = {field: int(statuses.get(state, {}).get('records', 0)) for state, field in DISPOSITION_FIELDS}
        counts['event_count'] = int(statuses.get('processed', {}).get('events', 0))
        live[revision_id] = counts
    return live


def status(environ=None):
    """Admin-only processing/publication status; never includes content or source IDs.

    Finalised revisions report their stored counts, which the release gate and
    manifest also use. In-progress revisions report live dispositions instead.
    """
    config = ResearchConfig(environ)
    revisions = db.rows('SELECT revision_id,created_at,status,policy_version,parser_version,detector_model,'
                        'expected_records,pending_records,processed_records,held_records,retry_pending_records,retry_exhausted_records,failed_records,event_count,'
                        'conversation_count,complete,updated_at FROM research_revisions FINAL '
                        'ORDER BY created_at DESC LIMIT 10')
    live = _live_dispositions([row['revision_id'] for row in revisions if row.get('status') in IN_PROGRESS_STATUSES])
    for row in revisions:
        row.update(live.get(row['revision_id'], {}))
    releases = db.rows('SELECT revision_id,status,released_at,release_setting,review_ack,event_count,'
                       'record_count,export_sha256 FROM research_releases FINAL ORDER BY released_at DESC LIMIT 10')
    pending = int(db.rows('SELECT count() AS c FROM records FINAL WHERE id NOT IN '
                          '(SELECT record_id FROM research_processing FINAL)')[0]['c'])
    otlp = {row['signal']: int(row['batches']) for row in db.rows(
        'SELECT signal,count() AS batches FROM client_batches FINAL GROUP BY signal ORDER BY signal')}
    return {'research': config.safe_status(), 'revisions': revisions, 'releases': releases,
            'raw_records_without_any_processing_status': pending,
            'otlp_derivation': {'status': 'unsupported', 'signal_batches_not_derived': otlp},
            'publication': 'manual_only', 'automatic_publish': False,
            'raw_retained': True, 'research_archive': 'none; exports generated on demand'}


def manifest(revision_id):
    if not REVISION_ID.fullmatch(str(revision_id)):
        raise ValueError('Invalid revision')
    release = _release_row(revision_id)
    if not release:
        raise HoldError('revision_not_released')
    return json.loads(release['manifest_json'])


def _all_export_events(revision_id, page_size=MAX_PAGE):
    cursor = None
    # Before the first release exists, recover the budgets from the revision's
    # own configuration instead of the historical defaults.
    limits = _release_limits(_release_row(revision_id) or {'revision_id': revision_id})
    while True:
        rows, more = _bounded_rows(revision_id, cursor, page_size, *limits)
        for row in rows:
            yield _export_event(row)
        if not more:
            return
        cursor = {'s': int(rows[-1]['source_seq']), 'i': int(rows[-1]['event_index']), 'e': rows[-1]['event_id']}


def _coverage_reason(event):
    reason = (event.get('payload') or {}).get('reason')
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
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
        elif value == '[WITHHELD]':
            found['policy_withheld'] = found.get('policy_withheld', 0) + 1

    visit(payload, True)
    return found


def _build_manifest(revision, config, superseded_event_rows=0):
    digest = hashlib.sha256()
    event_count = 0
    unlinked = 0
    observation_coverage = {}
    frame_consumers = {}
    exclusions = {}
    repeat_counts = {'eligible_events': 0, 'content_repeat_events': 0, 'payloads_suppressed': 0}
    for event in _all_export_events(revision['revision_id']):
        digest.update(jsonl_bytes([event]))
        event_count += 1
        if dedupe.FIELD in event['payload']:
            repeat_counts['eligible_events'] += 1
            repeat_counts['content_repeat_events'] += event['payload'][dedupe.FIELD] is not None
        if not event['conversation_ref']:
            unlinked += 1
        coverage = observation_coverage.setdefault(event['observation_ref'], {
            'events': 0, 'source_frames': 0, 'source_frame_mapped': 0,
            'source_frame_withheld': 0, 'source_frame_unsupported': 0,
            'event_mapped': 0, 'event_withheld': 0, 'event_unsupported': 0, 'nested_excluded_units': 0,
            'partial_or_unknown': 0})
        coverage['events'] += 1
        if event['kind'] == 'source_frame':
            coverage['source_frames'] += 1
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
        excluded = exclusions.setdefault(event['observation_ref'], {}) if nested else None
        if excluded is not None:
            for reason, amount in nested.items():
                excluded[reason] = excluded.get(reason, 0) + amount
    for frame in frame_consumers.values():
        coverage = observation_coverage[frame['observation_ref']]
        kinds = frame['consumer_kinds']
        if (frame['parse_status'] not in ('parsed', 'consecutive_json', 'incomplete') or not kinds or
                'unsupported' in kinds or 'parse_error' in kinds):
            coverage['source_frame_unsupported'] += 1
        elif kinds <= {'withheld'}:
            coverage['source_frame_withheld'] += 1
        else:
            coverage['source_frame_mapped'] += 1
    held_observations = db.rows('SELECT observation_ref,failure_class FROM research_processing FINAL WHERE revision_id=' +
                                db.literal(revision['revision_id']) + " AND status='held' ORDER BY observation_ref")
    otlp = {row['signal']: int(row['batches']) for row in db.rows(
        'SELECT signal,count() AS batches FROM client_batches FINAL GROUP BY signal ORDER BY signal')}
    manifest = {
        'schema_version': SCHEMA_VERSION, 'revision_id': revision['revision_id'],
        'dataset': 'sanitised Copilot traces research POC',
        'created_at': revision['created_at'], 'policy_version': revision['policy_version'],
        'parser_version': revision['parser_version'], 'sanitiser_version': revision.get('sanitiser_version') or '',
        'detector_model': revision['detector_model'],
        'detector_policy_version': revision['detector_policy_version'],
        'release_review_acknowledged': True, 'release_setting': config.release_setting,
        'retention': {'raw': config.retention_raw, 'curated': config.retention_curated,
                      'automatic_ttl': False, 'destructive_purge': 'manual_operator_only'},
        'counts': {'records_in_selection': int(revision['expected_records']),
                   'records_pending': int(revision.get('pending_records', 0)),
                   'records_processed': int(revision['processed_records']),
                   'records_withheld': int(revision['held_records']),
                   'records_retry_pending': int(revision.get('retry_pending_records', 0)),
                   'records_retry_exhausted': int(revision.get('retry_exhausted_records', 0)),
                   'records_failed': int(revision['failed_records']),
                   'events': event_count, 'observations': len(observation_coverage),
                   'source_frames': sum(item['source_frames'] for item in observation_coverage.values()),
                   'source_frames_mapped': sum(item['source_frame_mapped'] for item in observation_coverage.values()),
                   'source_frames_withheld': sum(item['source_frame_withheld'] for item in observation_coverage.values()),
                   'source_frames_unsupported': sum(item['source_frame_unsupported'] for item in observation_coverage.values()),
                   'nested_excluded_units': sum(item['nested_excluded_units'] for item in observation_coverage.values()),
                   'superseded_event_rows': int(superseded_event_rows),
                   'events_without_conversation_ref': unlinked,
                   'conversations_with_explicit_ref': int(revision['conversation_count'])},
        'per_observation_coverage': [{'observation_ref': ref, **observation_coverage[ref]}
                                     for ref in sorted(observation_coverage)],
        'per_observation_exclusions': [{'observation_ref': ref, 'reasons': exclusions[ref]}
                                       for ref in sorted(exclusions)],
        'held_observations': [{'observation_ref': row['observation_ref'], 'reason': row['failure_class']}
                              for row in held_observations],
        'coverage': {'source': 'Enterprise usage records observed through polling',
                     'conversation_coverage': 'unknown',
                     'conversation_boundaries': 'not inferred',
                     'timing': 'exact timestamps withheld',
                     'otlp': {'status': 'unsupported', 'signal_batches_not_derived': otlp,
                              'note': 'OTLP content remains raw evidence; no derived research events or completeness claim'}},
        'gaps': ['Conversation coverage is unknown; only explicit session/task/conversation/previous-response references are linked.',
                 'Repeated history windows are retained per observation; overlapping context is not deduplicated without evidence.',
                 'Unsupported attachments, system context and headers are withheld explicitly.',
                 'OTLP spans/logs/metrics are not derived into the curated dataset.',
                 'Privacy evaluation and real-world release approval remain pending.'],
        'export_sha256': digest.hexdigest(), 'export_format': 'UTF-8 JSON Lines, optional gzip',
        'page_size_max': MAX_PAGE,
    }
    repeat_config = dedupe.pinned(revision)
    if repeat_config:
        reconciled = dedupe.summary(revision, _checkpoint)
        if any(repeat_counts[name] != reconciled[name] for name in ('eligible_events', 'content_repeat_events')):
            raise OSError('Pinned repeat annotation counts do not reconcile')
        repeat_counts['retained_eligible_events'] = repeat_counts['eligible_events'] - repeat_counts['content_repeat_events']
        manifest['dedupe'] = {**repeat_config, 'counts': {**reconciled, **repeat_counts}}
        manifest['gaps'][1] = ('All history payloads are retained. Content-repeat annotations are sanitised equality, '
                               'not provider message identity; deliberate repeats and redaction collisions can match.')
    return manifest
