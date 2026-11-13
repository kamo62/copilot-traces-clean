"""Revision-local, non-destructive annotations of repeated sanitised history.

Text equality is NOT provider message identity. Every payload and observation is
retained; this index only lets an explicit content-unique consumer view distinguish
an earlier matching observation. It never supplies conversation identity.
"""
import json
import time

import clickhouse as db

ALGORITHM_VERSION = 'content-repeat/2026-10-31.F1'
FIELD = 'content_repeat_of'
PAGE_ROWS = 200
MAX_SQL_BYTES = 256 * 1024
MAX_QUERY_MEMORY = 512 * 1024 * 1024
METADATA = ('revision_id,source_seq,event_index,event_id,record_id,pipeline_id,observation_ref,'
            'conversation_ref,origin,kind,role,parse_status,coverage_status,parser_version,content_sha256')
PREDICATE = ("kind='message' AND origin='history' AND role IN ('user','assistant') "
             "AND parse_status='parsed' AND coverage_status IN ('unknown','observed','complete') "
             "AND conversation_ref!=''")


def configuration(event_bytes, page_bytes):
    return {'mode': 'annotate_sanitised_history', 'algorithm_version': ALGORITHM_VERSION,
            'page_rows': PAGE_ROWS, 'max_payload_bytes': max(int(page_bytes), 2 * int(event_bytes)),
            'max_event_bytes': int(event_bytes), 'max_sql_bytes': MAX_SQL_BYTES,
            'max_query_memory': MAX_QUERY_MEMORY, 'payloads_suppressed': False,
            'provider_message_identity_proven': False}


def pinned(revision):
    config = json.loads(revision.get('config_json') or '{}').get('dedupe')
    if config is not None and (not isinstance(config, dict) or
                              config != configuration(config.get('max_event_bytes', 0),
                                                      config.get('max_payload_bytes', 0))):
        raise OSError('Unsupported repeat annotation configuration')
    return config


def initialise():
    for ddl in (
        """CREATE TABLE IF NOT EXISTS research_dedupe_first_seen (
          revision_id String, conversation_ref String, role String, content_sha256 FixedString(64),
          source_seq UInt64, event_index UInt32, event_id String, record_id FixedString(64),
          pipeline_id String, observation_ref String, conflicted UInt8, repeat_count UInt64,
          algorithm_version String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,conversation_ref,role,content_sha256)""",
        """CREATE TABLE IF NOT EXISTS research_dedupe_decisions (
          revision_id String, source_seq UInt64, event_index UInt32, event_id String,
          record_id FixedString(64), pipeline_id String, conversation_ref String, role String,
          content_sha256 FixedString(64), content_repeat_of String, decision_class LowCardinality(String),
          algorithm_version String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,source_seq,event_index,event_id)""",
    ):
        db.execute(ddl)


def eligible_observation(parsed):
    # One content-free bit committed atomically with processed disposition. No
    # extra per-record write/text copy. Summaries/truncation/streams stay distinct.
    return (parsed.get('format') == 'json' and parsed.get('parse_status') == 'parsed' and
            parsed.get('stream_complete') is not False and not any(
                event['kind'] == 'source_frame' or event.get('payload', {}).get('reason') in
                ('provider_truncated', 'source_summary_present', 'partial_stream')
                for event in parsed['events']))


def _rows(sql, limit, byte_limit, config):
    sql += (' SETTINGS max_threads=1,max_block_size=1,max_memory_usage=' + str(config['max_query_memory']) +
            ',max_result_rows=' + str(limit) + ',max_result_bytes=' + str(byte_limit) +
            ",result_overflow_mode='throw'")
    if len(sql.encode('utf-8')) + len(' FORMAT JSONEachRow') > config['max_sql_bytes']:
        raise OSError('Repeat annotation query exceeds pinned budget')
    rows = db.rows(sql)
    if len(rows) > limit:
        raise OSError('Repeat annotation result exceeds pinned row budget')
    return rows


def _order(row):
    return (int(row['source_seq']), int(row['event_index']), row['event_id'])


def _key(row):
    return (row['conversation_ref'], row['role'], row['content_sha256'])


def _tuples(values):
    return ','.join('(' + ','.join(str(value) if type(value) is int else db.literal(value)
                                 for value in entry) + ')' for entry in sorted(set(values)))


def _at(revision_id, entries, config, payload=False):
    if not entries:
        return []
    select = METADATA + (',payload' if payload else ',length(payload) AS payload_bytes')
    return _rows('SELECT ' + select + ' FROM research_events FINAL PREWHERE revision_id=' +
                 db.literal(revision_id) + ' AND (source_seq,event_index,event_id) IN (' +
                 _tuples(_order(row) for row in entries) + ') ORDER BY source_seq,event_index,event_id LIMIT ' +
                 str(len(entries)), len(entries), config['max_payload_bytes'] + len(entries) * 2048, config)


def _first_seen(revision_id, entries, config):
    if not entries:
        return {}
    rows = _rows('SELECT * FROM research_dedupe_first_seen FINAL WHERE revision_id=' + db.literal(revision_id) +
                 ' AND (conversation_ref,role,content_sha256) IN (' + _tuples(_key(row) for row in entries) +
                 ') LIMIT ' + str(len(entries)), len(entries), len(entries) * 2048, config)
    return {_key(row): row for row in rows}


def _current(revision_id, entries, config):
    identifiers = sorted({row['record_id'] for row in entries})
    if not identifiers:
        return {}
    rows = _rows('SELECT record_id,pipeline_id,status FROM research_processing FINAL WHERE revision_id=' +
                 db.literal(revision_id) + ' AND record_id IN (' + ','.join(db.literal(value) for value in identifiers) +
                 ') LIMIT ' + str(len(identifiers)), len(identifiers), len(identifiers) * 1024, config)
    return {row['record_id']: row['pipeline_id'] for row in rows if row['status'] == 'processed'}


def _eligible_observations(revision_id, entries, config):
    identifiers = sorted({row['record_id'] for row in entries})
    rows = _rows('SELECT record_id,pipeline_id,dedupe_eligible FROM research_processing FINAL WHERE revision_id=' +
                 db.literal(revision_id) + ' AND record_id IN (' + ','.join(db.literal(value) for value in identifiers) +
                 ') LIMIT ' + str(len(identifiers)), len(identifiers), len(identifiers) * 1024, config) if identifiers else []
    eligible = {(row['record_id'], row['pipeline_id']) for row in rows if row['dedupe_eligible']}
    return {(int(row['source_seq']), row['record_id'], row['pipeline_id']) for row in entries
            if (row['record_id'], row['pipeline_id']) in eligible}


def candidate(row):
    return (row['kind'] == 'message' and row['origin'] == 'history' and row['role'] in ('user', 'assistant') and
            row['parse_status'] == 'parsed' and row['coverage_status'] in ('unknown', 'observed', 'complete') and
            bool(row['conversation_ref']))


def plain_payload(payload):
    # A closed semantic shape prevents frames, summaries, attachments or partial
    # units from accidentally becoming content repeats. File metadata is compared
    # too, rather than discarded from the sanitised-content hash.
    allowed = {'text', 'block_type', 'authorship', 'intent_label', 'intent_status', 'observed_file_references'}
    return (isinstance(payload, dict) and not set(payload) - allowed and
            isinstance(payload.get('text'), str) and bool(payload['text']) and '[WITHHELD]' not in payload['text'] and
            payload.get('block_type') == 'text' and payload.get('authorship') == 'unknown' and
            payload.get('intent_label') is None and payload.get('intent_status') == 'unknown')


def step(revision, checkpoint):
    """One fixed row/byte-budgeted page, or an idempotent pending-write recovery.

    Membership and conversation reconciliation finish before this scan. Winners
    follow source order, never insertion time. Persist a content-free write plan
    BEFORE any sidecar update; replay it after a crash, then advance the cursor.
    """
    config = pinned(revision)
    revision_id = revision['revision_id']
    key = 'research_dedupe:' + revision_id
    state = checkpoint(key) or {'cursor': [0, 0, ''], 'counts': {
        'scanned_history_messages': 0, 'eligible_events': 0, 'content_repeat_events': 0,
        'ineligible_events': 0, 'superseded_events': 0, 'hash_conflict_keys': 0}}
    if state.get('done'):
        return True
    if state.get('pending'):
        return _apply(key, state, checkpoint)
    ready = _rows('SELECT count() AS records,countIf(status NOT IN (\'processed\',\'held\')) AS unfinished '
                  'FROM research_processing FINAL WHERE revision_id=' + db.literal(revision_id) + ' LIMIT 1',
                  1, 1024, config)[0]
    if int(ready['records']) != int(revision['expected_records']) or int(ready['unfinished']):
        # Preserve the existing incomplete/retry disposition. Do not freeze a
        # partial index that a reset of an exhausted retry could later change.
        return True
    cursor = tuple(state['cursor'])
    # Select the fixed-size occurrence metadata BEFORE touching payload columns.
    # LIMIT on a query selecting length(payload) can still read/decompress content
    # while finding sparse history rows. Byte sizes are primary-key point reads.
    metadata = _rows('SELECT ' + METADATA + ' FROM research_events FINAL '
                     'PREWHERE revision_id=' + db.literal(revision_id) + ' AND (source_seq,event_index,event_id)>(' +
                     _tuples([cursor])[1:-1] + ') WHERE ' + PREDICATE +
                     ' ORDER BY source_seq,event_index,event_id LIMIT ' + str(config['page_rows']),
                     config['page_rows'], config['page_rows'] * 2048, config)
    if not metadata:
        checkpoint(key, {**state, 'done': True})
        return True
    current = _current(revision_id, metadata, config)
    eligible = _eligible_observations(revision_id, metadata, config)
    candidates = [row for row in metadata if current.get(row['record_id']) == row['pipeline_id'] and
                  (int(row['source_seq']), row['record_id'], row['pipeline_id']) in eligible]
    sizes = {_order(row): row for row in _at(revision_id, candidates, config)}
    if len(sizes) != len(candidates):
        raise OSError('Repeat annotation candidate evidence unavailable')
    for row in metadata:
        sized = sizes.get(_order(row))
        if sized is not None and any(row[name] != sized[name] for name in METADATA.split(',')):
            raise OSError('Repeat annotation candidate membership changed')
        row['payload_bytes'] = int(sized['payload_bytes']) if sized else 0
    first = _first_seen(revision_id, candidates, config)
    previous = [row for row in first.values() if not row['conflicted']]
    first_meta = {_order(row): row for row in _at(revision_id, previous, config)}
    if len(first_meta) != len(previous):
        raise OSError('Repeat annotation canonical evidence unavailable')
    canonical_current = _current(revision_id, previous, config)
    for winner in previous:
        target = first_meta[_order(winner)]
        if (canonical_current.get(winner['record_id']) != winner['pipeline_id'] or
                any(target[name] != winner[name] for name in
                    ('record_id', 'pipeline_id', 'observation_ref', 'conversation_ref', 'role', 'content_sha256'))):
            raise OSError('Repeat annotation canonical membership changed')
    # Budget BOTH sides of every comparison. Only a bounded prefix is fetched;
    # the next call starts immediately after it, without OFFSET or a large group.
    selected, bodies, targets, total = [], [], {}, 0
    candidate_orders = {_order(row) for row in candidates}
    for row in metadata:
        needs_body = _order(row) in candidate_orders
        target = first.get(_key(row)) if needs_body else None
        target = target if target and not target['conflicted'] else None
        target_order = _order(target) if target else None
        extra = int(row['payload_bytes']) if needs_body else 0
        if target_order is not None and target_order not in targets:
            extra += int(first_meta[target_order]['payload_bytes'])
        if needs_body and int(row['payload_bytes']) > config['max_event_bytes']:
            raise OSError('Repeat annotation event exceeds pinned budget')
        if total + extra > config['max_payload_bytes']:
            if not selected:
                raise OSError('Repeat annotation comparison exceeds pinned budget')
            break
        selected.append(row)
        total += extra
        if needs_body:
            bodies.append(row)
        if target is not None:
            targets[target_order] = target
    body_rows = {_order(row): row for row in _at(revision_id, bodies, config, payload=True)}
    target_rows = {_order(row): row for row in _at(revision_id, list(targets.values()), config, payload=True)}
    if len(body_rows) != len(bodies) or len(target_rows) != len(targets):
        raise OSError('Repeat annotation comparison evidence unavailable')
    for meta in bodies + [first_meta[_order(row)] for row in targets.values()]:
        body = (body_rows if _order(meta) in body_rows else target_rows)[_order(meta)]
        if any(meta[name] != body[name] for name in METADATA.split(',')):
            raise OSError('Repeat annotation comparison membership changed')
    counts, updates, decisions = dict(state['counts']), {}, []
    for meta in selected:
        counts['scanned_history_messages'] += 1
        if current.get(meta['record_id']) != meta['pipeline_id']:
            counts['superseded_events'] += 1
            continue
        row = body_rows.get(_order(meta))
        decision = {name: meta[name] for name in ('revision_id', 'source_seq', 'event_index', 'event_id',
                    'record_id', 'pipeline_id', 'conversation_ref', 'role', 'content_sha256')}
        decision.update(content_repeat_of='', decision_class='ineligible', algorithm_version=ALGORITHM_VERSION,
                        version=time.time_ns())
        if row is None or not plain_payload(json.loads(row['payload'])):
            counts['ineligible_events'] += 1
        else:
            counts['eligible_events'] += 1
            identity = _key(row)
            winner = updates.get(identity) or first.get(identity)
            if winner is None:
                winner = {name: row[name] for name in ('revision_id', 'conversation_ref', 'role', 'content_sha256',
                          'source_seq', 'event_index', 'event_id', 'record_id', 'pipeline_id', 'observation_ref')}
                winner.update(conflicted=0, repeat_count=0, algorithm_version=ALGORITHM_VERSION, version=time.time_ns())
                updates[identity] = winner
                target_rows[_order(row)] = row
                decision['decision_class'] = 'first_seen'
            elif winner['conflicted']:
                decision['decision_class'] = 'hash_conflict'
            else:
                target = target_rows[_order(winner)]
                # Digests select comparisons, never replace them. A hash collision
                # or semantic/version mismatch makes the entire key unmarked.
                if (row['payload'] != target['payload'] or row['parser_version'] != target['parser_version'] or
                        row['conversation_ref'] != target['conversation_ref'] or row['role'] != target['role']):
                    counts['content_repeat_events'] -= int(winner['repeat_count'])
                    winner = dict(winner, conflicted=1, repeat_count=0, version=time.time_ns())
                    counts['hash_conflict_keys'] += 1
                    updates[identity] = winner
                    decision['decision_class'] = 'hash_conflict'
                elif row['observation_ref'] == winner['observation_ref']:
                    # Identical units within one observation are never repeats.
                    decision['decision_class'] = 'same_observation'
                else:
                    decision.update(content_repeat_of=winner['event_id'], decision_class='content_repeat')
                    counts['content_repeat_events'] += 1
                    updates[identity] = dict(winner, repeat_count=int(winner['repeat_count']) + 1, version=time.time_ns())
        decisions.append(decision)
    pending = {'cursor': list(_order(selected[-1])), 'counts': counts,
               'first_seen': list(updates.values()), 'decisions': decisions}
    state = {**state, 'pending': pending}
    checkpoint(key, state)
    return _apply(key, state, checkpoint)


def _apply(key, state, checkpoint):
    pending = state['pending']
    db.insert('research_dedupe_first_seen', pending['first_seen'])
    db.insert('research_dedupe_decisions', pending['decisions'])
    checkpoint(key, {'cursor': pending['cursor'], 'counts': pending['counts']})
    return False


def summary(revision, checkpoint):
    state = checkpoint('research_dedupe:' + revision['revision_id'])
    if not state or not state.get('done') or state.get('pending'):
        raise OSError('Pinned repeat annotation reconciliation incomplete')
    return dict(state['counts'])


def annotate(rows, checkpoint):
    """Attach only nullable event references, using bounded point-key sidecar reads.

    Old revisions have no pinned algorithm and retain byte-identical exports.
    All payloads remain present, including deliberate repeats and hash conflicts.
    """
    active = [row for row in rows if row.get('dedupe_version')]
    if not active:
        return
    if any(row['dedupe_version'] != ALGORITHM_VERSION for row in active):
        raise OSError('Pinned repeat annotation algorithm unavailable')
    revision_id = active[0]['revision_id']
    if any(row['revision_id'] != revision_id for row in active):
        raise OSError('Mixed repeat annotation revision')
    summary({'revision_id': revision_id}, checkpoint)
    config = pinned({'config_json': json.dumps({'dedupe': json.loads(active[0]['dedupe_config_json'])})})
    candidates = [row for row in active if candidate(row)]
    if not candidates:
        return
    # Export pages have at most 500 rows. These content-free lookups are bounded
    # by that page, not the size of the revision/conversation or identity group.
    ledger = _rows('SELECT * FROM research_dedupe_decisions FINAL WHERE revision_id=' + db.literal(revision_id) +
                   ' AND (source_seq,event_index,event_id) IN (' + _tuples(_order(row) for row in candidates) +
                   ') LIMIT ' + str(len(candidates)), len(candidates), len(candidates) * 2048, config)
    decisions = {_order(row): row for row in ledger}
    winners = _first_seen(revision_id, [row for row in ledger if row['decision_class'] != 'ineligible'], config)
    current = _current(revision_id, list(winners.values()), config)
    for row in candidates:
        decision = decisions.get(_order(row))
        if (decision is None or decision['algorithm_version'] != ALGORITHM_VERSION or
                any(decision[name] != row[name] for name in ('record_id', 'pipeline_id', 'conversation_ref', 'role', 'content_sha256'))):
            raise OSError('Pinned repeat annotation decision unavailable')
        if decision['decision_class'] == 'ineligible':
            continue
        winner = winners.get(_key(decision))
        if (winner is None or winner['algorithm_version'] != ALGORITHM_VERSION or
                current.get(winner['record_id']) != winner['pipeline_id']):
            raise OSError('Pinned repeat annotation target unavailable')
        target = decision['content_repeat_of'] if not winner['conflicted'] else ''
        if target and (target != winner['event_id'] or _order(winner) >= _order(row) or
                       winner['observation_ref'] == row['observation_ref']):
            raise OSError('Invalid repeat annotation target')
        row[FIELD] = target or None
