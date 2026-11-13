"""Content-free, revision-local response identity graph for the serial worker.

After derivation, bounded keyset passes propagate the least label along verified
previous-response edges. Labels only decrease, so a finite frozen graph converges
independently of arrival order. No graph traversal or process-local cache is used.
"""
import time

import clickhouse as db


# Versioned table name: a new sort key cannot be added in place, and dropping a
# shared table is racy when the API and worker initialise concurrently. A new
# name is safe; the old, empty table is simply ignored.
LABELS_TABLE = 'research_conversation_labels_v2'
LABELS_DDL = """CREATE TABLE IF NOT EXISTS research_conversation_labels_v2 (
  revision_id String, run_id String, response_ref String, priority UInt8, conversation_ref String,
  active UInt8, conflicted UInt8, version UInt64
) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,run_id,response_ref)"""


def initialise():
    for ddl in (
        """CREATE TABLE IF NOT EXISTS research_identity_records (
          revision_id String, source_seq UInt64, record_id FixedString(64), request_id String,
          pipeline_id String, response_ref String, previous_ref String, explicit_ref String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,source_seq,record_id)""",
        """CREATE TABLE IF NOT EXISTS research_response_ids (
          revision_id String, response_ref String, record_id FixedString(64), pipeline_id String,
          seed_ref String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,response_ref,record_id)""",
        """CREATE TABLE IF NOT EXISTS research_request_ids (
          revision_id String, request_id String, record_id FixedString(64), record_type LowCardinality(String),
          response_ref String, pipeline_id String, version UInt64
        ) ENGINE=ReplacingMergeTree(version) ORDER BY (revision_id,request_id,record_id)""",
        LABELS_DDL,
    ):
        db.execute(ddl)
    db.execute("ALTER TABLE research_identity_records ADD COLUMN IF NOT EXISTS request_id String DEFAULT '' AFTER record_id")
    db.execute("ALTER TABLE research_request_ids ADD COLUMN IF NOT EXISTS record_type LowCardinality(String) DEFAULT ''")


def register(revision_id, record, parsed, pipeline_id, refs):
    responses = parsed.get('response_refs', [])
    response_ref = responses[0] if len(responses) == 1 else ''
    previous = sorted({link['ref'] for link in parsed.get('links', [])
                       if link['method'] == 'explicit_previous_response_id'})
    # A self-referential edge is malformed and must not activate a conversation.
    previous = [ref for ref in previous if ref != response_ref]
    raw_request_id = str(record.get('request_id') or '')
    request_id = refs.opaque('req', raw_request_id) if raw_request_id else ''
    entry = {'revision_id': revision_id, 'source_seq': int(record['seq']), 'record_id': record['id'],
             'request_id': request_id, 'pipeline_id': pipeline_id, 'response_ref': response_ref,
             'previous_ref': previous[0] if len(previous) == 1 else '',
             'explicit_ref': parsed.get('conversation_ref') or '', 'version': time.time_ns()}
    db.insert('research_identity_records', [entry])
    if request_id:
        db.insert('research_request_ids', [{'revision_id': revision_id, 'request_id': request_id,
                                            'record_id': record['id'], 'record_type': record.get('type') or '',
                                            'response_ref': response_ref, 'pipeline_id': pipeline_id,
                                            'version': entry['version']}])
    if entry['response_ref']:
        db.insert('research_response_ids', [{key: entry[key] for key in
                  ('revision_id', 'record_id', 'pipeline_id', 'response_ref', 'version')} | {
                      'seed_ref': refs.opaque('conv', 'response-chain:' + revision_id + ':' + entry['response_ref'])}])


def current(entry):
    rows = db.rows('SELECT status,pipeline_id FROM research_processing FINAL WHERE revision_id=' +
                   db.literal(entry['revision_id']) + ' AND record_id=' + db.literal(entry['record_id']) + ' LIMIT 1')
    return bool(rows and rows[0]['status'] == 'processed' and rows[0]['pipeline_id'] == entry['pipeline_id'])


def next_record(revision_id, cursor):
    return db.rows('SELECT * FROM research_identity_records FINAL WHERE revision_id=' + db.literal(revision_id) +
                   ' AND (source_seq,record_id)>(' + str(int(cursor[0])) + ',' + db.literal(cursor[1]) + ')' +
                   ' ORDER BY source_seq,record_id LIMIT 1 SETTINGS max_threads=1,max_block_size=1')


def _response(revision_id, ref):
    if not ref:
        return None
    rows = db.rows('SELECT * FROM research_response_ids FINAL WHERE revision_id=' + db.literal(revision_id) +
                   ' AND response_ref=' + db.literal(ref) + ' LIMIT 2 SETTINGS max_threads=1,max_block_size=2')
    # Conflicting observations of one provider ID are ambiguous, not a licence
    # to merge their conversations. Stale/held attempts never provide identity.
    return rows[0] if len(rows) == 1 and current(rows[0]) else None


def _label(response, run_id):
    # Labels are scoped to one reconciliation run. Sticky activity converges
    # inside a run, but must never be inherited by the next run, or an edge that
    # has since become ambiguous keeps a ghost conversation alive.
    rows = db.rows('SELECT run_id,priority,conversation_ref,active,conflicted FROM research_conversation_labels_v2 FINAL WHERE revision_id=' +
                   db.literal(response['revision_id']) + ' AND run_id=' + db.literal(run_id) +
                   ' AND response_ref=' + db.literal(response['response_ref']) + ' LIMIT 1')
    return rows[0] if rows else {'priority': 1, 'conversation_ref': response['seed_ref'], 'active': 0, 'conflicted': 0}


def _pair(entry):
    """The response produced by this request, only when the gateway id names one exchange.

    Supplementary to the header session anchor: an id shared by anything other
    than exactly one request and one response (streaming batches) never pairs.
    """
    if not entry.get('request_id'):
        return None
    rows = db.rows('SELECT revision_id,record_id,record_type,response_ref,pipeline_id FROM research_request_ids FINAL '
                   'WHERE revision_id=' + db.literal(entry['revision_id']) +
                   ' AND request_id=' + db.literal(entry['request_id']) +
                   ' LIMIT 3 SETTINGS max_threads=1,max_block_size=3')
    if len(rows) != 2:
        return None
    requests = [row for row in rows if row['record_type'] == 'request']
    responses = [row for row in rows if row['record_type'] == 'response']
    if len(requests) != 1 or len(responses) != 1 or not responses[0]['response_ref']:
        return None
    if not current(requests[0]) or not current(responses[0]):
        return None
    return _response(entry['revision_id'], responses[0]['response_ref'])


def _nodes(entry):
    return [_response(entry['revision_id'], entry['response_ref']),
            _response(entry['revision_id'], entry['previous_ref'])]


def reconcile(entry, run_id):
    own, previous = _nodes(entry)
    if entry['response_ref'] and own is None:
        # An ambiguous or unavailable own response is not evidence for any
        # conversation, and must not bridge or propagate across previous_ref.
        # A session ref it carries still applies to its own events.
        return False
    paired = _pair(entry) if not own else None
    nodes = {node['response_ref']: node for node in (own, previous, paired) if node}
    labels = {ref: _label(node, run_id) for ref, node in nodes.items()}
    candidates = [(int(label['priority']), label['conversation_ref']) for label in labels.values()]
    if entry['explicit_ref']:
        candidates.append((0, entry['explicit_ref']))
    if not labels:
        return False
    priority, ref = min(candidates)
    # Activity is monotonic inside one label generation: a node keeps what a
    # child propagated to it, which is what makes the pass converge. Labels are
    # run-scoped, so nothing survives into the next generation.
    # `paired` deliberately does not activate: a gateway id alone never makes
    # a conversation. Pairing only joins a response to an existing anchor.
    active = int(bool(previous or entry['explicit_ref'] or
                      any(label['active'] for label in labels.values())))
    explicit = {candidate_ref for candidate_priority, candidate_ref in candidates if candidate_priority == 0}
    conflicted = int(len(explicit) > 1 or any(label['conflicted'] for label in labels.values()))
    value = {'run_id': run_id, 'priority': priority, 'conversation_ref': ref,
             'active': active, 'conflicted': conflicted}
    changed = [dict(revision_id=entry['revision_id'], response_ref=node_ref, **value, version=time.time_ns())
               for node_ref, label in labels.items() if label != value]
    db.insert(LABELS_TABLE, changed)
    return bool(changed)


def conversation_for(entry, run_id):
    own, previous = _nodes(entry)
    if entry['response_ref'] and own is None:
        # Ambiguous own response: keep only its own explicit session, never a
        # conversation inherited across the dead edge.
        return entry['explicit_ref']
    paired = _pair(entry) if not own else None
    labels = [_label(node, run_id) for node in (own, previous, paired) if node]
    if any(label['conflicted'] for label in labels):
        return entry['explicit_ref']
    active = [label for label in labels if label['active']]
    if active:
        return min(active, key=lambda label: (int(label['priority']), label['conversation_ref']))['conversation_ref']
    return entry['explicit_ref']
