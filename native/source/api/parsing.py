"""Shared, versioned parsing and normalisation for Enterprise record bodies.

Streams are decoded with JSONDecoder.raw_decode. Newline splitting is never
used to recover JSON values, because escaped newlines in prompts and tool
outputs are content. Source frames and assembled output are separate events.
"""
from collections import OrderedDict
import json
import re

PARSER_VERSION = '2026-11-01.n'
SSE_START = re.compile(r'^(?:data|event|id|retry):', re.M)
EXPLICIT_REFS = (
    ('conversation_id', 'conversation', 'explicit_conversation_id'),
    ('session_id', 'session', 'explicit_session_id'),
    ('task_id', 'task', 'explicit_task_id'),
    ('previous_response_id', 'response', 'explicit_previous_response_id'),
)
TOP_LEVEL_KNOWN = {
    'model', 'messages', 'system', 'tools', 'tool_choice', 'stream', 'temperature', 'top_p', 'top_k',
    'max_tokens', 'max_output_tokens', 'stop', 'stop_sequences', 'metadata', 'usage', 'content', 'id',
    'object', 'created', 'choices', 'output', 'status', 'error', 'type', 'role', 'stop_reason',
    'stop_sequence', 'input', 'instructions', 'previous_response_id', 'session_id', 'task_id',
    'conversation_id', 'parallel_tool_calls', 'reasoning', 'text', 'store', 'include', 'truncation',
    'user', 'service_tier', 'prompt_cache_key', 'finish_reason', 'index', 'logprobs', 'delta', 'truncated',
    'summary', 'summaries',
}
MESSAGE_KNOWN = {'role', 'content', 'tool_calls', 'tool_call_id', 'name', 'function_call', 'refusal', 'annotations', 'audio'}
BLOCK_KNOWN = {'type', 'text', 'tool_use', 'tool_result', 'image', 'document', 'thinking', 'redacted_thinking'}


class PartialJSON(ValueError):
    def __init__(self, values, offset):
        self.values, self.offset = values, offset


def _json_values(text):
    decoder = json.JSONDecoder()
    values = []
    index = 0
    length = len(text)
    while True:
        while index < length and text[index].isspace():
            index += 1
        if index >= length:
            break
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            raise PartialJSON(values, index) from None
        if end <= index:
            raise ValueError('Decoder did not advance')
        values.append({'value': value, 'raw': text[index:end], 'start': index, 'end': end})
        index = end
    return values


def _parse_sse(text):
    frames = []
    # Only CR, LF and CRLF are physical SSE delimiters. str.splitlines also
    # splits U+2028/U+0085, which may be literal content inside JSON strings.
    physical = text.replace('\r\n', '\n').replace('\r', '\n')
    blocks = physical.split('\n\n')
    unterminated = not physical.endswith('\n\n')
    for block_index, block in enumerate(blocks):
        if not block.strip():
            continue
        event = 'message'
        data_lines = []
        identifier = None
        retry = None
        for line in block.split('\n'):
            if not line or line.startswith(':'):
                continue
            field, separator, value = line.partition(':')
            if separator and value.startswith(' '):
                value = value[1:]
            if field == 'event':
                event = value
            elif field == 'data':
                data_lines.append(value)
            elif field == 'id':
                identifier = value
            elif field == 'retry':
                retry = value
        data = '\n'.join(data_lines)
        parsed = None
        status = 'empty'
        if data:
            try:
                values = _json_values(data)
                if len(values) == 1:
                    parsed = values[0]['value']
                    status = 'parsed'
                else:
                    parsed = [item['value'] for item in values]
                    status = 'consecutive_json'
            except (ValueError, json.JSONDecodeError):
                status = 'invalid_json'
        if unterminated and block_index == len(blocks) - 1 and status == 'parsed':
            status = 'incomplete'
        frames.append({'event': event, 'id': identifier, 'retry': retry, 'data': data,
                       'value': parsed, 'parse_status': status})
    return frames


def classify_body(body):
    if not isinstance(body, str):
        return {'format': 'unsupported', 'parse_status': 'unsupported', 'values': [], 'frames': []}
    stripped = body.lstrip('\ufeff \t\r\n')
    if not stripped:
        return {'format': 'empty', 'parse_status': 'empty', 'values': [], 'frames': []}
    if SSE_START.match(stripped):
        frames = _parse_sse(stripped)
        status = 'partial' if any(f['parse_status'] in ('invalid_json', 'incomplete') and f['data'] != '[DONE]' for f in frames) else 'parsed'
        return {'format': 'sse', 'parse_status': status, 'values': [], 'frames': frames}
    try:
        values = _json_values(stripped)
    except PartialJSON as failure:
        if failure.values:
            return {'format': 'consecutive_json', 'parse_status': 'partial', 'values': failure.values, 'frames': [], 'error_offset': failure.offset}
        return {'format': 'malformed', 'parse_status': 'malformed', 'values': [], 'frames': []}
    except (ValueError, json.JSONDecodeError):
        return {'format': 'malformed', 'parse_status': 'malformed', 'values': [], 'frames': []}
    if not values:
        return {'format': 'empty', 'parse_status': 'empty', 'values': [], 'frames': []}
    return {'format': 'json' if len(values) == 1 else 'consecutive_json',
            'parse_status': 'parsed', 'values': values, 'frames': []}


class Builder:
    def __init__(self, refs):
        self.refs = refs
        self.events = []
        self.call_events = {}
        self.current_source_frame_index = None

    def add(self, kind, origin, payload=None, role=None, parse_status='parsed', linkage_status='unknown',
            coverage_status='unknown', link=None, call_ref=None, result_ref=None, parent_index=None):
        if role not in (None, 'system', 'developer', 'user', 'assistant', 'tool', 'function'):
            role = None
            coverage_status = 'unsupported'
        missing = getattr(self.refs, 'missing_calls', set())
        if call_ref in missing:
            call_ref, result_ref, link, linkage_status, parent_index = None, None, None, 'unknown', None
            if isinstance(payload, dict):
                payload = {**payload, 'call_ref': None}
                if 'result_ref' in payload: payload['result_ref'] = None
        event = {
            'event_index': len(self.events), 'kind': kind, 'origin': origin, 'role': role,
            'payload': payload or {}, 'parse_status': parse_status, 'linkage_status': linkage_status,
            'coverage_status': coverage_status, 'link': link, 'call_ref': call_ref, 'result_ref': result_ref,
        }
        if parent_index is not None:
            event['parent_event_index'] = parent_index
        if self.current_source_frame_index is not None and origin in ('output', 'history'):
            indexes = event['payload'].get('source_frame_event_indices', [])
            if self.current_source_frame_index not in indexes:
                indexes = list(indexes) + [self.current_source_frame_index]
            event['payload']['source_frame_event_indices'] = indexes
            event['payload']['fragment_count'] = len(indexes)
        self.events.append(event)
        return event['event_index']

    def link_for(self, kind, ref, method):
        return {'type': kind, 'ref': ref, 'method': method, 'confidence': 'explicit', 'raw_value_exported': False}


# Session identity GitHub puts on request headers. Responses carry no headers,
# so these anchor a conversation only for the request half of each turn.
HEADER_SESSION_FIELDS = (
    ('x-interaction-id', 'conversation', 'explicit_header_interaction'),
    ('x-conversation-id', 'conversation', 'explicit_header_conversation'),
    ('x-session-id', 'conversation', 'explicit_header_session'),
    ('x-copilot-session-id', 'conversation', 'explicit_header_session'),
    ('x-github-session-id', 'conversation', 'explicit_header_session'),
    ('x-agent-task-id', 'task', 'explicit_header_agent_task'),
)
HEADER_SESSION_NAMES = {header for header, _, _ in HEADER_SESSION_FIELDS}
CONVERSATION_HEADERS = {header for header, kind, _ in HEADER_SESSION_FIELDS if kind == 'conversation'}
# Several headers share one method (x-session-id, x-copilot-session-id and
# x-github-session-id are all explicit_header_session).
METHOD_HEADERS = {}
for _header, _, _method in HEADER_SESSION_FIELDS:
    for _name in (_method, _method.replace('explicit_', 'ambiguous_', 1)):
        METHOD_HEADERS.setdefault(_name, set()).add(_header)
HEADER_SESSION_NAME_LENGTH = max(map(len, HEADER_SESSION_NAMES))
MAX_WEBSOCKET_HEADER_FIELDS = 256
MAX_WEBSOCKET_IDENTITY_LENGTH = 1024


def _header_value(value):
    """Stored header values are lists. Anything but a single value is ambiguous."""
    if isinstance(value, list):
        if len(value) != 1:
            return None
        value = value[0]
    return value if isinstance(value, str) and value else None


# Unrolled, possessive string form: no per-character backtracking state, so a
# multi-megabyte string is skipped in constant memory.
_JSON_STRING = r'"[^"\\]*+(?:\\.[^"\\]*+)*+"'
_FRAME_TOKEN = re.compile(_JSON_STRING + r'|[\[\]{}]', re.S)
_FRAME_STRING = re.compile(_JSON_STRING, re.S)
_FRAME_SPACE = re.compile(r'[\ufeff \t\r\n]*')
_FRAME_DECODER = json.JSONDecoder()


def _skip_json_value(text, position):
    """End of the JSON value at position, without building it (strings and brackets only)."""
    first = text[position:position + 1]
    if first == '"':
        match = _FRAME_STRING.match(text, position)
        if not match:
            raise ValueError('unterminated string')
        return match.end()
    if first in ('[', '{'):
        depth = 0
        for match in _FRAME_TOKEN.finditer(text, position):
            token = text[match.start()]  # never copy a (possibly huge) string token
            if token == '"':
                continue
            depth += 1 if token in '[{' else -1
            if depth == 0:
                return match.end()
        raise ValueError('unbalanced value')
    return _FRAME_DECODER.raw_decode(text, position)[1]


def _repeated_pairs(pairs):
    names, repeated = {}, set()
    for key, value in pairs:
        name = key.lower() if isinstance(key, str) else key
        if isinstance(value, list) and len(value) > 1:
            # Multi-valued is ambiguous on its own; normalising it to None must
            # not let a later null or empty duplicate look consistent with it.
            repeated.add(name)
        # 'a' and ['a'] are the same header value, and every non-string value is
        # absent; compare as _header_refs would.
        value = _header_value(value)
        if value is not None and len(value) > MAX_WEBSOCKET_IDENTITY_LENGTH:
            value = None  # _header_refs ignores over-long frame identities too
        if name in names and names[name] != value:
            repeated.add(name)
        names.setdefault(name, value)
    return {'repeated': repeated}


def _frame_header_repeats(body):
    """Session headers the raw response.create frame does not state unambiguously.

    json.loads keeps only the last of repeated keys, hiding a conflict. Only the
    top-level object is scanned: the headers value is decoded with conflict
    tracking and every other value is skipped without building objects. A
    repeated headers container, a repeated conversation header, or a frame this
    scan cannot validate refuses the header anchor.
    """
    refused = {'headers'}
    if not isinstance(body, str):
        return refused
    try:
        position = _FRAME_SPACE.match(body).end()
        if body[position:position + 1] != '{':
            return refused
        position += 1
        seen = None
        while True:
            position = _FRAME_SPACE.match(body, position).end()
            if body[position:position + 1] == '}':
                break
            key, position = json.decoder.scanstring(body, position + 1)
            position = _FRAME_SPACE.match(body, position).end()
            if body[position:position + 1] != ':':
                return refused
            position = _FRAME_SPACE.match(body, position + 1).end()
            if key == 'headers':
                if seen is not None or body[position:position + 1] != '{':
                    return refused
                end = _skip_json_value(body, position)
                if end - position > 256 * 1024:
                    return refused
                seen = json.loads(body[position:end], object_pairs_hook=_repeated_pairs)
                position = end
            else:
                position = _skip_json_value(body, position)
            position = _FRAME_SPACE.match(body, position).end()
            if body[position:position + 1] == ',':
                position += 1
            elif body[position:position + 1] != '}':
                return refused
    except (ValueError, IndexError, RecursionError):
        return refused
    if seen is None:
        return set()
    return {header for header in HEADER_SESSION_NAMES if header in seen['repeated']}


def _header_refs(record, refs, max_value_length=None, ambiguous=None):
    headers = record.get('headers') if isinstance(record, dict) else None
    if not isinstance(headers, dict):
        return None, []
    lowered = {}
    observed = {}
    conflicting, values = set(), {}
    for key, value in headers.items():
        key = str(key)
        if len(key) > HEADER_SESSION_NAME_LENGTH:
            continue
        key = key.lower()
        if key not in HEADER_SESSION_NAMES:
            continue
        if isinstance(value, list) and len(value) > 1:
            conflicting.add(key)
        value = _header_value(value)
        if max_value_length is not None and value is not None and len(value) > max_value_length:
            value = None
        if value is not None and not value.strip():
            # A whitespace-only identity is shared by unrelated requests: keep it
            # as evidence, never as an anchor.
            conflicting.add(key)
            observed[key] = value
            lowered[key] = None
            continue
        observed[key] = value
        if value is not None and values.setdefault(key, value) != value:
            conflicting.add(key)
        # Case variants that disagree (including a valid value beside an empty or
        # junk one) stay ambiguous, even after a third value.
        if key in lowered and lowered[key] != value:
            lowered[key] = None
            conflicting.add(key)
        elif key not in lowered:
            lowered[key] = value
    if ambiguous is not None:
        # A multi-valued, conflicting or whitespace conversation header is
        # evidence against any single anchor. A lone empty, null or oversized
        # value is absent, so other explicit evidence can still apply.
        ambiguous.update(header for header, kind, _ in HEADER_SESSION_FIELDS
                         if kind == 'conversation' and header in conflicting)
    # Any ambiguous conversation header is evidence against every header
    # anchor in this container, not only its own.
    conversation_conflict = any(header in conflicting for header, kind, _ in HEADER_SESSION_FIELDS
                                if kind == 'conversation')
    conversation_ref = None
    links = []
    for header, kind, method in HEADER_SESSION_FIELDS:
        value = observed.get(header)
        if not value:
            continue
        unambiguous = lowered.get(header) == value and not (kind == 'conversation' and conversation_conflict)
        ref = refs.opaque('conv', 'header:' + header + ':' + value)
        # Keep the legacy last-observed ref as evidence, not as an anchor.
        # Removing its metadata could release a previously byte-budget-held row.
        links.append({'type': kind, 'ref': ref, 'method': method if unambiguous else method.replace('explicit_', 'ambiguous_', 1),
                      'confidence': 'explicit', 'raw_value_exported': False})
        if kind == 'conversation' and conversation_ref is None and unambiguous:
            conversation_ref = ref
    return conversation_ref, links


def _explicit_links(document, refs):
    links = []
    conversation_ref = None
    for key, kind, method in EXPLICIT_REFS:
        value = document.get(key) if isinstance(document, dict) else None
        if isinstance(value, str) and value:
            ref = refs.opaque('resp' if kind == 'response' else 'conv', value)
            link = {'type': kind, 'ref': ref, 'method': method, 'confidence': 'explicit', 'raw_value_exported': False}
            links.append(link)
            if kind in ('conversation', 'session', 'task') and conversation_ref is None:
                conversation_ref = ref
    return conversation_ref, links


def _arguments(value, refs):
    if value is None:
        return {'arguments': None, 'arguments_text': None, 'parse_status': 'empty'}
    if isinstance(value, dict):
        return {'arguments': value, 'arguments_text': None, 'parse_status': 'parsed'}
    if isinstance(value, list):
        return {'arguments': value, 'arguments_text': None, 'parse_status': 'parsed'}
    if isinstance(value, str):
        if not value.strip():
            return {'arguments': None, 'arguments_text': value, 'parse_status': 'empty'}
        try:
            parsed = json.loads(value)
            return {'arguments': parsed, 'arguments_text': None, 'parse_status': 'parsed'}
        except (ValueError, json.JSONDecodeError):
            return {'arguments': None, 'arguments_text': value, 'parse_status': 'invalid_json'}
    return {'arguments': None, 'arguments_text': str(value), 'parse_status': 'unsupported'}


def _tool_schema(tool, refs):
    if not isinstance(tool, dict):
        return {'name': None, 'description': None, 'parameters': None, 'supported': False}
    function = tool.get('function') if isinstance(tool.get('function'), dict) else tool
    return {'name': function.get('name'), 'description': function.get('description'),
            'parameters': function.get('parameters') or function.get('input_schema'), 'supported': True}


def _add_block(builder, block, origin, role, conversation_ref, links, parent_index=None):
    if isinstance(block, str):
        builder.add('message', origin, {'text': block, 'block_type': 'text', 'authorship': 'unknown',
                    'intent_label': None, 'intent_status': 'unknown'},
                    role=role, linkage_status='explicit' if conversation_ref else 'unknown',
                    coverage_status='unknown', link=links[0] if links else None)
        return
    if not isinstance(block, dict):
        builder.add('unsupported', origin, {'block_type': type(block).__name__, 'withheld': True},
                    role=role, parse_status='unsupported', coverage_status='unsupported')
        return
    if block.get('role') in ('system', 'developer'):
        builder.add('withheld', origin, {'withheld': True, 'reason': 'system_context'},
                    role=block['role'], parse_status='withheld', coverage_status='withheld')
        return
    block_type = block.get('type')
    if block_type in ('text', 'input_text', 'output_text'):
        builder.add('message', origin, {'text': block.get('text', ''), 'block_type': 'text', 'authorship': 'unknown',
                    'intent_label': None, 'intent_status': 'unknown'},
                    role=role, coverage_status='unknown', link=links[0] if links else None)
    elif block_type in ('tool_use', 'function_call'):
        call_ref = builder.refs.opaque('call', str(block.get('call_id') or block.get('id') or ''))
        args = _arguments(block.get('arguments', block.get('input')), builder.refs)
        index = builder.add('tool_call', origin, {'name': block.get('name'), **args, 'call_ref': call_ref},
                            role=role, linkage_status='explicit', call_ref=call_ref,
                            link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id'))
        if block.get('call_id') or block.get('id'):
            builder.call_events[str(block.get('call_id') or block.get('id'))] = index
    elif block_type in ('tool_result', 'function_call_output'):
        call_ref = builder.refs.opaque('call', str(block.get('tool_use_id', block.get('call_id')) or ''))
        result_ref = builder.refs.opaque('result', str(block.get('tool_use_id', block.get('call_id')) or '') + ':result')
        parent = builder.call_events.get(str(block.get('tool_use_id', block.get('call_id'))))
        builder.add('tool_result', origin, {'content': block.get('output', block.get('content')), 'is_error': bool(block.get('is_error')),
                    'call_ref': call_ref, 'result_ref': result_ref}, role=role,
                    linkage_status='explicit', call_ref=call_ref, result_ref=result_ref, parent_index=parent,
                    link=builder.link_for('tool_result', call_ref, 'explicit_tool_call_id'))
    elif block_type in ('thinking', 'redacted_thinking', 'reasoning'):
        builder.add('withheld', origin, {'withheld': True, 'reason': 'reasoning_context'},
                    role=role, parse_status='withheld', coverage_status='withheld')
    elif block_type in ('image', 'document', 'audio', 'file', 'attachment'):
        builder.add('withheld', origin, {'withheld': True, 'reason': 'unsupported_attachment',
                    'media_type': (block.get('source') or {}).get('media_type') if isinstance(block.get('source'), dict) else None},
                    role=role, parse_status='withheld', coverage_status='withheld')
    else:
        builder.add('unsupported', origin, {'block_type': block_type if isinstance(block_type, str) else type(block).__name__,
                    'withheld': True}, role=role, parse_status='unsupported', coverage_status='unsupported')


def _message(builder, message, origin, conversation_ref, links):
    if not isinstance(message, dict):
        builder.add('unsupported', origin, {'block_type': type(message).__name__, 'withheld': True},
                    parse_status='unsupported', coverage_status='unsupported')
        return
    role = message.get('role')
    if role in ('system', 'developer'):
        builder.add('withheld', origin, {'withheld': True, 'reason': 'system_context'},
                    role=role, parse_status='withheld', coverage_status='withheld')
        unknown = set(message) - MESSAGE_KNOWN
        if unknown:
            builder.add('unsupported', origin, {'withheld': True, 'fields': sorted(str(key) for key in unknown)},
                        role=role, parse_status='unsupported', coverage_status='unsupported')
        return role
    content = message.get('content')
    if role == 'tool':
        # A tool message is a result, not an authored assistant/user message.
        content = content
    elif isinstance(content, str):
        _add_block(builder, content, origin, role, conversation_ref, links)
    elif isinstance(content, list):
        for block in content:
            _add_block(builder, block, origin, role, conversation_ref, links)
    elif content is not None:
        builder.add('unsupported', origin, {'block_type': 'content:' + type(content).__name__, 'withheld': True},
                    role=role, parse_status='unsupported', coverage_status='unsupported')
    tool_calls = message.get('tool_calls')
    if tool_calls is not None and not isinstance(tool_calls, list):
        builder.add('unsupported', origin, {'block_type': 'tool_calls:' + type(tool_calls).__name__,
                    'withheld': True}, role=role, parse_status='unsupported', coverage_status='unsupported')
        tool_calls = []
    for source_index, call in enumerate(tool_calls or []):
        if not isinstance(call, dict):
            builder.add('unsupported', origin, {'block_type': 'tool_call:' + type(call).__name__,
                        'source_index': source_index, 'withheld': True}, role=role,
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        function = call.get('function')
        if not isinstance(function, dict):
            builder.add('unsupported', origin, {'block_type': 'tool_call_function:' + type(function).__name__,
                        'source_index': source_index, 'withheld': True}, role=role,
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        raw_id = call.get('id') or ''
        call_ref = builder.refs.opaque('call', str(raw_id))
        args = _arguments(function.get('arguments'), builder.refs)
        index = builder.add('tool_call', origin, {'name': function.get('name'), **args, 'call_ref': call_ref},
                            role=role, linkage_status='explicit', call_ref=call_ref,
                            link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id'))
        if raw_id:
            builder.call_events[str(raw_id)] = index
    legacy = message.get('function_call')
    if isinstance(legacy, dict):
        call_ref = builder.refs.opaque('call', '')
        builder.add('tool_call', origin, {'name': legacy.get('name'), **_arguments(legacy.get('arguments'), builder.refs),
                    'call_ref': call_ref}, role=role, linkage_status='explicit', call_ref=call_ref)
    if role == 'tool':
        raw_id = message.get('tool_call_id') or ''
        call_ref = builder.refs.opaque('call', str(raw_id))
        result_ref = builder.refs.opaque('result', str(raw_id) + ':result')
        parent = builder.call_events.get(str(raw_id))
        builder.add('tool_result', origin, {'content': content, 'is_error': False, 'call_ref': call_ref,
                    'result_ref': result_ref}, role=role, linkage_status='explicit', call_ref=call_ref,
                    result_ref=result_ref, parent_index=parent,
                    link=builder.link_for('tool_result', call_ref, 'explicit_tool_call_id'))
    unknown = set(message) - MESSAGE_KNOWN
    if unknown:
        builder.add('unsupported', origin, {'withheld': True, 'fields': sorted(str(key) for key in unknown)},
                    role=role, parse_status='unsupported', coverage_status='unsupported')
    return role


def _add_response_meta(builder, document, refs, origin='output'):
    usage = document.get('usage') if isinstance(document.get('usage'), dict) else None
    response_ref = None
    if isinstance(document.get('id'), str) and document.get('id'):
        response_ref = refs.opaque('resp', document['id'])
    payload = {'model': document.get('model'), 'stop_reason': document.get('stop_reason') or document.get('finish_reason'),
               'status': document.get('status'), 'usage': usage, 'response_ref': response_ref}
    payload = {key: value for key, value in payload.items() if value is not None}
    if payload:
        builder.add('response_meta', origin, payload, linkage_status='explicit' if response_ref else 'unknown',
                    link=builder.link_for('response', response_ref, 'observed_response_id') if response_ref else None)


def _normalise_complete(builder, document, origin, conversation_ref, links, record_type):
    if not isinstance(document, dict):
        builder.add('unsupported', 'metadata', {'block_type': type(document).__name__, 'withheld': True},
                    parse_status='unsupported', coverage_status='unsupported')
        return
    if isinstance(document.get('error'), dict):
        error = document['error']
        builder.add('error', origin, {'message': error.get('message'), 'error_type': error.get('type'),
                    'code': error.get('code')}, parse_status='parsed', coverage_status='unknown')
        return
    if document.get('instructions') is not None:
        builder.add('withheld', origin, {'withheld': True, 'reason': 'system_context'},
                    role='system', parse_status='withheld', coverage_status='withheld')
    if document.get('role') in ('system', 'developer'):
        builder.add('withheld', origin, {'withheld': True, 'reason': 'system_context'},
                    role=document['role'], parse_status='withheld', coverage_status='withheld')
        return
    if isinstance(document.get('messages'), list):
        system = document.get('system')
        if system is not None:
            builder.add('withheld', origin, {'withheld': True, 'reason': 'system_context'},
                        role='system', parse_status='withheld', coverage_status='withheld')
        for message in document['messages']:
            _message(builder, message, origin, conversation_ref, links)
    elif isinstance(document.get('choices'), list):
        for choice in document['choices']:
            if not isinstance(choice, dict):
                builder.add('unsupported', origin, {'withheld': True, 'reason': 'invalid_choice_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            message = choice.get('message') or choice.get('delta') or {}
            if isinstance(message, dict):
                _message(builder, message, origin, conversation_ref, links)
            else:
                builder.add('unsupported', origin, {'withheld': True, 'reason': 'invalid_choice_payload'},
                            parse_status='unsupported', coverage_status='unsupported')
            finish = choice.get('finish_reason')
            if finish:
                builder.add('completion', origin, {'finish_reason': finish, 'index': choice.get('index')},
                            coverage_status='unknown')
    elif isinstance(document.get('content'), list):
        for block in document['content']:
            _add_block(builder, block, origin, document.get('role') or 'assistant', conversation_ref, links)
    elif isinstance(document.get('output'), list):
        for item in document['output']:
            if not isinstance(item, dict):
                builder.add('unsupported', origin, {'block_type': type(item).__name__, 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            item_type = item.get('type')
            if item_type == 'message':
                for part in item.get('content') or []:
                    _add_block(builder, part, origin, item.get('role') or 'assistant', conversation_ref, links)
            elif item_type == 'function_call':
                raw_id = item.get('call_id')
                call_ref = builder.refs.opaque('call', str(raw_id)) if raw_id else None
                builder.add('tool_call', origin, {'name': item.get('name'), **_arguments(item.get('arguments'), builder.refs),
                            'call_ref': call_ref}, role='assistant',
                            linkage_status='explicit' if call_ref else 'unknown', call_ref=call_ref,
                            link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id') if call_ref else None)
            elif item_type == 'function_call_output':
                raw_id = item.get('call_id')
                call_ref = builder.refs.opaque('call', str(raw_id)) if raw_id else None
                result_ref = builder.refs.opaque('result', str(raw_id) + ':result') if raw_id else None
                builder.add('tool_result', origin, {'content': item.get('output'), 'is_error': False,
                            'call_ref': call_ref, 'result_ref': result_ref}, role='tool',
                            linkage_status='explicit' if call_ref else 'unknown', call_ref=call_ref,
                            result_ref=result_ref,
                            link=builder.link_for('tool_result', call_ref, 'explicit_tool_call_id') if call_ref else None)
            elif item_type in ('reasoning', 'web_search_call', 'file_search_call', 'computer_call', 'local_shell_call'):
                builder.add('withheld', origin, {'withheld': True, 'reason': 'unsupported_output_item',
                            'item_type': item_type}, parse_status='withheld', coverage_status='withheld')
            else:
                builder.add('unsupported', origin, {'block_type': item_type or 'output_item', 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
    elif isinstance(document.get('input'), (str, list)):
        if isinstance(document['input'], str):
            builder.add('message', origin, {'text': document['input'], 'block_type': 'text', 'authorship': 'unknown',
                        'intent_label': None, 'intent_status': 'unknown'}, role='user', coverage_status='unknown')
        else:
            for item in document['input']:
                if isinstance(item, dict) and 'role' in item:
                    _message(builder, item, origin, conversation_ref, links)
                elif isinstance(item, dict) and item.get('type') == 'function_call_output':
                    raw_id = item.get('call_id')
                    call_ref = builder.refs.opaque('call', str(raw_id)) if raw_id else None
                    result_ref = builder.refs.opaque('result', str(raw_id) + ':result') if raw_id else None
                    builder.add('tool_result', origin, {'content': item.get('output'), 'is_error': False,
                                'call_ref': call_ref, 'result_ref': result_ref}, role='tool',
                                linkage_status='explicit' if call_ref else 'unknown', call_ref=call_ref,
                                result_ref=result_ref,
                                parent_index=builder.call_events.get(str(raw_id)),
                                link=builder.link_for('tool_result', call_ref, 'explicit_tool_call_id') if call_ref else None)
                elif isinstance(item, dict) and item.get('type') == 'function_call':
                    raw_id = item.get('call_id')
                    call_ref = builder.refs.opaque('call', str(raw_id)) if raw_id else None
                    builder.add('tool_call', origin, {'name': item.get('name'), **_arguments(item.get('arguments'), builder.refs),
                                'call_ref': call_ref}, role='assistant',
                                linkage_status='explicit' if call_ref else 'unknown', call_ref=call_ref,
                                link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id') if call_ref else None)
                    if raw_id:
                        builder.call_events[str(raw_id)] = len(builder.events) - 1
                else:
                    _add_block(builder, item, origin, None, conversation_ref, links)
    else:
        builder.add('unsupported', 'metadata', {'withheld': True, 'fields': sorted(str(key) for key in document)},
                    parse_status='unsupported', coverage_status='unsupported')
    if document.get('instructions') is not None:
        builder.add('withheld', 'metadata', {'withheld': True, 'reason': 'system_context'}, parse_status='withheld', coverage_status='withheld')
    _add_response_meta(builder, document, builder.refs, origin)
    _tool_schemas(builder, document, origin)
    unknown = set(document) - TOP_LEVEL_KNOWN - {'system'}
    if unknown:
        builder.add('unsupported', 'metadata', {'withheld': True, 'fields': sorted(str(key) for key in unknown)},
                    parse_status='unsupported', coverage_status='unsupported')


def _tool_schemas(builder, document, origin):
    tools = document.get('tools')
    if isinstance(tools, list):
        for tool in tools:
            if not isinstance(tool, dict):
                builder.add('unsupported', origin, {'withheld': True, 'block_type': 'tool'}, parse_status='unsupported',
                            coverage_status='unsupported')
                continue
            schema = _tool_schema(tool, builder.refs)
            if schema['supported']:
                builder.add('tool_schema', origin, schema, parse_status='parsed', coverage_status='unknown')
            else:
                builder.add('unsupported', origin, {'withheld': True, 'block_type': 'tool'}, parse_status='unsupported',
                            coverage_status='unsupported')


def _frame_content(value):
    # Fragments can contain secrets that only become recognisable after
    # assembly. Research exports carry a content-free frame marker only.
    return {'content_present': value is not None, 'frame_type': type(value).__name__}


def _source_frame(builder, frame, event_name):
    status = frame.get('parse_status', 'parsed')
    payload = {'event': event_name, 'frame': _frame_content(frame.get('value')),
               'data_present': bool(frame.get('data'))}
    if frame.get('data') == '[DONE]':
        payload = {'event': event_name, 'frame': None, 'data_present': True, 'done_marker': True}
        status = 'parsed'
    return builder.add('source_frame', 'source_stream', payload, parse_status=status,
                       coverage_status='observed' if status == 'parsed' else 'incomplete')


def _contribute(state, frame):
    index = frame.get('_event_index')
    if index is not None:
        refs = state.setdefault('source_frame_event_indices', [])
        if index not in refs:
            refs.append(index)


def _associate_last_output(builder, indexes):
    if not indexes:
        return
    event = builder.events[-1]
    if event['origin'] == 'output':
        event['payload']['source_frame_event_indices'] = list(dict.fromkeys(indexes))
        event['payload']['fragment_count'] = len(event['payload']['source_frame_event_indices'])


def _response_item_text(builder, item):
    content = item.get('content') or []
    if not isinstance(content, list):
        builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_content_shape'},
                    parse_status='unsupported', coverage_status='unsupported')
        return ''
    pieces = []
    for part in content:
        if not isinstance(part, dict) or part.get('type') not in ('output_text', 'text'):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'unsupported_response_content_part'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        text = part.get('text', '')
        if not isinstance(text, str):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_text_fragment'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        pieces.append(text)
    return ''.join(pieces)


def _assemble_anthropic(builder, frames, conversation_ref, links):
    known = {'message_start', 'content_block_start', 'content_block_delta', 'content_block_stop',
             'message_delta', 'message_stop', 'error', 'ping'}
    states = OrderedDict()
    text = []
    model = None
    complete = False
    stop_reason = None
    control_frames = []
    for frame in frames:
        builder.current_source_frame_index = frame.get('_event_index')
        value = frame.get('value')
        name = frame.get('event')
        if not isinstance(value, dict):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_stream_frame'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        event_type = value.get('type') or name
        if event_type == 'message_start':
            control_frames.append(frame.get('_event_index'))
            message = value.get('message') or {}
            if not isinstance(message, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_message_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            model = message.get('model') or model
            content = message.get('content') or []
            if not isinstance(content, list):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_content_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            for block in content:
                _add_block(builder, block, 'output', message.get('role') or 'assistant', conversation_ref, links)
        elif event_type == 'content_block_start':
            index = value.get('index')
            if not isinstance(index, (int, str)):
                builder.add('unsupported', 'output', {'block_type': 'content_block_without_index', 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            block = value.get('content_block') or {}
            if not isinstance(block, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_content_block'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            states[index] = {'index': index, 'type': block.get('type'), 'text': block.get('text') or '',
                             'json': '', 'name': block.get('name'), 'id': block.get('id'),
                             'input': block.get('input'), 'source_frame_event_indices': [frame.get('_event_index')]}
        elif event_type == 'content_block_delta':
            index = value.get('index')
            if not isinstance(index, (int, str)):
                builder.add('unsupported', 'output', {'block_type': 'content_delta_without_index', 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            state = states.setdefault(index, {'index': index, 'type': 'text', 'text': '', 'json': ''})
            delta = value.get('delta') or {}
            if not isinstance(delta, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_delta_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            if delta.get('type') == 'text_delta':
                fragment = delta.get('text') or ''
                if not isinstance(fragment, str):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_text_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                else:
                    _contribute(state, frame)
                    state['text'] += fragment
            elif delta.get('type') == 'input_json_delta':
                fragment = delta.get('partial_json') or ''
                if not isinstance(fragment, str):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_json_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                else:
                    _contribute(state, frame)
                    state['json'] += fragment
            elif delta.get('type') == 'thinking_delta':
                fragment = delta.get('thinking') or ''
                if not isinstance(fragment, str):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_thinking_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                else:
                    _contribute(state, frame)
                    state['type'] = 'thinking'
                    state['text'] += fragment
            else:
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'unsupported_anthropic_delta'},
                            parse_status='unsupported', coverage_status='unsupported')
        elif event_type == 'message_delta':
            control_frames.append(frame.get('_event_index'))
            delta = value.get('delta') or {}
            if not isinstance(delta, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_message_delta'},
                            parse_status='unsupported', coverage_status='unsupported')
            else:
                stop_reason = delta.get('stop_reason') or stop_reason
        elif event_type == 'message_stop':
            complete = True
            control_frames.append(frame.get('_event_index'))
        elif event_type == 'error':
            error = value.get('error') or {}
            if not isinstance(error, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_anthropic_error_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
            else:
                builder.add('error', 'output', {'message': error.get('message'), 'error_type': error.get('type')},
                            coverage_status='unknown')
        elif event_type not in known:
            builder.add('unsupported', 'output', {'block_type': str(event_type), 'withheld': True,
                        'reason': 'unrecognised_stream_event'}, parse_status='unsupported', coverage_status='unsupported')
        else:
            control_frames.append(frame.get('_event_index'))
    builder.current_source_frame_index = None
    for state in states.values():
        status = 'complete' if complete else 'incomplete'
        if state.get('type') == 'tool_use':
            raw = state.get('json') or ''
            args = _arguments(raw if raw else state.get('input'), builder.refs)
            call_ref = builder.refs.opaque('call', str(state.get('id') or ''))
            event_index = builder.add('tool_call', 'output', {'name': state.get('name'), **args, 'call_ref': call_ref,
                        'stream_status': status}, role='assistant', linkage_status='explicit', call_ref=call_ref,
                        parse_status=args['parse_status'], coverage_status=status,
                        link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id'))
            _associate_last_output(builder, state.get('source_frame_event_indices', []))
        elif state.get('type') == 'thinking':
            builder.add('withheld', 'output', {'withheld': True, 'reason': 'reasoning_context', 'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        role='assistant', parse_status='withheld', coverage_status=status)
        elif state.get('type') not in ('text', None):
            builder.add('unsupported', 'output', {'block_type': state.get('type'), 'withheld': True,
                        'stream_status': status, 'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        role='assistant', parse_status='unsupported', coverage_status='unsupported')
        else:
            builder.add('message', 'output', {'text': state.get('text', ''), 'block_type': 'text',
                        'authorship': 'model_output', 'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])}, role='assistant',
                        coverage_status=status)
    if model or stop_reason or control_frames:
        builder.add('response_meta', 'output', {'model': model, 'stop_reason': stop_reason,
                    'stream_complete': complete, 'source_frame_event_indices': control_frames}, coverage_status='unknown')
    return complete


def _assemble_openai(builder, frames, conversation_ref, links):
    choices = {}
    complete = False
    control_frames = []
    for frame in frames:
        builder.current_source_frame_index = frame.get('_event_index')
        value = frame.get('value')
        if not isinstance(value, dict):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_stream_frame'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        if value.get('choices') is None:
            if isinstance(value.get('error'), dict):
                error = value['error']
                builder.add('error', 'output', {'message': error.get('message'), 'error_type': error.get('type'),
                            'code': error.get('code')}, coverage_status='unknown')
            else:
                control_frames.append(frame.get('_event_index'))
            continue
        if not isinstance(value.get('choices'), list):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_choices_shape'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        for choice in value['choices']:
            if not isinstance(choice, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_choice_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            index = choice.get('index', 0)
            if not isinstance(index, (int, str)):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_choice_index'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            state = choices.setdefault(index, {'text': '', 'tools': OrderedDict(), 'finish': None})
            delta = choice.get('delta') or {}
            if not isinstance(delta, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_delta_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            unknown_delta = set(delta) - {'role', 'content', 'tool_calls', 'function_call'}
            if unknown_delta:
                builder.add('unsupported', 'output', {'block_type': 'openai_delta_fields', 'withheld': True,
                            'fields': sorted(str(key) for key in unknown_delta)}, parse_status='unsupported',
                            coverage_status='unsupported')
            if 'role' in delta:
                control_frames.append(frame.get('_event_index'))
            if delta.get('content') is not None and not isinstance(delta.get('content'), str):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_content_delta'},
                            parse_status='unsupported', coverage_status='unsupported')
            if isinstance(delta.get('content'), str):
                _contribute(state, frame)
                state['text'] += delta['content']
            tool_calls = delta.get('tool_calls')
            if tool_calls is not None and not isinstance(tool_calls, list):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_tool_calls_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                tool_calls = []
            for source_index, tool in enumerate(tool_calls or []):
                if not isinstance(tool, dict):
                    builder.add('unsupported', 'output', {'block_type': 'tool_call:' + type(tool).__name__,
                                'source_index': source_index, 'withheld': True}, parse_status='unsupported',
                                coverage_status='unsupported')
                    continue
                key = tool.get('index')
                if key is None:
                    key = tool.get('id')
                if key is None:
                    builder.add('unsupported', 'output', {'block_type': 'tool_call_without_index_or_id', 'withheld': True},
                                parse_status='unsupported', coverage_status='unsupported')
                    continue
                if not isinstance(key, (int, str)):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_tool_index'},
                                parse_status='unsupported', coverage_status='unsupported')
                    continue
                tool_state = state['tools'].setdefault(key, {'id': None, 'name': None, 'arguments': '', 'index': key})
                _contribute(tool_state, frame)
                if tool.get('id'):
                    tool_state['id'] = tool['id']
                function = tool.get('function') or {}
                if not isinstance(function, dict):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_function_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                    continue
                if function.get('name'):
                    tool_state['name'] = function['name']
                if function.get('arguments') is not None:
                    if isinstance(function['arguments'], str):
                        tool_state['arguments'] += function['arguments']
                    else:
                        builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_argument_fragment'},
                                    parse_status='unsupported', coverage_status='unsupported')
            legacy = delta.get('function_call')
            if isinstance(legacy, dict):
                tool_state = state['tools'].setdefault(0, {'id': None, 'name': None, 'arguments': '', 'index': 0})
                _contribute(tool_state, frame)
                if legacy.get('name'):
                    tool_state['name'] = legacy['name']
                if legacy.get('arguments'):
                    tool_state['arguments'] += legacy['arguments']
            elif legacy is not None:
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_openai_function_call_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
            if choice.get('finish_reason'):
                state['finish'] = choice['finish_reason']
                complete = True
                control_frames.append(frame.get('_event_index'))
        if value.get('usage') is not None:
            builder.add('response_meta', 'output', {'usage': value['usage']}, coverage_status='unknown')
    builder.current_source_frame_index = None
    for index, state in choices.items():
        status = 'complete' if state['finish'] else 'incomplete'
        if state['text']:
            builder.add('message', 'output', {'text': state['text'], 'block_type': 'text', 'authorship': 'model_output',
                        'stream_status': status, 'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        role='assistant', coverage_status=status)
        for key, tool_state in state['tools'].items():
            raw_id = tool_state.get('id') or ''
            call_ref = builder.refs.opaque('call', str(raw_id) if raw_id else '')
            args = _arguments(tool_state.get('arguments'), builder.refs)
            builder.add('tool_call', 'output', {'name': tool_state.get('name'), **args, 'call_ref': call_ref,
                        'stream_status': status, 'source_frame_event_indices': tool_state.get('source_frame_event_indices', [])},
                        role='assistant', linkage_status='explicit', call_ref=call_ref,
                        parse_status=args['parse_status'], coverage_status=status,
                        link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id'))
        if state['finish']:
            builder.add('completion', 'output', {'finish_reason': state['finish'], 'choice_index': index,
                        'source_frame_event_indices': control_frames},
                        coverage_status='unknown')
    if control_frames and not any(event['kind'] == 'completion' for event in builder.events
                                  if event['origin'] == 'output'):
        builder.add('response_meta', 'output', {'protocol_control': True,
                    'source_frame_event_indices': list(dict.fromkeys(control_frames))}, coverage_status='unknown')
    return complete


def _assemble_responses(builder, frames, conversation_ref, links):
    known = {'response.created', 'response.failed', 'response.incomplete', 'response.completed',
             'response.output_item.added', 'response.output_item.done', 'response.output_text.delta',
             'response.output_text.done', 'response.content_part.added', 'response.content_part.done',
             'response.function_call_arguments.delta', 'response.function_call_arguments.done', 'error'}
    items = OrderedDict()
    complete = False
    response_meta = {}
    control_frames = []
    for frame in frames:
        builder.current_source_frame_index = frame.get('_event_index')
        value = frame.get('value')
        if not isinstance(value, dict):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_stream_frame'},
                        parse_status='unsupported', coverage_status='unsupported')
            continue
        event_type = value.get('type') or frame.get('event')
        if event_type == 'response.created':
            control_frames.append(frame.get('_event_index'))
            response = value.get('response') or {}
            if not isinstance(response, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            response_meta = {'model': response.get('model'), 'status': response.get('status'),
                             'response_ref': builder.refs.opaque('resp', str(response.get('id') or ''))}
            continue
        if event_type in ('response.failed', 'error'):
            control_frames.append(frame.get('_event_index'))
            complete = False
            response = value.get('response') or {}
            error = value.get('error') or (response.get('error') if isinstance(response, dict) else None) or {}
            if not isinstance(error, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_error_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
            else:
                builder.add('error', 'output', {'message': error.get('message'), 'error_type': error.get('type'),
                            'code': error.get('code')}, coverage_status='unknown')
            continue
        if event_type == 'response.incomplete':
            control_frames.append(frame.get('_event_index'))
            complete = False
            builder.add('completion', 'output', {'response_status': 'incomplete'}, coverage_status='incomplete')
            continue
        if event_type == 'response.completed':
            control_frames.append(frame.get('_event_index'))
            complete = True
            response = value.get('response') or {}
            if not isinstance(response, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                response = {}
            update = {'model': response.get('model'), 'status': response.get('status'),
                      'usage': response.get('usage')}
            # Align the emitted metadata with the id used for identity.
            if isinstance(response.get('id'), str) and response['id']:
                update['response_ref'] = builder.refs.opaque('resp', response['id'])
            response_meta.update(update)
            response_output = response.get('output') or []
            if not isinstance(response_output, list):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_output_shape'},
                            parse_status='unsupported', coverage_status='unsupported')
                response_output = []
            for source_index, item in enumerate(response_output):
                if not isinstance(item, dict):
                    builder.add('unsupported', 'output', {'block_type': 'response_output_item:' + type(item).__name__,
                                'source_index': source_index, 'withheld': True}, parse_status='unsupported',
                                coverage_status='unsupported')
                    continue
                item_id = item.get('id')
                call_id = item.get('call_id')
                key = item_id or call_id
                if key is not None and not isinstance(key, (int, str)):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_item_id'},
                                parse_status='unsupported', coverage_status='unsupported')
                    continue
                if key not in items and call_id:
                    key = next((candidate for candidate, state in items.items()
                                if state.get('id') == call_id), key)
                if key not in items:
                    key = key if key is not None else ('completed_item', source_index)
                    items[key] = {'type': item.get('type'), 'text': '', 'arguments': '',
                                  'name': item.get('name'), 'id': call_id, 'done': True,
                                  'source_frame_event_indices': []}
                state = items[key]
                _contribute(state, frame)
                state['type'] = item.get('type') or state.get('type')
                state['name'] = item.get('name') or state.get('name')
                if call_id:
                    state['id'] = call_id
                if item.get('type') == 'message':
                    # Final item text is already assembled by the provider; replace
                    # the matching deltas instead of appending the same content.
                    state['text'] = _response_item_text(builder, item)
                elif item.get('type') == 'function_call':
                    state['arguments'] = item.get('arguments') or state.get('arguments', '')
                state['done'] = True
            continue
        if event_type == 'response.output_item.added':
            item = value.get('item') or {}
            if not isinstance(item, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_output_item'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            key = item.get('id') or item.get('call_id') or len(items)
            if not isinstance(key, (int, str)):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_item_id'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            items[key] = {'type': item.get('type'), 'text': '', 'arguments': item.get('arguments') or '',
                          'name': item.get('name'), 'id': item.get('call_id'), 'done': False,
                          'source_frame_event_indices': [frame.get('_event_index')]}
            continue
        if event_type in ('response.output_text.delta', 'response.content_part.added'):
            key = value.get('item_id') or (value.get('item', {}).get('id') if isinstance(value.get('item'), dict) else None)
            if not key:
                builder.add('unsupported', 'output', {'block_type': 'response_text_without_item_id', 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            state = items.setdefault(key, {'type': 'message', 'text': '', 'arguments': '', 'name': None,
                                           'id': None, 'done': False, 'source_frame_event_indices': []})
            _contribute(state, frame)
            if event_type == 'response.output_text.delta':
                fragment = value.get('delta') or ''
                if not isinstance(fragment, str):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_text_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                else:
                    state['text'] += fragment
            else:
                part = value.get('part') or {}
                if not isinstance(part, dict):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_content_part'},
                                parse_status='unsupported', coverage_status='unsupported')
                elif part.get('type') in ('output_text', 'text'):
                    fragment = part.get('text') or ''
                    if not isinstance(fragment, str):
                        builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_text_fragment'},
                                    parse_status='unsupported', coverage_status='unsupported')
                    else:
                        state['text'] += fragment
                else:
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'unsupported_response_content_part'},
                                parse_status='unsupported', coverage_status='unsupported')
            continue
        if event_type in ('response.function_call_arguments.delta', 'response.function_call_arguments.done'):
            key = value.get('item_id')
            if not key:
                builder.add('unsupported', 'output', {'block_type': 'response_arguments_without_item_id', 'withheld': True},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            state = items.setdefault(key, {'type': 'function_call', 'text': '', 'arguments': '',
                                           'name': None, 'id': None, 'done': False,
                                           'source_frame_event_indices': []})
            _contribute(state, frame)
            if event_type.endswith('.delta'):
                fragment = value.get('delta') or ''
                if not isinstance(fragment, str):
                    builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_argument_fragment'},
                                parse_status='unsupported', coverage_status='unsupported')
                else:
                    state['arguments'] += fragment
            else:
                state['arguments'] = value.get('arguments') or state['arguments']
                state['done'] = True
            continue
        if event_type == 'response.output_item.done':
            item = value.get('item') or {}
            if not isinstance(item, dict):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_output_item'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            key = item.get('id') or item.get('call_id') or len(items)
            if not isinstance(key, (int, str)):
                builder.add('unsupported', 'output', {'withheld': True, 'reason': 'invalid_response_item_id'},
                            parse_status='unsupported', coverage_status='unsupported')
                continue
            state = items.setdefault(key, {'type': item.get('type'), 'text': '', 'arguments': '',
                                           'name': item.get('name'), 'id': item.get('call_id'),
                                           'done': True, 'source_frame_event_indices': []})
            _contribute(state, frame)
            if item.get('call_id') and item.get('type') == 'function_call':
                # output_item.done explicitly maps the provisional item id
                # used by argument deltas to the provider's call id.
                state['id'] = item['call_id']
            if item.get('type') == 'message':
                state['text'] = _response_item_text(builder, item)
            elif item.get('type') == 'function_call':
                state['arguments'] = item.get('arguments') or state['arguments']
                state['name'] = item.get('name') or state['name']
            state['done'] = True
            continue
        if event_type not in known:
            builder.add('unsupported', 'output', {'block_type': str(event_type), 'withheld': True,
                        'reason': 'unrecognised_stream_event'}, parse_status='unsupported', coverage_status='unsupported')
        else:
            control_frames.append(frame.get('_event_index'))
    builder.current_source_frame_index = None
    for key, state in items.items():
        status = 'complete' if complete and state.get('done') else 'incomplete'
        item_type = state.get('type')
        if item_type == 'message' or (item_type is None and state.get('text')):
            builder.add('message', 'output', {'text': state.get('text', ''), 'block_type': 'text',
                        'authorship': 'model_output', 'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        role='assistant', coverage_status=status)
        elif item_type == 'function_call':
            raw_id = state.get('id') or ''
            call_ref = builder.refs.opaque('call', str(raw_id)) if raw_id else None
            args = _arguments(state.get('arguments'), builder.refs)
            builder.add('tool_call', 'output', {'name': state.get('name'), **args, 'call_ref': call_ref,
                        'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])}, role='assistant',
                        linkage_status='explicit' if call_ref else 'unknown', call_ref=call_ref,
                        parse_status=args['parse_status'], coverage_status=status,
                        link=builder.link_for('tool_call', call_ref, 'explicit_tool_call_id') if call_ref else None)
        elif item_type in ('reasoning', 'web_search_call', 'file_search_call'):
            builder.add('withheld', 'output', {'withheld': True, 'reason': 'unsupported_output_item',
                        'item_type': item_type, 'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        parse_status='withheld', coverage_status='withheld')
        else:
            builder.add('unsupported', 'output', {'block_type': item_type or 'output_item', 'withheld': True,
                        'stream_status': status,
                        'source_frame_event_indices': state.get('source_frame_event_indices', [])},
                        parse_status='unsupported', coverage_status='unsupported')
    if response_meta:
        response_meta['source_frame_event_indices'] = control_frames
        builder.add('response_meta', 'output', {key: value for key, value in response_meta.items() if value is not None},
                    coverage_status='unknown')
    elif control_frames:
        builder.add('response_meta', 'output', {'protocol_control': True,
                    'source_frame_event_indices': control_frames}, coverage_status='unknown')
    return complete


def _has_stream_shape(values):
    for value in values:
        if not isinstance(value, dict):
            continue
        event_type = value.get('type')
        if isinstance(event_type, str) and (event_type.startswith('response.') or event_type.startswith('message_')
                                            or event_type.startswith('content_block_')):
            return True
        if 'choices' in value:
            return True
    return False


def _stream_kind(values, frames):
    text = ' '.join(str(item.get('event') or '') for item in frames)
    if 'response.' in text or any(isinstance(value, dict) and str(value.get('type', '')).startswith('response.')
                                  for value in values):
        return 'responses'
    if any(isinstance(value, dict) and 'choices' in value for value in values):
        return 'openai'
    return 'anthropic'


def derive_events(record, refs):
    """Return parser-versioned, unsanitised events for one source record."""
    body = record.get('body')
    parsed = classify_body(body)
    builder = Builder(refs)
    document = None
    if parsed['values'] and isinstance(parsed['values'][0]['value'], dict):
        document = parsed['values'][0]['value']
    conversation_ref = None
    links = []
    # Only provider envelopes carry response identity, never gateway request IDs
    # or IDs inside replayed messages/tools.
    documents = [item['value'] for item in parsed['values']]
    documents.extend(frame['value'] for frame in parsed['frames'])
    identity_documents = []
    envelope_refs = set()
    terminal_refs = set()
    for value in documents:
        if not isinstance(value, dict):
            continue
        identity_documents.append(value)
        if str(value.get('type', '')).startswith('response.') and isinstance(value.get('response'), dict):
            nested = value['response']
            identity_documents.append(nested)
            nested_id = nested.get('id')
            if record.get('type') == 'response' and isinstance(nested_id, str) and nested_id:
                envelope_refs.add(refs.opaque('resp', nested_id))
                # A Responses stream reports distinct created/in_progress/completed
                # IDs. Live data shows previous_response_id always references the
                # completed one, so that is the only usable chain anchor.
                if value.get('type') == 'response.completed':
                    terminal_refs.add(refs.opaque('resp', nested_id))
        if value.get('type') == 'message_start' and isinstance(value.get('message'), dict):
            identity_documents.append(value['message'])
    response_refs = set()
    for value in identity_documents:
        ref, explicit = _explicit_links(value, refs)
        conversation_ref = conversation_ref or ref
        for link in explicit:
            if link not in links:
                links.append(link)
        if record.get('type') == 'response' and isinstance(value.get('id'), str) and value['id']:
            # Stream event IDs belong to frames, not responses.
            if not str(value.get('type', '')).startswith(('response.', 'content_block_', 'message_')):
                response_refs.add(refs.opaque('resp', value['id']))
    # Only collapse a stream whose every response id came from response.*
    # envelopes. A mixed record that also carries an unrelated top-level
    # document id stays ambiguous instead of being narrowed to the completed id.
    if len(terminal_refs) == 1 and len(response_refs) > 1 and response_refs == envelope_refs:
        response_refs = terminal_refs
    ambiguous_headers = set()
    header_ref, header_links = _header_refs(record, refs, ambiguous=ambiguous_headers)
    # The WebSocket gateway stores request headers inside its single
    # response.create frame, not on the record. Only this protocol boundary is
    # evidence: nested content, response headers and mixed/batched frames are not.
    # Optional identity extraction must not rescan arbitrarily large containers.
    if (record.get('endpoint') == 'responses-ws' and record.get('type') == 'request'
            and parsed['format'] == 'json' and isinstance(document, dict)
            and document.get('type') == 'response.create'
            and isinstance(document.get('headers'), dict)
            and len(document['headers']) <= MAX_WEBSOCKET_HEADER_FIELDS):
        body_header_ref, body_header_links = _header_refs(document, refs, MAX_WEBSOCKET_IDENTITY_LENGTH,
                                                          ambiguous=ambiguous_headers)
        frame_repeats = _frame_header_repeats(body)
        ambiguous_headers.update(header for header in frame_repeats if header == 'headers' or header in CONVERSATION_HEADERS)
        # A repeated task header is not an anchor, but its last value must not
        # be exported as an explicit link either.
        body_header_links = [link for link in body_header_links
                             if 'headers' not in frame_repeats and not METHOD_HEADERS.get(link['method'], set()) & frame_repeats]
        if ambiguous_headers or (header_ref and body_header_ref and header_ref != body_header_ref):
            # Refused anchor: export no frame links (new metadata), and mark the
            # record's own conversation links ambiguous so no exported link
            # advertises the join that was refused. Relabelling only grows events.
            header_ref = None
            header_links = [dict(link, method=link['method'].replace('explicit_', 'ambiguous_', 1))
                            if link['type'] == 'conversation' else link for link in header_links]
        else:
            header_ref = header_ref or body_header_ref
            # Frame-level ambiguous links are new metadata with no hold to
            # preserve; do not export a joinable ref for them.
            header_links.extend(link for link in body_header_links if not link['method'].startswith('ambiguous_'))
    conversation_ref = conversation_ref or header_ref
    for link in header_links:
        if link not in links:
            links.append(link)
    identity = {'response_refs': sorted(response_refs)}
    if isinstance(record, dict):
        record_links = []
        for key, kind, method in EXPLICIT_REFS:
            value = record.get(key)
            if isinstance(value, str) and value and key not in (document or {}):
                ref = refs.opaque('resp' if kind == 'response' else 'conv', value)
                record_links.append({'type': kind, 'ref': ref, 'method': method, 'confidence': 'explicit',
                                     'raw_value_exported': False})
                if kind in ('conversation', 'session', 'task') and conversation_ref is None:
                    conversation_ref = ref
        links = record_links + links
    builder.add('observation', 'metadata', {'record_type': record.get('type'), 'document_format': parsed['format'],
                'stream_complete': None, 'headers_withheld': bool(record.get('headers'))},
                linkage_status='explicit' if conversation_ref else 'unknown',
                coverage_status='unknown', link=links[0] if links else None)
    if record.get('headers'):
        builder.add('withheld', 'metadata', {'withheld': True, 'reason': 'headers'}, parse_status='withheld',
                    coverage_status='withheld')

    if parsed['format'] == 'empty':
        builder.add('empty', 'metadata', {}, parse_status='empty', coverage_status='unknown')
        return {'parser_version': PARSER_VERSION, 'format': parsed['format'], 'parse_status': parsed['parse_status'],
                'stream_complete': None, 'events': builder.events, 'conversation_ref': conversation_ref, 'links': links, **identity}
    if parsed['format'] == 'malformed':
        builder.add('parse_error', 'metadata', {'byte_length': len((body or '').encode()), 'reason': 'malformed_json'},
                    parse_status='malformed', coverage_status='unknown')
        return {'parser_version': PARSER_VERSION, 'format': parsed['format'], 'parse_status': 'malformed',
                'stream_complete': False, 'events': builder.events, 'conversation_ref': conversation_ref, 'links': links, **identity}

    frames = parsed['frames']
    values = [item['value'] for item in parsed['values']]
    stream_complete = None
    end_marker_observed = None
    if frames:
        for frame in frames:
            frame['_event_index'] = _source_frame(builder, frame, frame.get('event'))
        stream_complete = _stream_kind([frame.get('value') for frame in frames], frames)
        kind = stream_complete
        actual = [frame for frame in frames if frame.get('value') is not None]
        invalid = [frame for frame in frames if frame.get('value') is None and frame.get('data') != '[DONE]']
        for frame in invalid:
            builder.current_source_frame_index = frame.get('_event_index')
            builder.add('unsupported', 'output', {'withheld': True,
                        'reason': 'invalid_source_frame' if frame.get('parse_status') != 'empty' else 'empty_source_frame'},
                        parse_status='unsupported', coverage_status='unsupported')
        if kind == 'openai':
            stream_complete = _assemble_openai(builder, actual, conversation_ref, links)
        elif kind == 'responses':
            stream_complete = _assemble_responses(builder, actual, conversation_ref, links)
        else:
            stream_complete = _assemble_anthropic(builder, actual, conversation_ref, links)
        end_marker_observed = stream_complete
        builder.current_source_frame_index = None
        if not any(event['origin'] == 'output' for event in builder.events):
            builder.add('unsupported', 'output', {'withheld': True, 'reason': 'unrecognised_stream_assembly'},
                        parse_status='unsupported', coverage_status='unsupported')
    elif parsed['format'] == 'consecutive_json':
        value_indexes = []
        for item in parsed['values']:
            frame = {'event': 'json', 'value': item['value'], 'data': item['raw'], 'parse_status': 'parsed'}
            value_indexes.append(_source_frame(builder, frame, 'json'))
        if _has_stream_shape(values):
            kind = _stream_kind(values, [])
            stream_frames = [{'value': value, '_event_index': value_indexes[index]}
                             for index, value in enumerate(values)]
            if kind == 'openai':
                stream_complete = _assemble_openai(builder, stream_frames, conversation_ref, links)
            elif kind == 'responses':
                stream_complete = _assemble_responses(builder, stream_frames, conversation_ref, links)
            else:
                stream_complete = _assemble_anthropic(builder, stream_frames, conversation_ref, links)
            end_marker_observed = stream_complete
        else:
            for index, value in enumerate(values):
                builder.current_source_frame_index = value_indexes[index]
                _normalise_complete(builder, value, 'output' if record.get('type') == 'response' else 'history',
                                    conversation_ref, links, record.get('type'))
        builder.current_source_frame_index = None
    elif document is not None:
        origin = 'output' if record.get('type') == 'response' else 'history'
        _normalise_complete(builder, document, origin, conversation_ref, links, record.get('type'))
    else:
        builder.add('unsupported', 'metadata', {'withheld': True, 'block_type': type(document).__name__
                    if document is not None else 'non_object_json'}, parse_status='unsupported', coverage_status='unsupported')

    unsupported_stream = any(event['origin'] == 'output' and
                             (event['kind'] == 'unsupported' or event['coverage_status'] == 'unsupported')
                             for event in builder.events)
    if end_marker_observed is not None:
        for event in builder.events:
            if event['kind'] == 'response_meta' and event['origin'] == 'output':
                event['payload']['end_marker_observed'] = end_marker_observed
    if unsupported_stream:
        stream_complete = False
        for event in builder.events:
            if event['origin'] == 'output':
                if event['coverage_status'] == 'complete':
                    event['coverage_status'] = 'incomplete'
                if 'stream_status' in event['payload'] and event['payload']['stream_status'] == 'complete':
                    event['payload']['stream_status'] = 'incomplete'
                if event['kind'] == 'response_meta' and 'stream_complete' in event['payload']:
                    event['payload']['stream_complete'] = False

    if parsed['parse_status'] == 'partial':
        stream_complete = False
        builder.add('parse_error', 'metadata', {'reason': 'partial_stream', 'error_offset': parsed.get('error_offset')}, parse_status='partial', coverage_status='incomplete')
        for event in builder.events:
            if event['coverage_status'] == 'complete':
                event['coverage_status'] = 'incomplete'
                if 'stream_status' in event['payload']: event['payload']['stream_status'] = 'incomplete'
    truncated = record.get('truncated') is True or (isinstance(document, dict) and document.get('truncated') is True)
    summary_present = isinstance(document, dict) and any(key in document for key in ('summary', 'summaries'))
    if truncated:
        builder.add('unsupported', 'metadata', {'withheld': True, 'reason': 'provider_truncated'},
                    parse_status='incomplete', coverage_status='incomplete')
    if summary_present:
        summary = document.get('summaries', document.get('summary'))
        builder.add('unsupported', 'metadata', {'withheld': True, 'reason': 'source_summary_present',
                    'summary_count': len(summary) if isinstance(summary, list) else 1},
                    parse_status='unsupported', coverage_status='partial')
    if truncated or parsed['parse_status'] == 'partial':
        stream_complete = False
        for event in builder.events:
            if event['coverage_status'] == 'complete':
                event['coverage_status'] = 'incomplete'
                if 'stream_status' in event['payload']:
                    event['payload']['stream_status'] = 'incomplete'
    if frames:
        for event in builder.events:
            if event['kind'] == 'response_meta' and event['origin'] == 'output':
                event['payload']['supported_content_complete'] = bool(stream_complete)
    for event in builder.events:
        if event.get('parent_event_index') is not None:
            parent = builder.events[event['parent_event_index']]
            event['parent_event_id'] = None
            event['parent_event_local'] = parent['event_index']
        if event.get('link'):
            event['linkage_status'] = 'explicit'
    return {'parser_version': PARSER_VERSION, 'format': parsed['format'], 'parse_status': parsed['parse_status'],
            'stream_complete': stream_complete, 'end_marker_observed': end_marker_observed,
            'events': builder.events, 'conversation_ref': conversation_ref,
            'links': links, **identity}
