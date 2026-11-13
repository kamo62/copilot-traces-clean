"""Focused synthetic checks for parsing, sanitisation, role isolation and export."""
import gzip
import hashlib
import http.client
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import auth
import parsing
import research
from sanitise import AssistedSpanDetector, HoldError, Policy, RefFactory, Sanitizer, canonical


def policy_data():
    return {
        'policy_version': 'synthetic-1', 'scope': 'synthetic-scope',
        'aliases': {'organisations': ['Example Holdings', 'example-holdings'],
                    'people': ['Alex Example'], 'products': ['Comet Pricing'],
                    'repositories': ['example-holdings/pricing-service'],
                    'hosts': ['pricing.internal.example'], 'work_items': ['PRICING-1234']},
        'withhold_keys': ['headers', 'authorization', 'cookie'],
        'assisted_detector': {'enabled': False, 'policy_version': 'disabled'},
        'retention': {'raw': 'manual', 'curated': 'manual'},
    }


def sanitizer():
    return Sanitizer(Policy(policy_data(), b'k' * 48))


def derive(body, record_type='request', extra=None):
    record = {'type': record_type, 'body': body, 'headers': {'Authorization': 'secret'}}
    record.update(extra or {})
    return parsing.derive_events(record, sanitizer().refs)


def sanitized_events(result):
    clean = sanitizer()
    return [clean.payload(event['payload']) for event in result['events']]


class ParserTests(unittest.TestCase):
    def test_consecutive_json_uses_raw_decode_and_preserves_escaped_newlines(self):
        body = ('{"messages":[{"role":"user","content":"line one\\nline two"}]}'
                '{"messages":[{"role":"user","content":"line one\\nline two"}]}')
        parsed = parsing.classify_body(body)
        self.assertEqual(parsed['format'], 'consecutive_json')
        self.assertEqual(len(parsed['values']), 2)
        result = derive(body)
        messages = [event for event in result['events'] if event['kind'] == 'message']
        self.assertEqual(len(messages), 2)  # repeated text is not deduplicated
        self.assertEqual(messages[0]['payload']['text'], 'line one\nline two')
        self.assertEqual(messages[1]['payload']['text'], 'line one\nline two')

    def test_sse_frames_and_assembly_are_distinct(self):
        body = '''event: message_start
data: {"type":"message_start","message":{"model":"claude","role":"assistant","content":[]}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hello\\nworld"}}

event: message_stop
data: {"type":"message_stop"}

'''
        result = derive(body, 'response')
        self.assertEqual(result['format'], 'sse')
        self.assertTrue(result['stream_complete'])
        self.assertTrue(any(event['kind'] == 'source_frame' and event['origin'] == 'source_stream'
                            for event in result['events']))
        assembled = [event for event in result['events'] if event['kind'] == 'message' and event['origin'] == 'output']
        self.assertEqual(assembled[0]['payload']['text'], 'Hello\nworld')

    def test_openai_parallel_fragmented_tool_arguments_by_index(self):
        chunks = [
            {'choices': [{'index': 0, 'delta': {'tool_calls': [
                {'index': 0, 'id': 'call_A', 'function': {'name': 'read', 'arguments': '{"pa'}},
                {'index': 1, 'id': 'call_B', 'function': {'name': 'grep', 'arguments': '{"q":"x'}}]}}]},
            {'choices': [{'index': 0, 'delta': {'tool_calls': [
                {'index': 1, 'function': {'arguments': 'y"}'}},
                {'index': 0, 'function': {'arguments': 'th":"/home/alex/repo/a.py"}'}}]}}]},
            {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]},
        ]
        result = derive('\n'.join(json.dumps(chunk) for chunk in chunks), 'response')
        calls = [event for event in result['events'] if event['kind'] == 'tool_call' and event['origin'] == 'output']
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0]['payload']['arguments'], {'path': '/home/alex/repo/a.py'})
        self.assertEqual(calls[1]['payload']['arguments'], {'q': 'xy'})
        self.assertTrue(all(event['payload']['parse_status'] == 'parsed' for event in calls))

    def test_invalid_tool_arguments_stay_text_not_repaired(self):
        body = json.dumps({'choices': [{'message': {'role': 'assistant', 'tool_calls': [
            {'id': 'call_bad', 'function': {'name': 'read', 'arguments': '{"path": '}}]}}]})
        result = derive(body, 'response')
        call = [event for event in result['events'] if event['kind'] == 'tool_call'][0]
        self.assertEqual(call['payload']['parse_status'], 'invalid_json')
        self.assertEqual(call['payload']['arguments_text'], '{"path": ')
        self.assertIsNone(call['payload']['arguments'])

    def test_responses_stream_events(self):
        frames = [
            {'type': 'response.created', 'response': {'id': 'resp_RAW', 'model': 'test'}},
            {'type': 'response.output_item.added', 'item': {'id': 'item_1', 'type': 'message'}},
            {'type': 'response.output_text.delta', 'item_id': 'item_1', 'delta': 'Bonjour '},
            {'type': 'response.output_text.delta', 'item_id': 'item_1', 'delta': '東京 🚀'},
            {'type': 'response.output_item.added', 'item': {'id': 'call_1', 'type': 'function_call', 'name': 'read'}},
            {'type': 'response.function_call_arguments.delta', 'item_id': 'call_1', 'delta': '{"path":"/a/b.py"}'},
            {'type': 'response.completed', 'response': {'id': 'resp_RAW', 'status': 'completed', 'output': []}},
        ]
        body = '\n\n'.join('data: ' + json.dumps(frame) for frame in frames) + '\n\n'
        result = derive(body, 'response')
        messages = [event for event in result['events'] if event['kind'] == 'message' and event['origin'] == 'output']
        calls = [event for event in result['events'] if event['kind'] == 'tool_call']
        self.assertEqual(messages[0]['payload']['text'], 'Bonjour 東京 🚀')
        self.assertEqual(calls[0]['payload']['arguments'], {'path': '/a/b.py'})
        self.assertTrue(result['stream_complete'])
        self.assertNotIn('resp_RAW', canonical(sanitized_events(result)))

    def test_responses_request_history_tool_call_and_output(self):
        body = json.dumps({
            'previous_response_id': 'resp_RAW_R',
            'input': [
                {'type': 'function_call', 'call_id': 'call_R', 'name': 'read', 'arguments': '{"path":"/r.py"}'},
                {'type': 'function_call_output', 'call_id': 'call_R', 'output': 'result R'},
                {'role': 'user', 'content': 'after result'},
            ],
        })
        result = derive(body)
        call = [event for event in result['events'] if event['kind'] == 'tool_call'][0]
        tool_result = [event for event in result['events'] if event['kind'] == 'tool_result'][0]
        self.assertEqual(tool_result['parent_event_local'], call['event_index'])
        self.assertEqual(tool_result['payload']['content'], 'result R')
        self.assertTrue(any(event['kind'] == 'message' and event['payload']['text'] == 'after result'
                            for event in result['events']))

    def test_tool_result_links_to_call_within_record(self):
        body = json.dumps({'messages': [
            {'role': 'assistant', 'content': [{'type': 'tool_use', 'id': 'toolu_1', 'name': 'read', 'input': {'path': '/a.py'}}]},
            {'role': 'user', 'content': [{'type': 'tool_result', 'tool_use_id': 'toolu_1', 'content': 'ok'}]},
        ]})
        result = derive(body)
        call = [event for event in result['events'] if event['kind'] == 'tool_call'][0]
        tool_result = [event for event in result['events'] if event['kind'] == 'tool_result'][0]
        self.assertEqual(tool_result['parent_event_local'], call['event_index'])
        self.assertNotIn('toolu_1', canonical(result['events']))

    def test_explicit_response_link_is_scoped_and_not_a_conversation_claim(self):
        body = json.dumps({'previous_response_id': 'resp_RAW_123', 'messages': [{'role': 'user', 'content': 'hi'}]})
        result = derive(body)
        self.assertIsNone(result['conversation_ref'])
        self.assertNotIn('resp_RAW_123', canonical(result['events']))
        self.assertEqual(result['links'][0]['method'], 'explicit_previous_response_id')
        self.assertEqual(result['links'][0]['confidence'], 'explicit')

    def test_unknown_blocks_are_explicit_unsupported_or_withheld(self):
        body = json.dumps({'messages': [
            {'role': 'assistant', 'content': [{'type': 'mystery_block', 'hidden': 'value'},
                                              {'type': 'image', 'source': {'media_type': 'image/png', 'data': 'raw'}}]},
            {'role': 'system', 'content': 'secret system context'},
        ]})
        result = derive(body, 'response')
        kinds = [event['kind'] for event in result['events']]
        self.assertIn('unsupported', kinds)
        self.assertIn('withheld', kinds)
        self.assertNotIn('secret system context', canonical(result['events']))
        self.assertNotIn('raw', canonical(result['events']).lower().replace('"raw_value_exported"', ''))

    def test_ordinary_openai_and_anthropic_outputs(self):
        openai = derive(json.dumps({'choices': [{'message': {
            'role': 'assistant', 'content': 'ordinary output',
            'tool_calls': [{'id': 'call_z', 'function': {'name': 'read', 'arguments': '{"path":"/z.py"}'}}]}}]}),
            'response')
        self.assertTrue(any(event['kind'] == 'message' and event['payload']['text'] == 'ordinary output'
                            for event in openai['events']))
        self.assertTrue(any(event['kind'] == 'tool_call' and event['payload']['arguments'] == {'path': '/z.py'}
                            for event in openai['events']))
        anthropic = derive(json.dumps({'role': 'assistant', 'content': [
            {'type': 'text', 'text': 'anthropic output'},
            {'type': 'tool_use', 'id': 'toolu_z', 'name': 'read', 'input': {'path': '/z.py'}}],
            'stop_reason': 'tool_use'}), 'response')
        self.assertTrue(any(event['kind'] == 'message' and event['payload']['text'] == 'anthropic output'
                            for event in anthropic['events']))
        self.assertTrue(any(event['kind'] == 'tool_call' for event in anthropic['events']))

    def test_tool_role_is_one_result_event_not_a_duplicate_message(self):
        body = json.dumps({'messages': [
            {'role': 'assistant', 'content': [{'type': 'tool_use', 'id': 'toolu_2', 'name': 'read', 'input': {}}]},
            {'role': 'tool', 'tool_call_id': 'toolu_2', 'content': 'result text'},
        ]})
        result = derive(body)
        results = [event for event in result['events'] if event['kind'] == 'tool_result']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['payload']['content'], 'result text')
        self.assertFalse(any(event['kind'] == 'message' and event['role'] == 'tool' for event in result['events']))

    def test_coverage_is_explicitly_unknown_without_stream_claim(self):
        result = derive(json.dumps({'messages': [{'role': 'user', 'content': 'hi'}]}))
        message = [event for event in result['events'] if event['kind'] == 'message'][0]
        self.assertEqual(message['coverage_status'], 'unknown')
        self.assertEqual(message['payload']['intent_status'], 'unknown')
        self.assertIsNone(message['payload']['intent_label'])

    def test_malformed_and_empty(self):
        malformed = derive('{"broken": ')
        self.assertEqual(malformed['events'][-1]['kind'], 'parse_error')
        self.assertEqual(malformed['events'][-1]['parse_status'], 'malformed')
        empty = derive('   ')
        self.assertEqual(empty['events'][-1]['kind'], 'empty')

    def test_system_and_headers_are_withheld(self):
        result = derive(json.dumps({'system': 'top secret', 'messages': [{'role': 'user', 'content': 'x'}]}))
        self.assertTrue(any(event['kind'] == 'withheld' and event['payload']['reason'] == 'system_context'
                            for event in result['events']))
        self.assertTrue(any(event['kind'] == 'withheld' and event['payload']['reason'] == 'headers'
                            for event in result['events']))
        self.assertNotIn('top secret', canonical(result['events']))


class SanitisationTests(unittest.TestCase):
    def test_nested_keys_values_paths_identifiers_and_aliases(self):
        sanitised = sanitizer().payload({
            'Example Holdings': {'PRICING-1234': 'example-holdings/pricing-service',
                                 'contact': 'alex@example.com'},
            'command': 'cat /home/alex/repos/company-pricing/src/quoting/QuoteEngine.cs',
            'endpoint': 'https://pricing.internal.example/v1/X',
            'ip': '10.2.3.4', 'credential': 'Bearer abcdefghijklmnopqrstuvwxyz',
            'person': 'Alex Example', 'repeat_path': '/home/alex/repos/company-pricing/src/quoting/QuoteEngine.cs',
        })
        text = canonical(sanitised)
        for forbidden in ('Example Holdings', 'example-holdings', 'PRICING-1234', 'alex@example.com',
                          '/home/alex', 'pricing.internal.example', '10.2.3.4', 'Alex Example',
                          'abcdefghijklmnopqrstuvwxyz'):
            self.assertNotIn(forbidden, text)
        self.assertIn('.cs', text)
        self.assertEqual(sanitised['command'].split()[-1], sanitised['repeat_path']['file_ref'])
        self.assertEqual(sanitised['repeat_path']['language'], 'C#')
        self.assertEqual(sanitised['repeat_path']['extension'], 'cs')

    def test_final_rejection_includes_nested_object_keys(self):
        original = {'outer': {'Example Holdings': 'value'}}
        with self.assertRaises(HoldError) as context:
            sanitizer().assert_clean(original, original)
        self.assertEqual(context.exception.reason, 'final_leak_check_alias')

    def test_text_is_preserved_except_selected_spans(self):
        original = 'Please keep this sentence and replace Example Holdings only.'
        clean = sanitizer().text(original)
        self.assertTrue(clean.startswith('Please keep this sentence and replace '))
        self.assertTrue(clean.endswith(' only.'))
        self.assertNotIn('Example Holdings', clean)

    def test_file_reference_is_stable_and_extension_is_preserved(self):
        payload = sanitizer().payload({'a': '/home/alex/repo/src/QuoteEngine.cs',
                                       'b': '/home/alex/repo/src/QuoteEngine.cs'})
        self.assertEqual(payload['a'], payload['b'])
        self.assertTrue(payload['a'].startswith('file_') and payload['a'].endswith('.cs'))

    def test_file_and_entity_references_default_to_revision_scope(self):
        refs_a = sanitizer().refs
        refs_b = sanitizer().refs
        refs_a.bind_revision('rev_' + 'a' * 32)
        refs_b.bind_revision('rev_' + 'b' * 32)
        self.assertNotEqual(refs_a.file('/workspace/project/src/main.py'),
                            refs_b.file('/workspace/project/src/main.py'))
        self.assertNotEqual(refs_a.opaque('entity', 'invented-person'),
                            refs_b.opaque('entity', 'invented-person'))

        broad_data = policy_data()
        broad_data['reference_scope'] = 'policy'
        broad = Policy(broad_data, b'k' * 48)
        broad_a, broad_b = RefFactory(broad), RefFactory(broad)
        broad_a.bind_revision('rev_' + 'a' * 32)
        broad_b.bind_revision('rev_' + 'b' * 32)
        self.assertEqual(broad_a.file('/workspace/project/src/main.py'),
                         broad_b.file('/workspace/project/src/main.py'))

    def test_unquoted_windows_and_backtick_paths_are_fully_replaced(self):
        clean = sanitizer().text(
            'at Q.Run() in C:\\Users\\Alice Example\\source\\repos\\Contoso.Pricing\\QuoteEngine.cs:line 42; '
            'open `C:\\Users\\Alice Example\\source\\repos\\Contoso.Pricing\\QuoteEngine.cs` and '
            '`/home/Alex Example/private repo/QuoteEngine.cs`')
        for forbidden in ('C:\\Users', 'Alice Example', 'source\\repos', 'Contoso.Pricing', 'QuoteEngine.cs',
                          '/home/Alex', 'private repo'):
            self.assertNotIn(forbidden, clean)
        # A line holding a Windows path is replaced whole (a name can follow the
        # path after a comma), so line numbers on it go with it.
        self.assertIn('file_', clean)

    def test_windows_balanced_parentheses_and_padded_backticks_are_fully_replaced(self):
        clean = sanitizer().text(
            'in C:\\Program Files (x86)\\Jane Corp\\tool.exe:line 4; '
            'C:\\Users\\Jane Example\\Proj Folder (old)\\x.cs:12 and ` /home/jane doe/proj x/file.py `')
        for forbidden in ('Program Files', 'x86', 'Jane Corp', 'tool.exe', 'Jane Example',
                          'Proj Folder', 'old', 'x.cs', '/home/jane', 'doe/proj', 'file.py'):
            self.assertNotIn(forbidden, clean)
        self.assertIn('file_', clean)
        with self.assertRaisesRegex(HoldError, 'final_leak_check_path'):
            sanitizer().assert_clean('synthetic source', {'text': 'file_ref)\\Jane Corp\\tool.exe'})

    def test_nested_repository_identity_context_and_tool_prose_are_preserved(self):
        payload = sanitizer().payload({
            'repository': {'name': 'contoso-pricing', 'owner': {'login': 'alice-example'}},
            'task': 'Fix the failing quote rounding test',
            'user_prompt': 'please refactor the parser',
            'tool_arguments': {'steps': ['read a file', {'task': 'update parser tests'}]},
        })
        encoded = canonical(payload)
        for raw in ('contoso-pricing', 'alice-example'):
            self.assertNotIn(raw, encoded)
        self.assertEqual(payload['task'], 'Fix the failing quote rounding test')
        self.assertEqual(payload['user_prompt'], 'please refactor the parser')
        self.assertEqual(payload['tool_arguments']['steps'], ['read a file', {'task': 'update parser tests'}])

        owner_id = sanitizer().payload({'repository': {'owner': {'id': 12345}}})['repository']['owner']['id']
        self.assertTrue(owner_id.startswith('person_'))

    def test_unicode_and_multiline_survive(self):
        clean = sanitizer().text('café 東京 🚀\nsecond line')
        self.assertEqual(clean, 'café 東京 🚀\nsecond line')


class DetectorTests(unittest.TestCase):
    class Cache:
        def get(self, identity):
            return None
        def put(self, identity, model, policy_version, spans):
            self.saved = (identity, model, policy_version, spans)

    def detector(self, output):
        detector = AssistedSpanDetector('https://approved.invalid/v1/chat', 'small-test-model', 'x' * 24,
                                        'detector-policy-1')
        detector._request = lambda chunk, field: output

        def validate(text, field, payload):
            return AssistedSpanDetector._validate(detector, text, field, payload)
        detector._validate = validate
        return detector

    def test_valid_span_is_applied_by_offsets_only(self):
        text = 'Use Example Holdings now'
        detector = self.detector({'spans': [{'field': 'content', 'start': 4, 'end': 20,
                                             'text': 'Example Holdings', 'entity': 'ORG'}]})
        clean = detector.apply(text, 'content', sanitizer().refs)
        self.assertTrue(clean.startswith('Use entity_'))
        self.assertTrue(clean.endswith(' now'))

    def test_invalid_offsets_and_entities_hold(self):
        for output in (
            {'spans': [{'field': 'content', 'start': 0, 'end': 3, 'text': 'wrong', 'entity': 'ORG'}]},
            {'spans': [{'field': 'other', 'start': 0, 'end': 3, 'text': 'Use', 'entity': 'ORG'}]},
            {'spans': [{'field': 'content', 'start': 0, 'end': 3, 'text': 'Use', 'entity': 'BAD ENTITY'}]},
            {'spans': [{'field': 'content', 'start': -1, 'end': 3, 'text': 'Use', 'entity': 'ORG'}]},
        ):
            with self.assertRaises(HoldError):
                self.detector(output).apply('Use Example Holdings now', 'content', sanitizer().refs)

    def test_chunks_cover_all_characters_without_truncation(self):
        chunks = []
        detector = AssistedSpanDetector('https://approved.invalid/v1/chat', 'small-test-model', 'x' * 24,
                                        'detector-policy-1', cache=self.Cache())
        detector.MAX_CHUNK = 7
        detector._request = lambda chunk, field: (chunks.append(chunk), {'spans': []})[1]
        text = 'abcdefghijklmnopqrstuvwxyz'
        detector.apply(text, 'content', sanitizer().refs)
        self.assertEqual(''.join(chunks), text)
        self.assertEqual(len(chunks), 4)

    def test_http_response_read_exceptions_are_retryable(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, limit): raise http.client.IncompleteRead(b'{', 10)

        class Opener:
            def open(self, request, timeout): return Response()

        detector = AssistedSpanDetector('https://approved.invalid/v1/chat', 'small-test-model', 'x' * 24,
                                        'detector-policy-1')
        with mock.patch('urllib.request.build_opener', return_value=Opener()):
            with self.assertRaisesRegex(OSError, 'detector_unavailable'):
                detector._request('synthetic payload', 'content')


class ResearchTests(unittest.TestCase):
    def revision(self):
        return {'revision_id': 'rev_' + 'a' * 32, 'config_json': '{}', 'detector_model': 'disabled',
                'policy_version': 'synthetic-1', 'parser_version': parsing.PARSER_VERSION,
                'schema_version': research.SCHEMA_VERSION, 'detector_policy_version': 'disabled',
                'expected_records': 1, 'processed_records': 1, 'held_records': 0, 'failed_records': 0,
                'event_count': 3, 'conversation_count': 0}

    def record_row(self, body):
        return {'id': 'b' * 64, 'seq': 7, 'timestamp': 1760000000000, 'type': 'response',
                'content_sha256': 'c' * 64, 'record_json': json.dumps({'type': 'response', 'body': body})}

    def test_event_ids_and_rows_are_deterministic_and_unique(self):
        sanitised = sanitizer()
        record = {'type': 'response', 'body': json.dumps({'choices': [{'message': {
            'role': 'assistant', 'content': 'same text'}}]})}
        parsed = parsing.derive_events(record, sanitised.refs)
        first, pipeline_one = research._event_rows(self.revision(), None, self.record_row(record['body']), parsed, sanitised)
        second, pipeline_two = research._event_rows(self.revision(), None, self.record_row(record['body']), parsed, sanitised)
        self.assertEqual(pipeline_one, pipeline_two)
        self.assertEqual([row['event_id'] for row in first], [row['event_id'] for row in second])
        self.assertEqual(len({row['event_id'] for row in first}), len(first))
        self.assertTrue(all(row['event_id'].startswith('event_') for row in first))
        exported = [research._export_event(row) for row in first]
        self.assertTrue(all('b' * 64 not in canonical(event) and 'record_id' not in event for event in exported))

    def test_superseded_event_rows_are_counted_without_blocking_membership(self):
        member = {'record_id': 'a' * 64, 'source_seq': 1, 'content_sha256': 'c' * 64,
                  'current_sha256': 'c' * 64, 'body_sha256': 'c' * 64}
        digest = hashlib.sha256((canonical([member['record_id'], 1, member['content_sha256']]) + '\n').encode()).hexdigest()
        revision = {'revision_id': 'rev_' + 'a' * 32, 'expected_records': 1, 'membership_sha256': digest}
        membership_pages = iter(([member], []))

        def rows(query):
            if query.startswith('SELECT m.record_id,m.source_seq'):
                return next(membership_pages)
            if query.startswith('SELECT count() AS n FROM research_processing FINAL'):
                return [{'n': 1}]
            if 'research_members AS m FINAL LEFT JOIN research_processing' in query:
                return [{'n': 0}]
            if 'research_processing AS p FINAL LEFT JOIN research_members' in query:
                return [{'n': 0}]
            if 'HAVING p.event_count!=actual' in query:
                return [{'n': 0}]
            if 'research_events AS e FINAL LEFT JOIN research_processing' in query:
                return [{'n': 0}]
            if 'research_events AS e FINAL INNER JOIN research_processing' in query:
                return [{'n': 2}]
            self.fail('Unexpected verification query: ' + query)

        with mock.patch.object(research.db, 'rows', side_effect=rows):
            result = research._verify_membership(revision)
        self.assertEqual(result, {'superseded_event_rows': 2})

        membership_pages = iter(([member], []))

        def broken_current_rows(query):
            if query.startswith('SELECT m.record_id,m.source_seq'):
                return next(membership_pages)
            if query.startswith('SELECT count() AS n FROM research_processing FINAL'):
                return [{'n': 1}]
            if 'research_members AS m FINAL LEFT JOIN research_processing' in query:
                return [{'n': 0}]
            if 'research_processing AS p FINAL LEFT JOIN research_members' in query:
                return [{'n': 0}]
            if 'HAVING p.event_count!=actual' in query:
                return [{'n': 1}]
            self.fail('The current-pipeline mismatch should reject before stale-row queries')

        membership_pages = iter(([member], []))
        with mock.patch.object(research.db, 'rows', side_effect=broken_current_rows):
            with self.assertRaisesRegex(HoldError, 'processed_event_count_mismatch'):
                research._verify_membership(revision)

    def test_withheld_scalar_markers_have_safe_exclusion_reasons(self):
        payload = {'text': '[WITHHELD]', 'nested': {'withheld': True, 'reason': 'unsupported_attachment'}}
        expected = {'policy_withheld': 1, 'unsupported_attachment': 1}
        self.assertEqual(research._nested_exclusions(payload), expected)
        import research_reader
        self.assertEqual(research_reader._nested_exclusions(payload), expected)

    def test_export_uses_revision_schema_and_keeps_old_bytes_stable(self):
        row = self.fake_row(3, 'old released payload')
        row['schema_version'] = 'research-event/1'
        row['parser_version'] = ''
        row['revision_parser_version'] = '2026-10-20.2'
        before = research.jsonl_bytes([research._export_event(row)])
        with mock.patch.object(research, 'SCHEMA_VERSION', 'research-event/99'), \
                mock.patch.object(research, 'PARSER_VERSION', 'future-parser'):
            after = research.jsonl_bytes([research._export_event(row)])
        self.assertEqual(before, after)

    def test_resetting_revision_resumes_setup_after_interruption(self):
        resetting = {'revision_id': 'rev_' + 'a' * 32, 'status': 'resetting',
                     'selection_max_seq': 7, 'membership_sha256': 'b' * 64}
        inserted = []
        with mock.patch.object(research, '_latest', return_value=resetting), \
                mock.patch.object(research, '_checkpoint') as checkpoint, \
                mock.patch.object(research.db, 'rows', return_value=[]), \
                mock.patch.object(research.db, 'insert', side_effect=lambda table, rows: inserted.append((table, rows))):
            resumed = research._worker_revision(None)
        self.assertEqual(resumed['status'], 'deriving')
        self.assertEqual(resumed['revision_id'], resetting['revision_id'])
        checkpoint.assert_called_once_with('research_worker:' + resetting['revision_id'], mock.ANY)
        self.assertEqual(inserted[0][0], 'research_revisions')
        self.assertEqual(inserted[0][1][0]['status'], 'deriving')

    def test_retry_exhausted_reset_starts_new_budget_and_keeps_old_attempts(self):
        row = {'record_id': 'a' * 64, 'observation_ref': 'obs_' + 'b' * 24, 'retry_epoch': 0}
        inserted = []
        with mock.patch.object(research.db, 'rows', return_value=[row]), \
                mock.patch.object(research.db, 'insert', side_effect=lambda table, values: inserted.append((table, values))):
            research._reset_retry_exhausted('rev_' + 'c' * 32)
        self.assertEqual(inserted[0][1][0]['status'], 'pending')
        self.assertEqual(inserted[0][1][0]['attempt_count'], 0)
        self.assertEqual(inserted[0][1][0]['retry_epoch'], 1)
        self.assertEqual(inserted[0][1][0]['observation_ref'], row['observation_ref'])

    def test_partial_snapshot_insert_is_replayed_before_revision_becomes_visible(self):
        member = {'id': 'a' * 64, 'seq': 7, 'content_sha256': 'c' * 64}
        config = SimpleNamespace(
            sanitisation_available=True,
            policy=SimpleNamespace(version='synthetic-1', detector_policy_version='disabled'),
            parser_version=parsing.PARSER_VERSION,
            schema_version=research.SCHEMA_VERSION,
            detector_model='disabled', detector_policy_version='disabled',
            detector=None, sanitiser=lambda: SimpleNamespace(refs=SimpleNamespace(
                opaque=lambda kind, value: kind + '_ref', bind_revision=lambda revision_id: None)),
        )
        inserted = []

        def insert(table, rows):
            inserted.append(table)
            if table == 'research_processing' and inserted.count(table) == 1:
                raise OSError('synthetic interrupted status insert')

        final_row = {'revision_id': 'rev_' + 'd' * 32, 'status': 'deriving'}
        with mock.patch.object(research, 'ResearchConfig', return_value=config), \
                mock.patch.object(research, 'config_revision', return_value=(final_row['revision_id'], {'synthetic': True})), \
                mock.patch.object(research, '_source_membership_digest', return_value='b' * 64), \
                mock.patch.object(research, '_source_members_page', side_effect=lambda maximum, cursor: [member] if cursor == (0, '') else []), \
                mock.patch.object(research, '_revision_row', side_effect=[None, None, final_row]), \
                mock.patch.object(research.db, 'rows', return_value=[{'seq': 7}]), \
                mock.patch.object(research.db, 'insert', side_effect=insert):
            with self.assertRaises(OSError):
                research.create_revision({})
            revision = research.create_revision({})
        self.assertEqual(revision['status'], 'deriving')
        self.assertEqual(inserted.count('research_members'), 2)
        self.assertEqual(inserted.count('research_processing'), 2)
        self.assertEqual(inserted.count('research_revisions'), 1)

    def test_cache_event_and_status_io_failures_retry_then_exhaust_without_skipping(self):
        config = SimpleNamespace(
            sanitisation_available=True, policy=Policy(policy_data(), b'k' * 48), detector_model='disabled',
            sanitiser=sanitizer,
        )
        revision = {'revision_id': 'rev_' + 'd' * 32}
        source_json = json.dumps({'type': 'response', 'body': '{}'}, separators=(',', ':'))
        source_sha = hashlib.sha256(source_json.encode()).hexdigest()
        metadata = {'id': 'a' * 64, 'seq': 7, 'expected_sha256': source_sha, 'source_bytes': len(source_json)}
        source = {'id': metadata['id'], 'seq': 7, 'content_sha256': source_sha, 'record_json': source_json,
                  'user_id': 'synthetic', 'timestamp': 1, 'type': 'response'}
        for failure_point in ('cache', 'events', 'status'):
            with self.subTest(failure_point=failure_point):
                current_attempt = 0
                inserts, checkpoint_writes = [], []

                def rows(query):
                    if 'SELECT attempt_count' in query:
                        return [{'attempt_count': current_attempt}] if current_attempt else []
                    if 'AS expected_sha256' in query:
                        return [metadata]
                    return [source]

                def insert(table, values):
                    nonlocal current_attempt
                    if ((failure_point == 'events' and table == 'research_events') or
                            (failure_point == 'status' and table == 'research_processing' and values[0]['status'] == 'processed')):
                        raise OSError('synthetic write unavailable')
                    inserts.append((table, values))
                    if table == 'research_processing':
                        current_attempt = int(values[0]['attempt_count'])

                def checkpoint(key, value=None):
                    if value is not None:
                        checkpoint_writes.append(value)
                    return None

                with mock.patch.object(research, 'ResearchConfig', return_value=config), \
                        mock.patch.object(research, '_worker_revision', return_value=revision), \
                        mock.patch.object(research, '_checkpoint', side_effect=checkpoint), \
                        mock.patch.object(research, 'derive_events', side_effect=OSError('synthetic cache unavailable') if failure_point == 'cache' else None, return_value={}), \
                        mock.patch.object(research, '_event_rows', return_value=([{'synthetic': True}], 'synthetic-pipeline')), \
                        mock.patch.object(research.db, 'rows', side_effect=rows), \
                        mock.patch.object(research.db, 'insert', side_effect=insert):
                    outcomes = [research.process_once({})['status'] for _ in range(research.MAX_ATTEMPTS)]

                self.assertEqual(outcomes, ['retry_pending'] * (research.MAX_ATTEMPTS - 1) + ['processed'])
                attempts = [values[0] for table, values in inserts if table == 'research_attempts']
                self.assertEqual([row['attempt'] for row in attempts], list(range(1, research.MAX_ATTEMPTS + 1)))
                self.assertEqual(attempts[-1]['outcome'], 'retry_exhausted')
                self.assertEqual([row['retry_epoch'] for row in attempts], [0, 0, 0])
                self.assertEqual(checkpoint_writes, [{'seq': 7, 'updated_at': mock.ANY}])

    def fake_row(self, number, text='hello'):
        return {'revision_id': 'rev_' + 'a' * 32, 'event_id': 'event_' + ('%024x' % number),
                'conversation_ref': '', 'observation_ref': 'obs_' + 'd' * 24,
                'origin': 'output', 'kind': 'message', 'role': 'assistant', 'source_seq': number,
                'event_index': 0, 'parent_event_id': '', 'call_ref': '', 'result_ref': '', 'link_json': '',
                'parse_status': 'parsed', 'linkage_status': 'unknown', 'coverage_status': 'unknown',
                'payload_bytes': len(json.dumps({'text': text}, ensure_ascii=False).encode()), 'payload': json.dumps({'text': text}, ensure_ascii=False), 'revision_id': 'rev_' + 'a' * 32}

    def test_page_budget_below_one_event_still_progresses(self):
        rows = [self.fake_row(1, 'x' * 2048), self.fake_row(2, 'y' * 2048)]
        release = {'manifest_json': canonical({'counts': {'events': 2}, 'export_sha256': 'x'}),
                   'event_bytes_limit': 2 * 1024 * 1024, 'page_bytes_limit': 1}
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research, 'MAX_PAGE_BYTES', 1), \
                mock.patch.object(research.db, 'rows', side_effect=[rows, rows[:1]]):
            page, _body = research.export_page('rev_' + 'a' * 32, limit=2)
        self.assertEqual(page['event_count'], 1)
        self.assertIsNotNone(page['next_cursor'])

    def test_released_revision_uses_its_pinned_ceiling(self):
        row = self.fake_row(1, 'x' * 2600000)
        release = {'manifest_json': canonical({'counts': {'events': 1}, 'export_sha256': 'x'}),
                   'event_bytes_limit': 4 * 1024 * 1024, 'page_bytes_limit': 8 * 1024 * 1024}
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research, 'MAX_EVENT_BYTES', 2 * 1024 * 1024), \
                mock.patch.object(research.db, 'rows', side_effect=[[row], [row]]):
            page, _body = research.export_page('rev_' + 'a' * 32, limit=1)
        self.assertEqual(page['event_count'], 1)

    def test_legacy_release_recovers_the_revision_limits(self):
        row = self.fake_row(1, 'x' * 2600000)
        release = {'manifest_json': canonical({'counts': {'events': 1}, 'export_sha256': 'x'}),
                   'revision_id': 'rev_' + 'a' * 32}
        revision = {'config_json': canonical({'limits': {'max_event_bytes': 4 * 1024 * 1024,
                                                         'max_page_bytes': 8 * 1024 * 1024}})}
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_revision_row', return_value=revision), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research, 'MAX_EVENT_BYTES', 2 * 1024 * 1024), \
                mock.patch.object(research.db, 'rows', side_effect=[[row], [row]]):
            page, _body = research.export_page('rev_' + 'a' * 32, limit=1)
        self.assertEqual(page['event_count'], 1)

    def test_legacy_release_without_pins_uses_the_historical_ceiling(self):
        row = self.fake_row(1, 'x' * 2600000)
        release = {'manifest_json': canonical({'counts': {'events': 1}, 'export_sha256': 'x'})}
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research.db, 'rows', side_effect=[[row]]):
            with self.assertRaises(HoldError):
                research.export_page('rev_' + 'a' * 32, limit=1)

    def test_first_release_recovers_the_revision_limits(self):
        # No release row exists yet while the first manifest is built.
        revision = {'config_json': canonical({'limits': {'max_event_bytes': 4 * 1024 * 1024,
                                                         'max_page_bytes': 8 * 1024 * 1024}})}
        with mock.patch.object(research, '_release_row', return_value=None), \
                mock.patch.object(research, '_revision_row', return_value=revision), \
                mock.patch.object(research, '_bounded_rows', return_value=([], False)) as bounded:
            list(research._all_export_events('rev_' + 'a' * 32))
        self.assertEqual(bounded.call_args[0][3:], (4 * 1024 * 1024, 8 * 1024 * 1024))

    def test_insert_accepts_a_versioned_table_name(self):
        import clickhouse
        with mock.patch.object(clickhouse, 'execute') as execute:
            clickhouse.insert('research_conversation_labels_v2', [{'a': 1}])
        self.assertTrue(execute.called)

    def test_bounded_page_cursor_digest_and_gzip(self):
        rows = [self.fake_row(index, 'line one\nline two 東京') for index in (1, 2, 3)]
        release = {'manifest_json': canonical({'counts': {'events': 3}, 'export_sha256': 'x'})}
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research.db, 'rows', side_effect=[rows, rows[:2]]):
            page, body = research.export_page('rev_' + 'a' * 32, limit=2)
        self.assertEqual(page['event_count'], 2)
        self.assertFalse(page['complete'])
        self.assertIsNotNone(page['next_cursor'])
        self.assertEqual(page['page_sha256'], hashlib.sha256(body).hexdigest())
        self.assertEqual(body.count(b'\n'), 2)
        cursor = page['next_cursor']
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research.db, 'rows', side_effect=[rows[2:], rows[2:]]):
            page_two, body_two = research.export_page('rev_' + 'a' * 32, cursor=cursor, limit=2)
        self.assertEqual(page_two['event_count'], 1)
        self.assertTrue(page_two['complete'])
        self.assertIn('manifest_sha256', page_two)
        self.assertNotIn('line one\nline two', body.decode())  # newline is escaped inside JSON
        self.assertEqual(json.loads(body.splitlines()[0])['payload']['text'], 'line one\nline two 東京')
        with mock.patch.object(research, '_release_row', return_value=release), \
                mock.patch.object(research, '_cursor_key', return_value=b'k' * 48), \
                mock.patch.object(research.db, 'rows', side_effect=[rows, rows[:2]]):
            compressed, content_type, headers = research.export_jsonl('rev_' + 'a' * 32, limit=2, compress=True)
        self.assertEqual(content_type, 'application/gzip')
        self.assertEqual(headers['X-Research-Complete'], 'false')
        self.assertNotIn('X-Research-Manifest-SHA256', headers)
        self.assertEqual(gzip.decompress(compressed).count(b'\n'), 2)

    def test_cursor_cannot_cross_revision(self):
        cursor = research._encode_cursor('rev_' + 'a' * 32, {'source_seq': 1, 'event_index': 0,
                                                             'event_id': 'event_' + 'f' * 24}, b'k' * 48)
        with self.assertRaises(ValueError):
            research._decode_cursor(cursor, 'rev_' + 'b' * 32, b'k' * 48)
        with self.assertRaises(ValueError):
            research._decode_cursor(cursor, 'rev_' + 'a' * 32, b'x' * 48)

    def test_manifest_is_content_free_and_schema_is_typed(self):
        manifest = {'revision_id': 'rev_' + 'a' * 32, 'counts': {'events': 1},
                    'coverage': {'conversation_coverage': 'unknown'},
                    'export_sha256': 'd' * 64}
        with mock.patch.object(research, '_release_row', return_value={'manifest_json': canonical(manifest)}):
            loaded = research.manifest('rev_' + 'a' * 32)
        self.assertEqual(loaded, manifest)
        text = canonical(loaded)
        for forbidden in ('record_id', 'source_sha256', 'record_json', 'user_id'):
            self.assertNotIn(forbidden, text)
        schema = research.EVENT_SCHEMA
        self.assertFalse(schema['additionalProperties'])
        self.assertIn('event_id', schema['required'])
        self.assertIn('payload', schema['required'])


class ReleaseGateTests(unittest.TestCase):
    def test_release_blockers_and_detector_requirement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy = root / 'policy.json'
            key = root / 'key'
            policy.write_text(json.dumps(policy_data()))
            key.write_bytes(b'k' * 48)
            base = {'COPILOT_RESEARCH_POLICY_FILE': str(policy), 'COPILOT_RESEARCH_PSEUDONYM_KEY_FILE': str(key)}
            blockers = research.ResearchConfig(base).release_blockers()
            self.assertIn('explicit_manual_retention_not_configured', blockers)
            self.assertIn('release_setting_not_evaluated', blockers)
            ready = dict(base, COPILOT_RESEARCH_RETENTION_RAW='manual',
                         COPILOT_RESEARCH_RETENTION_CURATED='manual',
                         COPILOT_RESEARCH_RELEASE_SETTING='evaluated')
            self.assertEqual(research.ResearchConfig(ready).release_blockers(), [])
            required = policy_data()
            required['assisted_detector'] = {'enabled': True, 'policy_version': 'must-run'}
            policy.write_text(json.dumps(required))
            self.assertIn('detector_required_by_policy_but_disabled',
                          research.ResearchConfig(ready).release_blockers())

    def test_export_and_manifest_hold_without_release(self):
        with mock.patch.object(research, '_release_row', return_value=None):
            with self.assertRaises(HoldError):
                research.export_page('rev_' + 'a' * 32)
            with self.assertRaises(HoldError):
                research.manifest('rev_' + 'a' * 32)


class RoleTests(unittest.TestCase):
    def test_route_roles(self):
        self.assertEqual(auth.required_role('GET', '/v1/research/export'), 'research')
        self.assertEqual(auth.required_role('GET', '/v1/research/status'), 'admin')
        self.assertEqual(auth.required_role('GET', '/v1/copilot/storage'), 'status')
        self.assertEqual(auth.required_role('GET', '/v1/review/records'), 'admin')
        self.assertEqual(auth.required_role('POST', '/v1/ingest/records'), 'admin')
        self.assertEqual(auth.required_role('POST', '/v1/research/releases'), 'admin')
        self.assertEqual(auth.required_role('POST', '/v1/traces'), 'otlp')
        self.assertIsNone(auth.required_role('GET', '/healthz'))

    def test_credentials_must_be_distinct(self):
        with self.assertRaises(ValueError):
            auth.validate_credentials('a' * 32, 'b' * 32, 'a' * 32, 'c' * 32)
        with self.assertRaises(ValueError):
            auth.validate_credentials('a' * 32, 'a' * 32, '', 'c' * 32)
        self.assertTrue(auth.validate_credentials('a' * 32, 'b' * 32, 'c' * 32, 'd' * 32))
        self.assertTrue(auth.validate_credentials('a' * 32, 'b' * 32, '', 'd' * 32))
        self.assertTrue(auth.authorised('Bearer ' + 'r' * 32, 'r' * 32))
        self.assertFalse(auth.authorised('Bearer ' + 'r' * 32, 's' * 32))


class ReaderTests(unittest.TestCase):
    def test_jsonl_and_gzip_reader_with_manifest_checksum(self):
        import research_reader
        event = research._export_event(ResearchTests().fake_row(1, 'café 東京\nline two'))
        body = research.jsonl_bytes([event])
        coverage = {'observation_ref': event['observation_ref'], 'events': 1, 'source_frames': 0,
                    'mapped': 1, 'withheld': 0, 'unsupported': 0, 'partial_or_unknown': 1}
        manifest = {'revision_id': event['revision_id'], 'export_sha256': hashlib.sha256(body).hexdigest(),
                    'counts': {'events': 1, 'observations': 1, 'source_frames': 0},
                    'per_observation_coverage': [coverage]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jsonl = root / 'export.jsonl'
            jsonl.write_bytes(body)
            manifest_path = root / 'manifest.json'
            manifest_path.write_text(json.dumps(manifest))
            summary = research_reader.read_export(jsonl, manifest_path)
            self.assertEqual(summary['events'], 1)
            self.assertTrue(summary['manifest_checksum_verified'])
            compressed = root / 'export.jsonl.gz'
            compressed.write_bytes(gzip.compress(body, mtime=0))
            self.assertEqual(research_reader.read_export(compressed, manifest_path)['events'], 1)


class ReviewRegressionTests(unittest.TestCase):
    def test_non_object_tool_call_members_are_unsupported_without_dropping_valid_siblings(self):
        body = json.dumps({'choices': [{'message': {'role': 'assistant', 'tool_calls': [
            42, {'id': 'call_synthetic', 'type': 'function',
                 'function': {'name': 'read', 'arguments': '{"path":"/synthetic/a.py"}'}}]}}]})
        result = derive(body, 'response')
        unsupported = [event for event in result['events'] if event['kind'] == 'unsupported']
        calls = [event for event in result['events'] if event['kind'] == 'tool_call']
        self.assertEqual(len(unsupported), 1)
        self.assertEqual(unsupported[0]['payload']['source_index'], 0)
        self.assertEqual(unsupported[0]['payload']['block_type'], 'tool_call:int')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['payload']['arguments'], {'path': '/synthetic/a.py'})

    def test_fragmented_openai_secret_never_appears_in_research_source_frames(self):
        body = '\n\n'.join('data: ' + json.dumps(frame) for frame in [
            {'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0, 'id': 'call_1',
                'function': {'name': 'read', 'arguments': '{"api_'}}]}}]},
            {'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': 0,
                'function': {'arguments': 'key":"tiny-private-123"}'}}]}}]},
            {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]},
        ]) + '\n\n'
        clean = sanitized_events(derive(body, 'response'))
        exported = canonical(clean)
        self.assertNotIn('tiny-private-123', exported)
        self.assertNotIn('tiny-private-123', exported)
        self.assertTrue(any(item.get('frame') for item in clean if 'frame' in item))

    def test_recursive_role_attachment_guard_and_role_array(self):
        body = json.dumps({'role': 'user', 'content': [
            {'type': 'tool_result', 'content': {'document': {'source': {'text': 'SYNTHETIC_NESTED_DOC'}}}},
            {'role': 'system', 'content': 'SYNTHETIC_SYSTEM_ROLE'}]})
        result = derive(body)
        safe = canonical([sanitizer().payload(research._policy_guard(event['payload'], event.get('role')))
                          for event in result['events']])
        self.assertNotIn('SYNTHETIC_NESTED_DOC', safe)
        self.assertNotIn('SYNTHETIC_SYSTEM_ROLE', safe)
        top = derive(json.dumps({'role': 'system', 'content': [{'type': 'text', 'text': 'SYNTHETIC_TOP_ROLE'}]}))
        self.assertNotIn('SYNTHETIC_TOP_ROLE', canonical(top['events']))
        ordinary = research._policy_guard({'file': '/project/src/example.py', 'source': 'print(42)'})
        safe = sanitizer().payload(ordinary)
        self.assertEqual(safe['source'], 'print(42)')
        self.assertIn('file_ref', safe['file'])

    def test_quoted_windows_path_with_spaces_and_nested_repository_name(self):
        clean = sanitizer().payload({'command': 'read "C:\\\\Users\\Alice Example\\Sensitive Project\\Internal Repo\\customer.py"',
                                     'repository': {'full_name': 'acme/billing-secret'}})
        rendered = canonical(clean)
        self.assertNotIn('Alice Example', rendered)
        self.assertNotIn('Sensitive Project', rendered)
        self.assertNotIn('Internal Repo', rendered)
        self.assertNotIn('acme/billing-secret', rendered)
        self.assertIn('file_', rendered)
        self.assertIn('repo_', rendered)

    def test_unexpected_choice_shapes_are_explicit_and_never_crash(self):
        for choices in (['x'], [{'index': 0, 'delta': 'x'}], 'x'):
            result = derive(json.dumps({'choices': choices}), 'response')
            self.assertTrue(any(event['kind'] == 'unsupported' for event in result['events']))

    def test_responses_provisional_item_is_promoted_only_by_explicit_mapping(self):
        body = '\n\n'.join('data: ' + json.dumps(frame) for frame in [
            {'type': 'response.function_call_arguments.delta', 'item_id': 'fc_1', 'delta': '{"path":"/a.py"}'},
            {'type': 'response.output_item.done', 'item': {'id': 'fc_1', 'call_id': 'call_9',
             'type': 'function_call', 'name': 'read', 'arguments': '{"path":"/a.py"}'}},
            {'type': 'response.completed', 'response': {'status': 'completed'}},
        ]) + '\n\n'
        calls = [event for event in derive(body, 'response')['events'] if event['kind'] == 'tool_call']
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['call_ref'], sanitizer().refs.opaque('call', 'call_9'))

    def test_detector_labels_are_closed_and_uncertainty_holds(self):
        detector = AssistedSpanDetector('https://approved.invalid/v1/chat', 'small-test-model', 'x' * 24,
                                        'detector-policy-1')
        with self.assertRaises(HoldError):
            detector._validate('AliceExample', 'content', {'spans': [{'field': 'content', 'start': 0,
                'end': 12, 'text': 'AliceExample', 'entity': 'AliceExample'}]})
        with self.assertRaises(HoldError):
            detector._validate('public', 'content', {'spans': [], 'uncertain': True})

    def test_sse_physical_delimiters_preserve_unicode_and_mark_truncated_tail(self):
        body = 'data: {"choices": [{"index":0,"delta":{"content":"a\u2028b"}}]}\r\r'
        parsed = parsing.classify_body(body)
        self.assertEqual(parsed['frames'][0]['value']['choices'][0]['delta']['content'], 'a\u2028b')
        tail = parsing.classify_body('data: {"choices": []}')
        self.assertEqual(tail['parse_status'], 'partial')
        multi = parsing.classify_body('event: message\r\ndata: {\r\ndata: "choices": [{"index":0,"delta":{"content":"x\u2028y"}}]\r\ndata: }\r\n\r\n')
        self.assertEqual(len(multi['frames']), 1)
        self.assertEqual(multi['frames'][0]['event'], 'message')
        self.assertEqual(multi['frames'][0]['value']['choices'][0]['delta']['content'], 'x\u2028y')
        truncated = derive(json.dumps({'truncated': True, 'choices': [{'message': {'role': 'assistant', 'content': 'done'},
                                                                         'finish_reason': 'stop'}]}), 'response')
        self.assertFalse(truncated['stream_complete'])
        self.assertIn('provider_truncated', canonical(truncated['events']))

    def test_nested_credentials_numeric_identity_and_consistent_paths(self):
        clean = sanitizer().payload({'password': {'value': 'short-private'}, 'employee_id': 123456,
                                     'path': '/home/alex/example-holdings/src/a.py',
                                     'text': 'read /home/alex/example-holdings/src/a.py'})
        self.assertEqual(clean['password'], '[WITHHELD]')
        self.assertNotIn('123456', canonical(clean))
        self.assertEqual(clean['path']['file_ref'], clean['text'].split()[-1])
        self.assertEqual(clean['path']['language'], 'Python')

    def test_key_spellings_lists_and_embedded_secret_assignments(self):
        raw = {'userId':'alice.smith','sessionId':'sess-7781','user_ids':['bob.jones',42],
               'accountId':99812,'apiKey':'abcd1234zz','api_key':'abcd1234zz',
               'X-Api-Key':'k-998877','Api-Key':'k-887766',
               'token':'tok-abc-123','x':{'authToken':'tok-abc-123'},'credentials':{'k':'v'}}
        clean = sanitizer().payload(raw)
        for secret in ('alice.smith','sess-7781','bob.jones','99812','abcd1234zz','tok-abc-123','k-998877','k-887766'):
            self.assertNotIn(secret, canonical(clean))
        self.assertTrue(all(value.startswith('person_') for value in clean['user_ids']))
        text = sanitizer().payload({'text':'{"api_key": "abcd1234zz"} export GITHUB_TOKEN=abc123def456'})
        self.assertNotIn('abcd1234zz', canonical(text))
        self.assertNotIn('abc123def456', canonical(text))
        for quoted in ('password = "hunter two"', "secret='three four'", 'apiKey="escaped \\" value"'):
            clean_text = sanitizer().payload({'text':quoted})
            self.assertEqual(clean_text['text'].split('=',1)[1].strip(), '"[REDACTED_CREDENTIAL]"')
            with self.assertRaises(HoldError): sanitizer().assert_clean({'text':quoted}, {'text':quoted})
        with self.assertRaises(HoldError): sanitizer().assert_clean(raw, raw)
        with self.assertRaises(HoldError): sanitizer().text('{"credentials":{"name":"value"}}')

    def test_responses_history_and_absent_call_identity(self):
        result = derive(json.dumps({'input': [
            {'type': 'function_call', 'call_id': 'call_A', 'name': 'read', 'arguments': '{"path":"/a.py"}'},
            {'type': 'function_call_output', 'call_id': 'call_A', 'output': 'ok'},
            {'type': 'function_call', 'name': 'missing', 'arguments': '{}'}]}))
        calls = [e for e in result['events'] if e['kind'] == 'tool_call']
        output = [e for e in result['events'] if e['kind'] == 'tool_result'][0]
        self.assertEqual(output['parent_event_local'], calls[0]['event_index'])
        self.assertIsNone(calls[1]['call_ref'])
        self.assertEqual(calls[1]['linkage_status'], 'unknown')
        self.assertIsNone(calls[1]['link'])

    def test_frames_cannot_reintroduce_withheld_content(self):
        body = '\n\n'.join('data: ' + json.dumps(v) for v in [
            {'type': 'message_start', 'message': {'content': [{'type': 'image', 'source': {'data': 'SYNTHETIC_PRIVATE_IMAGE'}}]}},
            {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'thinking_delta', 'thinking': 'SYNTHETIC_PRIVATE_REASON'}},
            {'type': 'message_stop'}]) + '\n\n'
        exported = canonical(sanitized_events(derive(body, 'response')))
        self.assertNotIn('SYNTHETIC_PRIVATE_IMAGE', exported)
        self.assertNotIn('SYNTHETIC_PRIVATE_REASON', exported)
        malformed = canonical(derive('{"password":"short-private"')['events'])
        self.assertNotIn('short-private', malformed)
        top = derive(json.dumps({'instructions': 'SYNTHETIC_PRIVATE_INSTRUCTION', 'input': 'do work'}))
        self.assertIn('system_context', canonical(top['events']))
        self.assertNotIn('SYNTHETIC_PRIVATE_INSTRUCTION', canonical(top['events']))

    def test_bom_valid_prefix_and_invalid_sse_do_not_claim_complete(self):
        self.assertEqual(parsing.classify_body('\ufeff{"input":"x"}')['parse_status'], 'parsed')
        partial = derive('{"input":"valid prefix"}{"broken":')
        self.assertEqual(partial['parse_status'], 'partial')
        self.assertIn('valid prefix', canonical(partial['events']))
        self.assertFalse(partial['stream_complete'])
        result = derive('data: broken\n\ndata: {"type":"message_stop"}\n\n', 'response')
        self.assertFalse(result['stream_complete'])
        self.assertEqual(result['parse_status'], 'partial')
        self.assertNotIn('broken', canonical(result['events']))

    def test_policy_content_key_and_endpoint_pin_revision(self):
        c = mock.Mock(policy=Policy(policy_data(), b'a'*48), detector=None, detector_model='disabled')
        original = research.config_revision(c, 42)[0]
        data = policy_data(); data['aliases']['people'].append('Other Invented Person')
        c.policy = Policy(data, b'a'*48)
        self.assertNotEqual(original, research.config_revision(c, 42)[0])
        c.policy = Policy(policy_data(), b'b'*48)
        self.assertNotEqual(original, research.config_revision(c, 42)[0])

    def test_unicode_physical_lines_typed_schema_and_unknown_call(self):
        import research_reader
        event = research._export_event(ResearchTests().fake_row(1, 'a\u2028b\u0085c'))
        event.update(kind='tool_result', call_ref='call_'+'a'*24, parent_event_id=None)
        research_reader.validate_event(event)
        body = research.jsonl_bytes([event])
        coverage = {'observation_ref': event['observation_ref'], 'events': 1, 'source_frames': 0,
                    'mapped': 1, 'withheld': 0, 'unsupported': 0, 'partial_or_unknown': 1}
        manifest = {'revision_id': event['revision_id'], 'export_sha256': hashlib.sha256(body).hexdigest(),
                    'counts': {'events': 1, 'observations': 1, 'source_frames': 0},
                    'per_observation_coverage': [coverage]}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'sample.jsonl.gz';path.write_bytes(gzip.compress(body, mtime=0))
            self.assertTrue(research_reader.read_export(path, manifest)['manifest_checksum_verified'])
            bad = dict(event, observed_sequence='not-an-integer')
            with self.assertRaises(ValueError): research_reader.validate_event(bad)

    def test_all_stream_event_envelopes_obey_schema_values(self):
        import research_reader
        raw = {'type':'response','body':'data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}\n\ndata: {"type":"message_stop"}\n\n'}
        clean = sanitizer(); parsed = parsing.derive_events(raw, clean.refs)
        rows, _ = research._event_rows(ResearchTests().revision(), None, ResearchTests().record_row(raw['body']), parsed, clean)
        for row in rows:
            event = research._export_event(row)
            research_reader.validate_event(event)
            for key in ('kind','origin','parse_status','linkage_status','coverage_status'):
                self.assertIn(event[key], research.EVENT_SCHEMA['properties'][key]['enum'])


if __name__ == '__main__':
    unittest.main()
