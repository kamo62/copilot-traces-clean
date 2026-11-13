"""Focused source-frame coverage regressions for streaming parsers."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(ROOT.parents[1] / 'clients'))

import parsing


class StubRefs:
    missing_calls = set()

    def opaque(self, kind, value):
        return f'{kind}:{value}' if value else None


def derive_sse(events, names=None):
    names = names or ['message'] * len(events)
    body = ''.join('event: ' + name + '\ndata: ' + json.dumps(value) + '\n\n'
                   for name, value in zip(names, events))
    return parsing.derive_events({'type': 'response', 'body': body}, StubRefs())


def outputs(result, kind=None):
    return [event for event in result['events'] if event['origin'] == 'output'
            and (kind is None or event['kind'] == kind)]


class ParserCoverageTests(unittest.TestCase):
    def test_anthropic_unknown_delta_is_explicit_and_downgrades_completion(self):
        result = derive_sse([
            {'type': 'message_start', 'message': {'model': 'claude', 'role': 'assistant', 'content': []}},
            {'type': 'content_block_start', 'index': 0,
             'content_block': {'type': 'text', 'text': ''}},
            {'type': 'content_block_delta', 'index': 0,
             'delta': {'type': 'text_delta', 'text': 'visible'}},
            {'type': 'content_block_delta', 'index': 0,
             'delta': {'type': 'citations_delta', 'citation': {'secret': 'withheld'}}},
            {'type': 'message_stop'},
        ], ['message_start', 'content_block_start', 'content_block_delta',
            'content_block_delta', 'message_stop'])
        message = outputs(result, 'message')[0]
        unsupported = outputs(result, 'unsupported')[0]
        self.assertEqual(message['payload']['text'], 'visible')
        self.assertEqual(message['payload']['source_frame_event_indices'], [2, 3])
        self.assertEqual(unsupported['payload']['source_frame_event_indices'], [4])
        controls = outputs(result, 'response_meta')[0]
        self.assertEqual(controls['payload']['source_frame_event_indices'], [1, 5])
        self.assertFalse(result['stream_complete'])
        self.assertTrue(result['end_marker_observed'])
        self.assertTrue(controls['payload']['end_marker_observed'])
        self.assertEqual(message['payload']['stream_status'], 'incomplete')
        self.assertNotIn('citation', json.dumps(unsupported['payload']))

        consecutive = parsing.derive_events({'type': 'response', 'body': ''.join(json.dumps(value) for value in [
            {'type': 'message_delta', 'delta': {'stop_reason': 'end_turn'}},
            {'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'citations_delta'}},
            {'type': 'message_stop'},
        ])}, StubRefs())
        self.assertTrue(consecutive['end_marker_observed'])
        self.assertFalse(consecutive['stream_complete'])
        self.assertTrue(outputs(consecutive, 'response_meta')[0]['payload']['end_marker_observed'])

    def test_openai_content_array_and_nonobject_tool_fragment_are_unsupported(self):
        result = derive_sse([
            {'choices': [{'index': 0, 'delta': {'content': 'hello'}}]},
            {'choices': [{'index': 0, 'delta': {'content': [{'type': 'text', 'text': 'unsafe'}],
                          'tool_calls': [None]}}]},
            {'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]},
        ])
        message = outputs(result, 'message')[0]
        unsupported = outputs(result, 'unsupported')
        self.assertEqual(message['payload']['text'], 'hello')
        self.assertEqual(message['payload']['source_frame_event_indices'], [1])
        self.assertEqual(len(unsupported), 2)
        self.assertTrue(all(event['payload']['source_frame_event_indices'] == [2]
                            for event in unsupported))
        self.assertFalse(result['stream_complete'])

    def test_responses_item_id_is_provisional_and_text_uses_only_its_frames(self):
        result = derive_sse([
            {'type': 'response.output_text.delta', 'item_id': 'item_1', 'delta': 'first'},
            {'type': 'response.output_text.delta', 'item_id': 'item_1', 'delta': ' second'},
            {'type': 'response.function_call_arguments.delta', 'item_id': 'item_2', 'delta': '{"x":1}'},
            {'type': 'response.completed', 'response': {'status': 'completed', 'output': []}},
        ], ['response.output_text.delta', 'response.output_text.delta',
            'response.function_call_arguments.delta', 'response.completed'])
        message = outputs(result, 'message')[0]
        call = outputs(result, 'tool_call')[0]
        self.assertEqual(message['payload']['text'], 'first second')
        self.assertEqual(message['payload']['source_frame_event_indices'], [1, 2])
        self.assertIsNone(call['call_ref'])
        self.assertEqual(call['linkage_status'], 'unknown')
        self.assertIsNone(call['link'])
        self.assertEqual(call['payload']['source_frame_event_indices'], [3])

    def test_responses_completed_reconciles_final_items_without_duplicate_text(self):
        result = derive_sse([
            {'type': 'response.output_text.delta', 'item_id': 'm1', 'delta': 'FIRST'},
            {'type': 'response.completed', 'response': {'status': 'completed', 'output': [
                {'id': 'm1', 'type': 'message', 'content': [{'type': 'output_text', 'text': 'FIRST'}]},
                {'id': 'm2', 'type': 'message', 'content': [{'type': 'output_text', 'text': 'SECOND'}]},
                42,
            ]}},
        ], ['response.output_text.delta', 'response.completed'])
        messages = outputs(result, 'message')
        self.assertEqual([event['payload']['text'] for event in messages], ['FIRST', 'SECOND'])
        self.assertEqual(messages[0]['payload']['source_frame_event_indices'], [1, 2])
        self.assertEqual(messages[1]['payload']['source_frame_event_indices'], [2])
        invalid = outputs(result, 'unsupported')[0]
        self.assertEqual(invalid['payload']['source_frame_event_indices'], [2])
        self.assertFalse(result['stream_complete'])
        self.assertTrue(result['end_marker_observed'])
        meta = outputs(result, 'response_meta')[0]['payload']
        self.assertTrue(meta['end_marker_observed'])
        self.assertFalse(meta['supported_content_complete'])

    def test_malformed_provider_shapes_become_frame_scoped_unsupported(self):
        anthropic = derive_sse([
            {'type': 'message_delta', 'delta': 'bad'},
            {'type': 'error', 'error': 'bad'},
            {'type': 'message_stop'},
        ], ['message_delta', 'error', 'message_stop'])
        self.assertEqual(len(outputs(anthropic, 'unsupported')), 2)
        self.assertTrue(all(event['payload']['source_frame_event_indices'] in ([1], [2])
                            for event in outputs(anthropic, 'unsupported')))
        self.assertTrue(anthropic['end_marker_observed'])
        self.assertFalse(anthropic['stream_complete'])

        openai = derive_sse([
            {'choices': [{'index': [], 'delta': {'content': 'bad'}}]},
            {'choices': [{'index': 0, 'delta': {'tool_calls': [{'index': {}, 'function': {'arguments': '{}'}}]}}]},
        ])
        unsupported = outputs(openai, 'unsupported')
        self.assertEqual(len(unsupported), 2)
        self.assertEqual([event['payload']['source_frame_event_indices'] for event in unsupported], [[1], [2]])

        responses = derive_sse([
            {'type': 'response.created', 'response': 'bad'},
            {'type': 'response.completed', 'response': 'bad'},
        ], ['response.created', 'response.completed'])
        self.assertEqual(len(outputs(responses, 'unsupported')), 2)
        self.assertFalse(responses['stream_complete'])

    def test_complete_responses_item_id_alone_does_not_create_call_edge(self):
        result = parsing.derive_events({'type': 'response', 'body': json.dumps({
            'output': [{'type': 'function_call', 'id': 'fc_1', 'name': 'lookup', 'arguments': '{}'}]
        })}, StubRefs())
        call = outputs(result, 'tool_call')[0]
        self.assertIsNone(call['call_ref'])
        self.assertIsNone(call['link'])
        self.assertEqual(call['linkage_status'], 'unknown')


if __name__ == '__main__':
    unittest.main()
