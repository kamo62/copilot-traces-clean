"""Invented-only checks for lane D's read-only utility measurement."""
import importlib.util
import io
from pathlib import Path
import random
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))
import sanitise

SPEC = importlib.util.spec_from_file_location('utility_measurement', ROOT / 'tools' / 'measure_sanitiser_utility.py')
measurement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measurement)


def meter():
    policy = sanitise.Policy({'policy_version': 'invented-d', 'scope': 'invented-d',
                              'aliases': {}, 'assisted_detector': {'enabled': False}}, b'd' * 48)
    return measurement.measured_sanitizer(sanitise)(policy)


class MeasurementLaneDTests(unittest.TestCase):
    def test_blank_gaps_and_crlf_are_in_one_replacement_block(self):
        text = 'keep\r\nx\\y\r\n \r\nz\\q\r\nkeep'
        blocks, fallback = measurement.replacement_blocks(text, lambda line: '\\' in line, sanitise.LINE_BREAK, 'file')
        self.assertEqual([text[a:b] for a, b in blocks], ['x\\y\r\n \r\nz\\q'])
        self.assertFalse(fallback)
        measured = meter()
        measured._replace_lines(text, lambda line: '\\' in line, 'file')
        self.assertEqual(measured.counts['file_characters'], len('x\\y\r\n \r\nz\\q'))
        self.assertEqual(measured.counts['file_blocks'], 1)
        self.assertEqual(measured.counts['file_lines'], 3)

    def test_growth_fallback_counts_whole_string_once_not_candidate_blocks(self):
        text = '\n'.join(['x\\y', 'a'] * 100)
        measured = meter()
        result = measured._replace_lines(text, lambda line: '\\' in line, 'file')
        self.assertEqual(result, measured.refs.opaque('file', text))
        self.assertEqual(measured.counts['file_characters'], len(text))
        self.assertEqual(measured.counts['file_blocks'], 1)
        self.assertEqual(measured.counts['file_fallbacks'], 1)

    def test_interval_prediction_preserves_mixed_line_endings_and_empty_lines(self):
        randomiser = random.Random(31)
        for _ in range(100):
            text = ''.join(randomiser.choice(('ordinary', 'x\\y', ' ', '', '\n', '\r', '\r\n'))
                           for _ in range(30))
            measured = meter()
            result = measured._replace_lines(text, lambda line: '\\' in line, 'file')
            baseline = sanitise.Sanitizer(measured.policy)
            self.assertEqual(result, baseline._replace_lines(text, lambda line: '\\' in line, 'file'))

    def test_long_run_and_windows_line_counts_match_unchanged_payloads(self):
        measured = meter()
        measured.record_backslash_paths = True
        payload = {'text': 'keep\nC:\\Invented\\src\\a.cs:line 42\nkeep\n' + 'x' * 128}
        result = measured.payload(payload)
        self.assertEqual(measured.events_verified, 1)
        self.assertIn('file_', result['text'])
        self.assertIn('id_', result['text'])
        self.assertEqual(measured.counts['file_location_lines'], 1)
        self.assertEqual(measured.counts['id_characters'], 128)

    def test_instrumentation_does_not_relax_a_hold(self):
        measured = meter()
        with self.assertRaises(sanitise.HoldError) as failure:
            measured.payload({'text': '{"credentials": ["invented fixture"]}'})
        self.assertEqual(failure.exception.reason, 'embedded_credential_container')
        self.assertEqual(measured.events_verified, 0)

    def test_numbered_location_and_fenced_code_are_indicators_not_content(self):
        measured = meter()
        payload = {'text': '```cs\nvar x = "C:\\Invented\\a.cs:7";\n```\nkeep'}
        measured.payload(payload)
        self.assertEqual(measured.counts['file_location_lines'], 1)
        self.assertEqual(measured.counts['file_code_shaped_lines'], 1)
        self.assertNotIn('text', measured.counts)

    def test_generated_references_are_not_counted_as_literal_characters_twice(self):
        measured = meter()
        measured.refs.recording = True
        reference = measured.refs.opaque('id', 'invented')
        measured._replace_lines(reference + '\\x', lambda line: True, 'file')
        self.assertEqual(measured.counts['file_characters'], len(reference) + 2)
        self.assertEqual(measured.counts['file_literal_characters'], 2)

    def test_instrumentation_never_copies_a_growing_generated_reference_set(self):
        class NoCopySet(set):
            def copy(self):
                raise AssertionError('quadratic generated-reference copying')
        measured = meter()
        reference = measured.refs.opaque('id', 'invented')
        measured.refs.generated = NoCopySet([reference])
        measured._replace_lines(reference + '\\x', lambda line: True, 'file')
        self.assertEqual(measured.counts['file_literal_characters'], 2)

    def test_keys_have_separate_counters_and_are_not_record_text(self):
        measured = meter()
        measured.payload({'C:\\Invented\\a.py': 'ordinary prose'})
        self.assertGreater(measured.counts['key_file_characters'], 0)
        self.assertEqual(measured.counts['file_characters'], 0)
        self.assertEqual(list(measurement.strings({'invented key': 'value'})), ['value'])

    def test_source_text_budget_excludes_frame_refs_and_withheld_markers(self):
        import research
        event = {'kind': 'message', 'role': 'user', 'payload': {
            'text': 'invented prose', 'source_frame_refs': ['event_' + 'd' * 24],
            'block_type': 'text', 'authorship': 'unknown'}}
        self.assertEqual(measurement.source_text_characters(event, research), len('invented prose'))
        event['role'] = 'system'
        self.assertEqual(measurement.source_text_characters(event, research), 0)
        event = {'kind': 'tool_result', 'payload': {'content': [
            {'type': 'text', 'text': 'invented'}, {'type': 'image', 'source': {'data': 'invented attachment'}}]}}
        self.assertEqual(measurement.source_text_characters(event, research), len('text') + len('invented'))

    def test_a_value_named_key_is_still_record_text(self):
        measured = meter()
        measured.payload({'key': 'C:\\Invented\\a.py'})
        self.assertGreater(measured.counts['file_characters'], 0)
        self.assertEqual(measured.counts['key_file_characters'], 0)

    def test_zero_loss_records_remain_in_quantiles_and_share_denominator(self):
        rows = [{'input_characters': 10, 'file_characters': 8}, {'input_characters': 10},
                {'input_characters': 20}, {'input_characters': 20}]
        summary = measurement.summarise(rows)
        self.assertEqual(summary['file_characters'], {'total': 8, 'median': 0, 'p90': 8})
        self.assertEqual(summary['line_character_share'], 8 / 60)

    def test_decoded_text_share_is_not_diluted_by_protocol_input_characters(self):
        rows = [{'input_characters': 100, 'source_text_characters': 10, 'line_characters': 5,
                 'file_characters': 5, 'literal_line_characters': 4},
                {'input_characters': 100, 'source_text_characters': 10}]
        summary = measurement.summarise(rows)
        self.assertEqual(summary['line_character_share'], 5 / 200)
        self.assertEqual(summary['source_text_line_share'], 5 / 20)
        self.assertEqual(summary['source_text_nonreference_line_share'], 4 / 20)

    def test_disproportionate_strata_are_reweighted_to_record_population(self):
        population = [{'endpoint': 'messages', 'record_type': 'request', 'records': 90},
                      {'endpoint': 'messages', 'record_type': 'response', 'records': 10}]
        rows = [{'endpoint': 'messages', 'record_type': 'request', 'window_flag': 1},
                {'endpoint': 'messages', 'record_type': 'response', 'window_flag': 0}]
        summary = measurement.weighted_summary(rows, population)
        self.assertEqual(summary['window_flag']['mean'], .9)
        self.assertEqual(summary['window_flag']['estimated_population_total'], 90)

    def test_read_only_queries_and_primary_key_sample_have_hard_bounds(self):
        db = mock.Mock()
        measurement.read_rows(db, 'SELECT count() FROM invented')
        self.assertNotIn('readonly', db.rows.call_args.args[0])  # rows() sends readonly=2
        self.assertIn('max_memory_usage=536870912', db.rows.call_args.args[0])
        for sql in ('INSERT INTO invented VALUES (1)', 'SELECT 1; DROP TABLE invented'):
            with self.assertRaises(ValueError):
                measurement.read_rows(db, sql)
        sql = measurement.sample_sql('rev_' + 'd' * 32, 'messages', 'request', 200)
        self.assertIn('LIMIT 200', sql)
        self.assertIn('PREWHERE id IN', sql)
        self.assertNotIn('record_json', sql)
        with self.assertRaises(ValueError):
            measurement.sample_sql('rev_' + 'd' * 32, 'messages', 'request', 201)

    def test_record_context_counts_loss_in_sibling_event_without_local_path(self):
        import parsing
        import research
        import json
        row = {'id': 'd' * 64, 'user_id': 123, 'record_json': json.dumps({
            'type': 'request', 'body': json.dumps({'messages': [
                {'role': 'user', 'content': 'C:\\Invented\\a.py'},
                {'role': 'assistant', 'content': 'corp\\invented'}]})})}
        revision = {'revision_id': 'rev_' + 'd' * 32}
        measured = meter()
        result = measurement.measure_record(row, revision, sanitise, research, parsing, measured.policy,
                                             'messages', 'request')
        self.assertEqual(result['window_flag'], 1)
        self.assertEqual(result['context_only_loss_events'], 1)
        self.assertEqual(result['verified_payloads'], result['events'])
        self.assertNotIn(row['id'], str(result))
        self.assertNotIn('Invented', str(result))

    def test_failure_output_never_contains_exception_content(self):
        output = io.StringIO()
        with mock.patch.object(sys, 'argv', ['measure', '--revision', 'rev_' + 'd' * 32]), \
                mock.patch.object(measurement, 'run', side_effect=ValueError('invented restricted text')), \
                mock.patch('sys.stdout', output):
            self.assertEqual(measurement.main(), 1)
        self.assertEqual(output.getvalue().strip(), '{"measurement_failed": "ValueError"}')


class ArgumentFailureTests(unittest.TestCase):
    def test_malformed_arguments_are_not_echoed(self):
        import contextlib
        import io
        for argv in (['--revision', 'rev_x', '--sample-per-stratum', 'SENTINEL-secret-value'],
                     ['--revision', 'rev_x', '--SENTINEL-secret-flag']):
            with self.subTest(argv=argv):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    with self.assertRaises(SystemExit):
                        measurement.main(argv)
                self.assertNotIn('SENTINEL', out.getvalue() + err.getvalue())
                self.assertIn('invalid_arguments', out.getvalue())


if __name__ == '__main__':
    unittest.main()
