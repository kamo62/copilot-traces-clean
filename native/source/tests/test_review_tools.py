"""Synthetic checks for coverage comparison, privacy evaluation, annotations and the admin review routes.

All data is invented. No server, network, model or local agent history is used; ClickHouse is mocked.
"""
import contextlib
import email.message
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
sys.path.insert(0, str(ROOT / 'api'))
sys.path.insert(0, str(REPO / 'clients'))

_TOKEN_DIR = tempfile.mkdtemp(prefix='review-tools-')
unittest.addModuleCleanup(shutil.rmtree, _TOKEN_DIR, True)
(Path(_TOKEN_DIR) / 'otlp').write_text('o' * 40)
os.environ.setdefault('COPILOT_OTLP_TOKEN_FILE', str(Path(_TOKEN_DIR) / 'otlp'))

import clickhouse  # noqa: E402
import conversation_coverage as coverage  # noqa: E402
import privacy_eval  # noqa: E402
import parsing  # noqa: E402
import research  # noqa: E402
import review  # noqa: E402
import service  # noqa: E402
from sanitise import Policy, Sanitizer  # noqa: E402

REV = 'rev_' + 'a' * 32
OBS = 'obs_' + 'b' * 24
EVT = ['event_' + str(index) * 24 for index in range(1, 5)]
KEYS = {'admin': 'a' * 40, 'status': 's' * 40, 'research': 'r' * 40}
ARGS = '{"path":"notes.txt","limit":20}'
CALL = {'id': 'call_A', 'type': 'function', 'function': {'name': 'read_file', 'arguments': ARGS}}
USER = {'role': 'user', 'content': 'Open the invented notes file and summarise it.'}
FINAL = 'The notes contain one invented line.'


def record(kind, body):
    return {'type': kind, '@timestamp': 1760000000000, 'user_id': 7, 'github_request_id': 'req-1', 'body': json.dumps(body)}


def conversation():
    return [
        record('request', {'messages': [USER]}),
        record('response', {'choices': [{'message': {'role': 'assistant', 'content': None, 'tool_calls': [CALL]}}]}),
        record('request', {'messages': [USER, {'role': 'assistant', 'content': None, 'tool_calls': [CALL]},
                                        {'role': 'tool', 'tool_call_id': 'call_A', 'content': 'invented notes line'}]}),
        record('response', {'choices': [{'message': {'role': 'assistant', 'content': FINAL}, 'finish_reason': 'stop'}]}),
    ]


def reference(call_id='call_A', source='invented_reference'):
    return {'contract': coverage.CONTRACT,
            'capture': {'source': source, 'client': 'invented-client', 'client_version': '0', 'task': 'invented-task'},
            'items': [{'kind': 'message', 'role': 'user', 'text': USER['content']},
                      {'kind': 'tool_call', 'call_id': call_id, 'name': 'read_file', 'arguments': json.loads(ARGS)},
                      {'kind': 'tool_result', 'call_id': call_id, 'content': 'invented notes line'},
                      {'kind': 'message', 'role': 'assistant', 'text': FINAL}]}


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='coverage-'))
        self.addCleanup(shutil.rmtree, self.directory, True)

    def run_source(self, records, expected=None):
        (self.directory / 'expected.json').write_text(json.dumps(expected or reference()))
        (self.directory / 'observed.json').write_text(json.dumps(records))
        return coverage.report(self.directory / 'expected.json', self.directory / 'observed.json', 'source-records')

    def test_exact_source_comparison_links_results_and_separates_repeated_history(self):
        result = self.run_source(conversation())
        self.assertEqual((result['result'], result['overall_verdict'], result['verdict_limits']), ('no_gaps_found', 'no_gaps_found', []))
        self.assertEqual(result['comparison_strength'], 'exact_content')
        self.assertEqual(result['counts']['matched'], 4)
        self.assertEqual(result['counts']['linked'], 1)
        self.assertEqual(result['counts']['repeated_exact_duplicates'], 2)  # history copies are not "extra"
        self.assertEqual(result['evidence_class'], 'synthetic_reference')
        self.assertFalse(result['boundaries']['session_boundaries_inferred'])
        text = json.dumps(result)
        for content in (USER['content'], FINAL, 'invented notes line', 'notes.txt'):
            self.assertNotIn(content, text)  # content-free: digests and positions only

    def test_done_marker_and_assistant_claim_never_close_a_gap(self):
        records = conversation()[:3] + [record('response', {'choices': [{'message': {
            'role': 'assistant', 'content': 'DONE: everything is finished'}, 'finish_reason': 'stop'}]})]
        result = self.run_source(records)
        self.assertEqual(result['result'], 'gaps_found')
        self.assertEqual(result['counts']['missing'], 1)
        self.assertEqual(result['counts']['extra_observed'], 1)
        self.assertFalse(result['boundaries']['last_expected_matched'])

    def test_duplicates_need_the_same_explicit_identity_and_content(self):
        other = {**CALL, 'id': 'call_B'}
        anonymous = {'type': 'function', 'function': CALL['function']}
        brief = reference()
        brief['items'] = brief['items'][:2]

        def calls(*members):
            return [conversation()[0], record('response', {'choices': [{'message': {
                'role': 'assistant', 'content': None, 'tool_calls': list(members)}}]})]
        different = self.run_source(calls(CALL, other), brief)  # same name and arguments, different explicit ID
        self.assertEqual([item['classification'] for item in different['unmatched_observed']], ['extra'])
        self.assertEqual(different['result'], 'no_gaps_found_with_extra_observed')
        unknown = self.run_source(calls(CALL, anonymous), brief)  # no identity: cannot establish a duplicate or an extra
        self.assertEqual([item['classification'] for item in unknown['unmatched_observed']], ['unassessable_unknown_identity'])
        self.assertEqual((unknown['result'], unknown['overall_verdict']), ('no_gaps_found', 'coverage_limited'))
        self.assertEqual(unknown['counts']['extra_observed'], 0)
        self.assertIn('unassessable_observed_items', unknown['verdict_limits'])

    def test_repeated_output_message_is_ambiguous_but_replayed_history_is_a_duplicate(self):
        final = record('response', {'choices': [{'message': {'role': 'assistant', 'content': FINAL}}]})
        brief = reference()
        brief['items'] = [brief['items'][0], brief['items'][3]]
        repeated = self.run_source([conversation()[0], final, final], brief)
        self.assertEqual([item['classification'] for item in repeated['unmatched_observed']], ['unassessable_repeated_content'])
        self.assertEqual(repeated['overall_verdict'], 'coverage_limited')
        replay = self.run_source([conversation()[0], final, record('request', {'messages': [USER]})], brief)
        self.assertEqual([item['classification'] for item in replay['unmatched_observed']], ['repeated_exact_duplicate'])

    def test_distinct_repeated_tool_calls_and_results_each_match_their_own_identity(self):
        other = {**CALL, 'id': 'call_B'}
        data = reference()
        data['items'] = [data['items'][0],
                         {'kind': 'tool_call', 'call_id': 'call_A', 'name': 'read_file', 'arguments': json.loads(ARGS)},
                         {'kind': 'tool_call', 'call_id': 'call_B', 'name': 'read_file', 'arguments': json.loads(ARGS)},
                         {'kind': 'tool_result', 'call_id': 'call_A', 'content': 'same'},
                         {'kind': 'tool_result', 'call_id': 'call_B', 'content': 'same'}]
        records = [conversation()[0],
                   record('response', {'choices': [{'message': {'role': 'assistant', 'content': None, 'tool_calls': [CALL, other]}}]}),
                   record('request', {'messages': [USER, {'role': 'assistant', 'content': None, 'tool_calls': [CALL, other]},
                                                   {'role': 'tool', 'tool_call_id': 'call_A', 'content': 'same'},
                                                   {'role': 'tool', 'tool_call_id': 'call_B', 'content': 'same'}]})]
        result = self.run_source(records, data)
        self.assertEqual((result['counts']['matched'], result['counts']['linked'], result['counts']['extra_observed']), (5, 2, 0))
        self.assertEqual(result['counts']['repeated_exact_duplicates'], 3)  # replayed user message and both calls
        self.assertEqual(result['overall_verdict'], 'no_gaps_found')
        swapped = self.run_source(records, {**data, 'items': data['items'][:3] + [
            {'kind': 'tool_result', 'call_id': 'call_B', 'content': 'other'}, data['items'][4]]})
        self.assertEqual(swapped['result'], 'gaps_found')

    def test_withheld_observed_events_limit_the_verdict_without_erasing_the_exact_result(self):
        records = conversation()
        records[0] = record('request', {'messages': [{'role': 'system', 'content': 'invented system text'}, USER]})
        result = self.run_source(records)
        self.assertEqual(result['result'], 'no_gaps_found')  # supported events still match exactly
        self.assertEqual(result['overall_verdict'], 'coverage_limited')
        self.assertIn('withheld_or_unsupported_observed_events', result['verdict_limits'])
        self.assertGreater(result['counts']['withheld_or_unsupported_observed'], 0)
        self.assertIn('not research-safe', result['report_handling'])
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(coverage.main(['--expected', str(self.directory / 'expected.json'),
                                            '--observed', str(self.directory / 'observed.json'),
                                            '--observed-format', 'source-records']), 1)

    def test_missing_result_out_of_order_wrong_identity_and_unknown_link(self):
        records = conversation()
        missing = self.run_source(records[:2] + records[3:])
        self.assertEqual((missing['counts']['missing'], missing['items'][2]['link']), (1, 'result_unmatched'))
        reordered = self.run_source([records[0], records[3], records[1], records[2]])
        self.assertEqual(reordered['counts']['out_of_order'], 1)
        self.assertEqual(reordered['result'], 'gaps_found')
        wrong = self.run_source(records, reference(call_id='call_OTHER'))
        self.assertEqual(wrong['items'][1]['status'], 'missing')  # explicit call identity differs
        orphan = conversation()
        orphan[2] = record('request', {'messages': [USER, {'role': 'tool', 'tool_call_id': 'call_A', 'content': 'invented notes line'}]})
        unknown = self.run_source(orphan)
        self.assertEqual(unknown['items'][2]['link'], 'unknown_link')
        self.assertEqual(unknown['result'], 'gaps_found')

    def test_sanitised_export_is_structural_only(self):
        policy = Policy({'policy_version': 'synthetic-1', 'scope': 'synthetic'}, b'k' * 48)
        clean, rows = Sanitizer(policy), []
        revision = {'revision_id': REV, 'config_json': '{}', 'schema_version': research.SCHEMA_VERSION}
        for number, source in enumerate(conversation(), 1):
            clean.refs.identity_scope = '7'
            parsed = parsing.derive_events(source, clean.refs)
            row = {'id': format(number, '064x'), 'seq': number, 'timestamp': 1760000000000, 'content_sha256': 'c' * 64}
            rows += research._event_rows(revision, None, row, parsed, clean)[0]
        (self.directory / 'export.jsonl').write_bytes(research.jsonl_bytes([research._export_event(row) for row in rows]))
        (self.directory / 'expected.json').write_text(json.dumps(reference()))
        result = coverage.report(self.directory / 'expected.json', self.directory / 'export.jsonl', 'research-export')
        self.assertEqual(result['comparison_strength'], 'structural_only')
        self.assertEqual(result['observed_kind'], 'sanitised_research_export')
        self.assertEqual(result['result'], 'no_gaps_found')
        self.assertFalse(result['extra_items_assessable'])  # repeated history cannot be told from extras structurally
        self.assertEqual(result['counts']['unclassified_structural'], 2)
        self.assertTrue(all(row['observed_sha256'] is None for row in result['items']))  # no text equality claimed
        self.assertEqual(result['items'][2]['link'], 'linked')

    def test_reference_contract_and_path_guards(self):
        self.assertEqual(len(coverage.load_expected((REPO / 'clients/conversation-coverage-reference.example.json').read_bytes())[1]), 4)
        bad = reference()
        bad['items'].insert(0, {'kind': 'tool_result', 'call_id': 'call_A', 'content': 'x'})
        with self.assertRaises(coverage.InputError):
            coverage.load_expected(json.dumps(bad).encode())  # result without an earlier call
        for broken in ({**reference(), 'contract': 'other/1'}, {**reference(), 'extra': 1}):
            with self.assertRaises(coverage.InputError):
                coverage.load_expected(json.dumps(broken).encode())
        history = self.directory / '.claude'
        history.mkdir()
        (history / 'session.json').write_text('{}')
        with self.assertRaises(coverage.InputError):
            coverage.read_input(history / 'session.json')
        link = self.directory / 'link.json'
        link.symlink_to(self.directory / 'missing.json')
        with self.assertRaises(coverage.InputError):
            coverage.read_input(link)
        with self.assertRaises(coverage.InputError):
            coverage.read_input(self.directory)  # a directory is never walked


class PrivacyEvalTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(tempfile.mkdtemp(prefix='privacy-'))
        self.addCleanup(shutil.rmtree, self.directory, True)
        self.policy = REPO / 'research-policy.example.json'
        self.example = REPO / 'clients/privacy-eval-cases.example.json'

    def write(self, data, name='cases.json', directory=None):
        path = (directory or self.directory) / name
        path.write_text(json.dumps(data))
        return path

    def test_example_cases_report_denominators_and_are_content_free(self):
        result = privacy_eval.evaluate(self.example, self.policy)
        totals = result['denominators']
        self.assertEqual((totals['cases'], totals['held'], totals['holds_as_expected'], totals['errors']), (7, 2, 2, 0))
        self.assertEqual((totals['removal_items'], totals['removal_misses'], totals['preservation_items'], totals['over_removed'],
                          totals['type_items'], totals['type_changes']), (13, 0, 7, 0, 4, 0))
        self.assertEqual(totals['removal_items_in_held_cases'], 1)
        self.assertEqual(result['thresholds']['approval_label'], 'proposed_not_operator_approved')
        self.assertFalse(result['anonymity_guarantee'] or result['release_gate_changed'] or result['detector_called'])
        text = json.dumps(result)
        for value in ('Alex Example', 'Example Holdings', 'sk-INVENTED', 'QuoteEngine', 'alex@example.com', 'calculate_total'):
            self.assertNotIn(value, text)

    def test_misses_over_removal_unexpected_hold_and_errors_are_counted(self):
        data = json.loads(self.example.read_text())
        data['cases'] = [
            {'id': 'unlabelled-name', 'payload': {'text': 'Ask Smithson about the build.'},
             'must_remove': [{'value': 'Smithson', 'category': 'person'}],
             'must_keep': [{'value': 'deadbeefdeadbeefdeadbeefdeadbeef', 'category': 'developer_intent'}]},
            {'id': 'surprise-hold', 'payload': {'text': 'cfg {"token": {"a": "b"}}'}},
            {'id': 'missed-hold', 'payload': {'text': 'plain'}, 'expect_hold': 'ambiguous_identity_field'},
            {'id': 'crash', 'payload': {'text': 'boom'}},
        ]
        data['cases'][0]['payload']['text'] += ' deadbeefdeadbeefdeadbeefdeadbeef'
        original = Sanitizer.payload

        def payload(sanitiser, value):
            if value.get('text') == 'boom':
                raise KeyError('x')
            return original(sanitiser, value)
        with mock.patch.object(Sanitizer, 'payload', payload):
            result = privacy_eval.evaluate(self.write(data), self.policy)
        totals = result['denominators']
        self.assertEqual((totals['removal_misses'], totals['over_removed'], totals['unexpected_holds'],
                          totals['holds_missed'], totals['errors']), (1, 1, 1, 1, 1))
        self.assertEqual(totals['removal_rate'], 0.0)
        self.assertFalse(result['thresholds']['all_met'])
        self.assertNotIn('Smithson', json.dumps(result))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(privacy_eval.main(['--cases', str(self.write(data, 'again.json')), '--policy', str(self.policy)]), 1)

    def test_threshold_values_are_finite_in_range_and_wrong_reason_holds_fail_the_gate(self):
        data = json.loads(self.example.read_text())
        for field, value in (('min_removal_rate', 1.5), ('min_preservation_rate', -0.1), ('max_errors', -1),
                             ('max_type_changes', 1.5), ('max_unexpected_holds', True), ('min_removal_rate', True),
                             ('max_missed_holds', 'x'), ('min_removal_rate', float('nan')), ('min_removal_rate', float('inf'))):
            data['thresholds'] = {'version': 'x', 'state': 'proposed', 'approved_by': None, field: value}
            with self.assertRaises(privacy_eval.InputError, msg=(field, value)):
                privacy_eval.load_cases(data, self.directory / 'cases.json')
        raw = self.example.read_text().replace('"min_removal_rate": 1.0', '"min_removal_rate": NaN')
        (self.directory / 'nan.json').write_text(raw)
        with self.assertRaises(privacy_eval.InputError):
            privacy_eval.evaluate(self.directory / 'nan.json', self.policy)  # NaN/Infinity are not valid JSON input
        data['thresholds'] = {'version': 'x', 'state': 'proposed', 'approved_by': None, 'min_removal_rate': 0, 'max_missed_holds': 0}
        privacy_eval.load_cases(data, self.directory / 'cases.json')  # boundary values are valid
        data['cases'] = [{'id': 'wrong-reason', 'payload': {'text': 'cfg {"token": {"a": "b"}}'},
                          'expect_hold': 'ambiguous_identity_field'}]
        report = privacy_eval.evaluate(self.write(data), self.policy)
        self.assertEqual((report['denominators']['holds_wrong_reason'], report['denominators']['holds_not_as_expected']), (1, 1))
        self.assertFalse(report['thresholds']['met']['max_missed_holds'])
        self.assertFalse(report['thresholds']['all_met'])
        self.assertIn('not research-safe', report['report_handling'])

    def test_thresholds_labels_and_restricted_inputs_are_enforced(self):
        data = json.loads(self.example.read_text())
        data['thresholds'] = None
        self.assertEqual(privacy_eval.evaluate(self.write(data), self.policy)['thresholds']['state'], 'not_defined')
        data['thresholds'] = {'version': 'x', 'state': 'operator_approved', 'approved_by': None, 'max_errors': 0}
        with self.assertRaises(privacy_eval.InputError):
            privacy_eval.evaluate(self.write(data), self.policy)
        data['thresholds'] = None
        data['dataset'] = {'label': 'heldout', 'provenance': 'restricted_labelled_heldout', 'split': 'held_out'}
        with self.assertRaises(privacy_eval.InputError):  # tracked tree: inside the repository but not under private/
            privacy_eval.load_cases(data, REPO / 'clients' / 'heldout.json')
        privacy_eval.load_cases(data, REPO / 'private' / 'heldout.json')
        data['dataset']['split'] = 'development'
        with self.assertRaises(privacy_eval.InputError):
            privacy_eval.load_cases(data, self.directory / 'heldout.json')
        data['dataset']['split'] = 'held_out'
        restricted = privacy_eval.evaluate(self.write(data), self.policy)  # outside the repository
        self.assertEqual(restricted['evidence_class'], 'restricted_labelled_heldout_unverified_labels')
        link = self.directory / 'link.json'
        link.symlink_to(self.example)
        with self.assertRaises(privacy_eval.InputError):
            privacy_eval.evaluate(link, self.policy)


class FakeDb:
    """Dispatch mocked ClickHouse reads by statement; records every statement for bound checks."""

    literal = staticmethod(clickhouse.literal)

    def __init__(self, **tables):
        self.tables, self.statements, self.inserted = tables, [], []

    def rows(self, sql):
        self.statements.append(sql)
        for marker, value in self.tables.items():
            if marker in sql:
                return value(sql) if callable(value) else value
        return []

    def insert(self, table, values):
        self.inserted.append((table, values))


class AnnotationTests(unittest.TestCase):
    def body(self, **changes):
        base = {'revision_id': REV, 'observation_ref': OBS, 'dimension': 'task_intent', 'label': 'bug_fix',
                'evidence_event_ids': [EVT[0]], 'reviewer': 'operator.one', 'note': 'restricted note'}
        return {**base, **changes}

    def store(self, body, events, status='processed', latest=None):
        fake = FakeDb(**{'SELECT record_id,status,failure_class': [{
            'record_id': 'c' * 64, 'status': status, 'failure_class': '', 'event_count': 4, 'pipeline_id': 'p'}],
            'SELECT e.event_id': events, 'FROM research_annotations': latest or []})
        with mock.patch.object(review, 'db', fake), mock.patch.object(research, '_revision_row', return_value={'revision_id': REV}):
            return review.store_annotation(body), fake

    def test_taxonomy_is_code_owned_and_validation_is_closed(self):
        self.assertEqual(review.TAXONOMY['task_intent']['labels'], ('code_help', 'feature_work', 'bug_fix', 'testing', 'review',
                         'documentation', 'presentation', 'email', 'other', 'unknown'))
        for change in ({'label': 'excellent'}, {'dimension': 'performance'}, {'reviewer': 'a b'}, {'note': 'x' * 501},
                       {'evidence_event_ids': []}, {'evidence_event_ids': ['event_x']}, {'evidence_event_ids': [EVT[0], EVT[0]]},
                       {'observation_ref': 'obs_bad'}, {'revision_id': 'rev_bad'}, {'note': 'bad \x00 note'}):
            with self.assertRaises(ValueError):
                review.validate_annotation(self.body(**change))
        with self.assertRaises(ValueError):
            review.validate_annotation({**self.body(), 'score': 5})
        self.assertEqual(review.validate_annotation(self.body(label='unknown', evidence_event_ids=[]))['evidence_event_ids'], [])

    def test_intent_needs_cited_user_message_not_tool_names(self):
        user = [{'event_id': EVT[0], 'kind': 'message', 'role': 'user'}]
        tool = [{'event_id': EVT[0], 'kind': 'tool_call', 'role': 'assistant'}]
        stored, fake = self.store(self.body(), user)
        self.assertEqual((stored['review_state'], stored['taxonomy_version'], stored['label']), ('reviewed', review.TAXONOMY_VERSION, 'bug_fix'))
        table, rows = fake.inserted[0]
        self.assertEqual((table, rows[0]['evidence_json']), ('research_annotations', json.dumps([EVT[0]])))
        with self.assertRaises(ValueError):
            self.store(self.body(), tool)  # tool activity alone cannot establish developer intent
        with self.assertRaises(ValueError):
            self.store(self.body(), [])  # cited event is not a current event of this observation
        with self.assertRaises(ValueError):
            self.store(self.body(), user, status='held')  # nothing derived to cite
        retrieval, _ = self.store(self.body(dimension='context_retrieval', label='file_read'), tool)
        self.assertEqual(retrieval['dimension'], 'context_retrieval')

    def test_outcome_labels_need_their_own_evidence_kind(self):
        assistant = [{'event_id': EVT[0], 'kind': 'message', 'role': 'assistant'}]
        result = [{'event_id': EVT[0], 'kind': 'tool_result', 'role': 'tool'}]
        user = [{'event_id': EVT[0], 'kind': 'message', 'role': 'user'}]
        call = [{'event_id': EVT[0], 'kind': 'tool_call', 'role': 'assistant'}]

        def outcome(label):
            return self.body(dimension='outcome', label=label)
        for label in ('tool_success_observed', 'tool_error_observed'):
            with self.assertRaises(ValueError):
                self.store(outcome(label), assistant)  # an assistant message is not a tool result
            self.assertEqual(self.store(outcome(label), result)[0]['label'], label)
        with self.assertRaises(ValueError):
            self.store(outcome('assistant_reported_done'), result)  # a tool result is not an assistant self-report
        self.assertEqual(self.store(outcome('assistant_reported_done'), assistant)[0]['label'], 'assistant_reported_done')
        with self.assertRaises(ValueError):
            self.store(outcome('assistant_reported_done'), user)
        self.assertEqual(self.store(outcome('no_outcome_observed'), user)[0]['label'], 'no_outcome_observed')
        self.assertEqual(self.store(self.body(dimension='context_retrieval', label='none_observed'), user)[0]['label'], 'none_observed')
        with self.assertRaises(ValueError):
            self.store(self.body(dimension='context_retrieval', label='search'), user)
        self.assertEqual(self.store(self.body(dimension='context_retrieval', label='search'), call)[0]['label'], 'search')
        requirements = review.taxonomy()['dimensions']['outcome']['label_evidence_requirements']
        self.assertIn('tool_success_observed', requirements)

    def test_identical_resubmission_is_idempotent_and_history_is_append_only(self):
        user = [{'event_id': EVT[0], 'kind': 'message', 'role': 'user'}]
        first, fake = self.store(self.body(), user)
        latest = [{**fake.inserted[0][1][0], 'dimension': 'task_intent'}]
        again, repeat = self.store(self.body(), user, latest=latest)
        self.assertEqual(again['annotation_id'], first['annotation_id'])
        self.assertEqual(repeat.inserted, [])
        changed, repeat = self.store(self.body(label='testing'), user, latest=latest)
        self.assertEqual(len(repeat.inserted), 1)
        self.assertNotEqual(changed['annotation_id'], first['annotation_id'])
        self.assertTrue(any('ORDER BY version DESC LIMIT 1 BY dimension' in sql for sql in repeat.statements))

    def test_annotations_are_not_part_of_exports(self):
        self.assertNotIn('research_annotations', Path(research.__file__).read_text())
        self.assertFalse([name for name in research.EVENT_SCHEMA['properties'] if 'annot' in name or 'note' in name])
        fake = FakeDb(**{'SELECT record_id,status,failure_class': [{
            'record_id': 'c' * 64, 'status': 'processed', 'failure_class': '', 'event_count': 4, 'pipeline_id': 'p'}]})
        with mock.patch.object(review, 'db', fake), mock.patch.object(research, '_revision_row', return_value={'revision_id': REV}):
            current = review.annotations(REV, OBS)
        self.assertEqual(current['current']['outcome'], {'dimension': 'outcome', 'review_state': 'unreviewed', 'label': None})
        self.assertFalse(current['exported_to_research'])


class ReviewQueryTests(unittest.TestCase):
    def test_observation_pages_are_bounded_and_validated(self):
        for kwargs in ({'limit': 0}, {'limit': 101}, {'after': 'nope'}, {'status': "x' OR 1=1 --"}):
            with self.assertRaises(ValueError):
                review.observations(REV, **kwargs)
        with self.assertRaises(ValueError):
            review.observations("rev_a' OR '1'='1")
        rows = [{'observation_ref': 'obs_' + str(number) * 24} for number in (1, 2)]
        fake = FakeDb(**{'FROM research_processing FINAL': rows})
        with mock.patch.object(review, 'db', fake):
            page = review.observations(REV, limit=2, status='held')
        self.assertEqual(page['next_after'], rows[-1]['observation_ref'])
        self.assertIn('LIMIT 2', fake.statements[0])
        self.assertIn("status='held'", fake.statements[0])
        self.assertNotIn('record_id', fake.statements[0].split('FROM')[0])  # source IDs are not listed

    def test_summary_counts_holds_exclusions_and_gaps_without_content(self):
        fake = FakeDb(**{'FROM research_revisions FINAL': [{
            'revision_id': REV, 'pending_records': 0, 'retry_pending_records': 0, 'retry_exhausted_records': 0, 'failed_records': 0}],
            'GROUP BY status,failure_class': [{'status': 'held', 'failure_class': 'source_record_oversized', 'observations': 2},
                                              {'status': 'processed', 'failure_class': '', 'observations': 5}],
            'GROUP BY kind,coverage_status': [{'kind': 'message', 'coverage_status': 'unknown', 'events': 9},
                                              {'kind': 'withheld', 'coverage_status': 'withheld', 'events': 3},
                                              {'kind': 'unsupported', 'coverage_status': 'unsupported', 'events': 1}]})
        with mock.patch.object(review, 'db', fake), mock.patch.object(research.ResearchConfig, '__init__', lambda *a, **k: None), \
                mock.patch.object(research.ResearchConfig, 'release_blockers', lambda self: ['release_setting_not_evaluated']):
            result = review.summary(REV)
        self.assertEqual((result['held_observations'], result['oversize_held_observations'], result['withheld_events'],
                          result['unsupported_events'], result['partial_or_unknown_events'], result['released']), (2, 2, 3, 1, 9, False))
        self.assertEqual(result['hold']['release_blocked'], ['release_setting_not_evaluated'])
        self.assertTrue(all('LIMIT' in sql for sql in fake.statements if 'GROUP BY' in sql))
        self.assertNotIn('payload', ' '.join(fake.statements))
        self.assertTrue(any('2 MiB' in gap for gap in result['known_gaps']))  # existing oversize HOLD stays explicit

    def test_compare_omits_oversized_original_and_bounds_derived_events(self):
        events = [{'event_index': index, 'payload_bytes': 120 * 1024} for index in range(5)]
        fake = FakeDb(**{'SELECT record_id,status,failure_class': [{
            'record_id': 'c' * 64, 'status': 'processed', 'failure_class': '', 'event_count': 5, 'pipeline_id': 'p'}],
            'length(record_json)': [{'bytes': review.ORIGINAL_DISPLAY_BYTES + 1}],
            'length(payload)': events, 'FROM research_annotations': []})
        with mock.patch.object(review, 'db', fake), mock.patch.object(research, '_revision_row', return_value={'revision_id': REV}), \
                mock.patch.object(review.archive, 'review_record', side_effect=AssertionError('oversized original must not load')):
            result = review.compare(REV, OBS)
        self.assertFalse(result['original']['included'])
        self.assertEqual(result['original']['reason'], 'over_display_bound')
        self.assertTrue(result['derived']['truncated'])
        self.assertEqual(result['derived']['next_from_index'], 2)  # two 120 KiB events fit the 256 KiB display budget
        self.assertEqual(result['original']['record_id'], 'c' * 64)  # exact admin-only ID to find it in the raw viewer
        fetch = [sql for sql in fake.statements if 'event_index IN (0,1)' in sql]
        self.assertEqual(len(fetch), 1)
        self.assertTrue(fetch[0].endswith('LIMIT 2 SETTINGS max_threads=1'))
        for bad in (-1, 'x'):
            with self.assertRaises(ValueError):
                review.compare(REV, OBS, bad)


class CompareBoundTests(unittest.TestCase):
    def compare(self, sizes, original=100):
        events = [{'event_index': index, 'event_id': 'event_' + str(index + 1) * 24, 'payload_bytes': size}
                  for index, size in enumerate(sizes)]
        fake = FakeDb(**{'SELECT record_id,status,failure_class': [{
            'record_id': 'c' * 64, 'status': 'processed', 'failure_class': '', 'event_count': len(sizes), 'pipeline_id': 'p'}],
            'length(record_json)': [{'bytes': original}], 'length(payload)': events, 'FROM research_annotations': []})
        record = {'record_id': 'c' * 64, 'content_sha256': 'd' * 64, 'record': {}}
        with mock.patch.object(review, 'db', fake), mock.patch.object(research, '_revision_row', return_value={'revision_id': REV}), \
                mock.patch.object(review.archive, 'review_record', return_value=record):
            return review.compare(REV, OBS), fake

    def test_first_oversized_event_is_named_and_later_events_still_load(self):
        big = review.DERIVED_DISPLAY_BYTES  # payload plus envelope overhead exceeds the documented bound
        result, fake = self.compare([big, 10 * 1024, 10 * 1024])
        derived = result['derived']
        self.assertEqual([(item['event_index'], item['reason']) for item in derived['omitted_events']], [(0, 'over_display_bound')])
        self.assertEqual(derived['omitted_events'][0]['event_id'], 'event_' + '1' * 24)
        self.assertFalse(derived['truncated'])
        self.assertIsNone(derived['next_from_index'])
        fetch = [sql for sql in fake.statements if 'event_index IN (' in sql]
        self.assertEqual(len(fetch), 1)
        self.assertIn('event_index IN (1,2)', fetch[0])  # the oversized event's payload is never selected
        self.assertTrue(result['original']['included'])

    def test_oversized_events_never_stall_pagination_or_exceed_the_budget(self):
        big = review.DERIVED_DISPLAY_BYTES
        only_big, fake = self.compare([big, big])
        self.assertEqual(len(only_big['derived']['omitted_events']), 2)
        self.assertEqual(only_big['derived']['events'], [])
        self.assertIsNone(only_big['derived']['next_from_index'])
        self.assertFalse([sql for sql in fake.statements if 'event_index IN (' in sql])  # no payload fetch at all
        paged, _ = self.compare([big, 130 * 1024, 130 * 1024])
        self.assertEqual(paged['derived']['next_from_index'], 2)  # strictly after the consumed events, from_index was 0
        self.assertTrue(paged['derived']['truncated'])
        self.assertEqual(len(paged['derived']['omitted_events']), 1)


class Harness(service.Handler):
    """Drive a real request handler without opening a socket."""

    def __init__(self, method, path, headers, body):
        self.command, self.path = method, path
        self.headers = email.message.Message()
        for name, value in headers.items():
            self.headers[name] = value
        self.rfile, self.wfile = io.BytesIO(body), io.BytesIO()
        self.connection = types.SimpleNamespace(settimeout=lambda _: None)
        self.request_version, self.requestline, self.client_address = 'HTTP/1.1', method + ' ' + path, ('127.0.0.1', 0)


class RouteTests(unittest.TestCase):
    PATHS = ('/v1/research/review/taxonomy', '/v1/research/review/summary?revision=' + REV,
             '/v1/research/review/observations?revision=' + REV,
             '/v1/research/review/compare?revision=%s&observation=%s' % (REV, OBS),
             '/v1/research/review/annotations?revision=%s&observation=%s' % (REV, OBS))

    def setUp(self):
        for name, value in (('KEY', KEYS['status']), ('ADMIN_KEY', KEYS['admin']), ('RESEARCH_KEY', KEYS['research'])):
            patcher = mock.patch.object(service, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def call(self, method, path, role=None, body=b'', **headers):
        if role:
            headers['Authorization'] = 'Bearer ' + (KEYS.get(role) or 'o' * 40)
        if method == 'POST':
            headers.setdefault('Content-Length', str(len(body)))
            headers.setdefault('Content-Type', 'application/json')
        handler = Harness(method, path, headers, body)
        getattr(handler, 'do_' + method)()
        head, _, payload = handler.wfile.getvalue().partition(b'\r\n\r\n')
        return int(head.split(b' ', 2)[1]), payload

    def test_only_admin_reaches_review_reads_and_annotation_writes(self):
        trap = mock.Mock(side_effect=AssertionError('reached review code without the admin role'))
        with mock.patch.multiple(review, taxonomy=trap, summary=trap, observations=trap, compare=trap, annotations=trap,
                                 store_annotation=trap):
            for role in (None, 'research', 'status', 'otlp'):
                for path in self.PATHS:
                    self.assertEqual(self.call('GET', path, role)[0], 401, (role, path))
                self.assertEqual(self.call('POST', '/v1/research/review/annotations', role, b'{}')[0], 401, role)
        self.assertEqual(self.call('GET', '/v1/research/review/taxonomy', 'admin')[0], 200)  # real, content-free taxonomy

    def test_inputs_are_validated_before_any_database_access(self):
        trap = mock.Mock(side_effect=AssertionError('database reached'))
        with mock.patch.object(review.db, 'rows', trap), mock.patch.object(review.db, 'insert', trap), \
                mock.patch.object(research.db, 'rows', trap):
            for path in ('/v1/research/review/summary', '/v1/research/review/summary?revision=bad',
                         '/v1/research/review/summary?revision=%s&revision=%s' % (REV, REV),
                         '/v1/research/review/summary?revision=%s&x=1' % REV,
                         '/v1/research/review/observations?revision=%s&limit=101' % REV,
                         '/v1/research/review/observations?revision=%s&limit=abc' % REV,
                         '/v1/research/review/observations?revision=%s&status=%%27%%20OR%%201' % REV,
                         '/v1/research/review/compare?revision=%s&observation=obs_x' % REV,
                         '/v1/research/review/compare?revision=%s&observation=%s&from=-1' % (REV, OBS)):
                self.assertEqual(self.call('GET', path, 'admin')[0], 400, path)
            self.assertEqual(self.call('GET', '/v1/research/review/unknown', 'admin')[0], 404)
            good = json.dumps({'revision_id': REV, 'observation_ref': OBS, 'dimension': 'task_intent', 'label': 'bug_fix',
                               'evidence_event_ids': [EVT[0]], 'reviewer': 'operator.one'})
            for body, headers in ((b'{}', {}), (b'[]', {}), (b'not json', {}), (good.replace('bug_fix', 'brilliant').encode(), {}),
                                  (good[:-1].encode() + b',"extra":1}', {}), (good.encode(), {'Content-Type': 'text/plain'}),
                                  (b'{"note":"' + b'x' * 17000 + b'"}', {}), (b'', {'Content-Length': '0'})):
                self.assertEqual(self.call('POST', '/v1/research/review/annotations', 'admin', body, **headers)[0], 400)
            self.assertEqual(self.call('POST', '/v1/research/review/annotations?x=1', 'admin', good.encode())[0], 404)

    def test_admin_write_returns_created_without_logging_content(self):
        stored = {'annotation_id': 'ann_x', 'review_state': 'reviewed'}
        with mock.patch.object(review, 'store_annotation', return_value=stored) as store:
            status, payload = self.call('POST', '/v1/research/review/annotations', 'admin', b'{"note":"restricted note"}')
        self.assertEqual((status, json.loads(payload)), (201, stored))
        store.assert_called_once_with({'note': 'restricted note'})

    def test_headless_service_has_no_custom_frontend_routes_or_assets(self):
        status, body = self.call('GET', '/')
        self.assertEqual(status, 200)
        self.assertIs(json.loads(body)['frontend'], False)
        for path in ('/viewer', '/viewer/', '/review', '/review/', '/docs/viewer.html',
                     '/docs/viewer.js', '/docs/review.html', '/docs/review.js'):
            for role in (None, 'admin'):
                self.assertEqual(self.call('GET', path, role)[0], 404, (path, role))
        self.assertEqual(self.call('GET', '/docs')[0], 200)
        self.assertEqual(self.call('GET', '/openapi.json')[0], 200)

    def test_contract_lists_the_new_admin_routes_with_admin_security(self):
        from openapi import SPECIFICATION
        self.assertEqual(SPECIFICATION['info']['version'], '3.0.0')
        for path in ('taxonomy', 'summary', 'observations', 'compare', 'annotations'):
            operations = SPECIFICATION['paths']['/v1/research/review/' + path]
            self.assertTrue(all(op['security'] == [{'adminBearer': []}] for op in operations.values()), path)
        self.assertEqual(research.SCHEMA_VERSION, 'research-event/2')  # event contract unchanged


if __name__ == '__main__':
    unittest.main()
