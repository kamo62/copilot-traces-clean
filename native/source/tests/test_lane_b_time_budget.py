"""Lane B: invented-only scaling, span fidelity and interruptible worker deadlines."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import random
import re
import select
import signal
import statistics
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'api'))

import research
from sanitise import (AssistedSpanDetector, CREDENTIAL_PATTERNS, HoldError, Policy, QUOTED_PATH_PATTERN,
                      Sanitizer, canonical)


def invented_policy():
    return Policy({'policy_version': 'invented-lane-b', 'scope': 'invented-lane-b',
                   'aliases': {'person': ['Nerina Frostwillow'], 'org': ['Invented Holdings']}}, b'b' * 48)


class InventedSpanDetector(AssistedSpanDetector):
    def __init__(self):
        pass  # No endpoint, credential, cache or transport: invented spans only.

    def detect(self, text, field):
        return [(index, index + 8, text[index:index + 8], 'PERSON') for index in range(0, len(text) - 8, 128)]


class ProbeDeadline(BaseException):
    pass


@contextmanager
def probe_budget(seconds=30):
    def interrupt(*_):
        raise ProbeDeadline()
    previous = signal.signal(signal.SIGALRM, interrupt)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@unittest.skipUnless(hasattr(signal, 'setitimer'), 'POSIX timers required')
class PayloadScalingTests(unittest.TestCase):
    def assert_linear(self, make_payload, small_size, expected='processed', detector=None):
        timings = []
        for size in (small_size, small_size * 4):
            payload = make_payload(size)
            samples = []
            for _ in range(3):
                clean = Sanitizer(invented_policy(), detector)
                # CPU time isolates algorithmic growth from shared-host/cgroup
                # descheduling. The probe guard and worker tests use wall time.
                started = time.process_time()
                outcome = 'processed'
                try:
                    with probe_budget():
                        clean.payload(payload)
                except HoldError as failure:
                    outcome = failure.reason
                except ProbeDeadline:
                    self.fail('Payload exceeded the probe deadline at size ' + str(size))
                samples.append(time.process_time() - started)
                self.assertEqual(outcome, expected)
            timings.append(statistics.median(samples))
        # Allow scheduling noise and fixed overhead, but not quadratic (16x)
        # growth. The old quoted-path/private-key/collision paths fail this.
        self.assertLess(timings[1], 6 * timings[0] + 0.03, 'small/4x seconds: ' + str(timings))

    def test_base64url_credential_names_scale(self):
        # f11f063 already guards run starts; c31d68c retried at each hyphen.
        self.assert_linear(lambda n: {'content': ('Zy8nXv-_Ab2e' * ((n + 11) // 12))[:n]}, 65536)

    def test_credential_keywords_in_long_names_scale(self):
        self.assert_linear(lambda n: {'content': ('authtokenapi-key_secret-' * ((n + 22) // 23))[:n]}, 65536)

    def test_quote_followed_by_whitespace_scales(self):
        self.assert_linear(lambda n: {'content': '"' + ' ' * n}, 16384)

    def test_unterminated_quoted_path_with_whitespace_scales(self):
        self.assert_linear(lambda n: {'content': '"/a' + ' ' * n}, 16384)

    def test_quoted_path_with_wrong_closing_quote_scales(self):
        self.assert_linear(lambda n: {'content': '"/a' + ' ' * n + '`'}, 16384)

    def test_unterminated_private_key_blocks_scale_and_hold(self):
        self.assert_linear(lambda n: {'content': ('-----BEGIN RSA PRIVATE KEY-----\n' * ((n + 30) // 31))[:n]},
                           65536, 'final_leak_check_credential')

    def test_colliding_truncated_keys_scale(self):
        self.assert_linear(lambda n: {('invented field ' * 20) + str(i): 0 for i in range(n)}, 2000)

    def test_assisted_span_replacement_scales(self):
        self.assert_linear(lambda n: {'content': ('invented ordinary prose ' * ((n + 23) // 24))[:n]},
                           512 * 1024, detector=InventedSpanDetector())


class SpanFidelityTests(unittest.TestCase):
    def test_quoted_path_spans_equal_the_original_pattern(self):
        reference = re.compile(r'''(?P<quote>["'`])\s*(?P<path>(?:[A-Za-z]:\\|/|\.\.?/)[^"'`\r\n<>|]+?)\s*(?P=quote)''')
        samples = ['" /a  "', "'./a b.py\t'", '`../a\n`', '"/ "', '"/"', '" /  \r\n"',
                   '"C:\\Program Files\\Invented\\x.py  "', '" /a\n b"', '" /a\t\v\f\u2003"']
        generator = random.Random(631)
        for _ in range(4000):
            quote = generator.choice('"\'`')
            prefix = generator.choice(('/', './', '../', 'C:\\', 'not-a-path'))
            body = ''.join(generator.choice('ab/\\ .\t\r\n\v\f\u2003<>|"\'`')
                           for _ in range(generator.randrange(24)))
            samples.append(quote + generator.choice(('', ' ', '\n\t')) + prefix + body +
                           generator.choice((' ', '\r\n', '')) + generator.choice('"\'`'))
        for text in samples:
            want = [(match.span(), match.groupdict()) for match in reference.finditer(text)]
            got = [(match.span(), match.groupdict()) for match in QUOTED_PATH_PATTERN.finditer(text)]
            self.assertEqual(got, want)  # Do not print fixture bodies on failure.

    def test_private_key_complete_spans_and_holds_are_preserved(self):
        reference = re.compile(r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----', re.S)
        begin = '-----BEGIN RSA PRIVATE KEY-----'
        end = '-----END EC PRIVATE KEY-----'
        for text in ('before ' + begin + '\ninvented-body\n' + end + ' after',
                     begin + begin + '\ninvented-body\n' + end,
                     begin + 'invented-body' + end + begin + 'second-body' + end):
            pattern, replacement = CREDENTIAL_PATTERNS[0]
            self.assertEqual(pattern.sub(replacement, text), reference.sub('[REDACTED_PRIVATE_KEY]', text))
        for text in (begin + 'invented-body', begin * 20, end + 'invented-body',
                     begin + 'body' + end + begin + 'unterminated-body'):
            with self.assertRaises(HoldError) as context:
                Sanitizer(invented_policy()).payload({'content': text})
            self.assertEqual(context.exception.reason, 'final_leak_check_credential')

    def test_final_check_holds_complete_and_unterminated_key_blocks(self):
        begin = '-----BEGIN RSA PRIVATE KEY-----'
        end = '-----END RSA PRIVATE KEY-----'
        for text in (begin + 'invented-body', begin + 'invented-body' + end):
            with self.assertRaises(HoldError) as context:
                Sanitizer(invented_policy()).assert_clean({'content': 'invented'}, {'content': text})
            self.assertEqual(context.exception.reason, 'final_leak_check_credential')

    def test_duplicate_key_suffixes_preserve_order_and_natural_collisions(self):
        raw = {'invented field': 1, 'invented_field__2': 2, 'invented  field': 3,
               'invented\tfield': 4, 'invented_field__3': 5, 'invented\nfield': 6}
        clean = Sanitizer(invented_policy()).payload(raw)
        self.assertEqual(list(clean.items()), [('invented_field', 1), ('invented_field__2', 2),
                                              ('invented_field__3', 3), ('invented_field__4', 4),
                                              ('invented_field__3__2', 5), ('invented_field__5', 6)])

    def test_prefixed_credential_names_still_redact_values(self):
        for name in ('token', 'x-auth', 'my-api_token', 'db-password', 'client_secret',
                     'credentials', 'x_credential', 'x-api-key'):
            for quote in ('', '"', "'"):
                text = name + '=' + quote + 'invented-sensitive-value' + quote
                output = canonical(Sanitizer(invented_policy()).payload({'content': text}))
                self.assertNotIn('invented-sensitive-value', output)

    def test_assisted_span_output_equals_reverse_splicing(self):
        detector = InventedSpanDetector()
        clean = Sanitizer(invented_policy())
        text = 'Invented ordinary prose. ' * 30
        expected = text
        for start, end, span_text, entity in sorted(detector.detect(text, 'content'), reverse=True):
            expected = expected[:start] + clean.refs.opaque('entity', entity + '\x00' + span_text) + expected[end:]
        self.assertEqual(detector.apply(text, 'content', clean.refs), expected)

    def test_overlapping_assisted_spans_hold(self):
        detector = InventedSpanDetector()
        with mock.patch.object(detector, 'detect', return_value=[(0, 6, 'Invent', 'PERSON'),
                                                               (2, 8, 'vented', 'PERSON')]):
            with self.assertRaises(HoldError) as context:
                detector.apply('Invented prose', 'content', Sanitizer(invented_policy()).refs)
        self.assertEqual(context.exception.reason, 'detector_overlapping_spans')


class RecordTimeLimitTests(unittest.TestCase):
    def test_time_limit_defaults_and_bounded_overrides(self):
        name = 'COPILOT_RESEARCH_MAX_RECORD_SECONDS'
        for raw, expected in (('', 30), (' 1 ', 1), ('47', 47), ('300', 300)):
            with mock.patch.dict(os.environ, {name: raw}):
                self.assertEqual(research._seconds_limit(name, 30, 1, 300), expected)
        for raw in ('0', '-1', '301', 'nan', 'inf', '1.5', '30s'):
            with mock.patch.dict(os.environ, {name: raw}):
                with self.assertRaises(ValueError):
                    research._seconds_limit(name, 30, 1, 300)

    def test_revision_pins_the_budget_and_status_reports_it(self):
        config = SimpleNamespace(policy=invented_policy(), detector=None, detector_model='disabled')
        with mock.patch.object(research, 'MAX_RECORD_SECONDS', 30):
            first, payload = research.config_revision(config, 10, 'b' * 64)
            self.assertEqual(payload['limits']['max_record_seconds'], 30)
            self.assertEqual(research.ResearchConfig({}).safe_status()['limits']['max_record_seconds'], 30)
        with mock.patch.object(research, 'MAX_RECORD_SECONDS', 31):
            second, payload = research.config_revision(config, 10, 'b' * 64)
            self.assertEqual(payload['limits']['max_record_seconds'], 31)
        self.assertNotEqual(first, second)

    def test_record_deadline_is_not_an_event_exclusion_reason(self):
        self.assertNotIn('record_time_budget_exceeded', research.EXCLUSION_REASONS)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'POSIX timers required')
    def test_timer_and_handler_are_restored_on_success_and_failure(self):
        previous = signal.getsignal(signal.SIGALRM)
        for failure in (False, True):
            try:
                with research._record_time_budget():
                    self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
                    if failure:
                        raise HoldError('invented-hold')
            except HoldError:
                pass
            self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
            self.assertEqual(signal.getsignal(signal.SIGALRM), previous)

    def test_non_main_thread_fails_closed(self):
        errors = []
        def run():
            try:
                with research._record_time_budget():
                    errors.append('unbounded')
            except research.ConfigError:
                errors.append('configuration_error')
        thread = threading.Thread(target=run)
        thread.start()
        thread.join(timeout=1)
        self.assertEqual(errors, ['configuration_error'])

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'POSIX timers required')
    def test_existing_timer_fails_closed_without_replacing_it(self):
        previous = signal.getsignal(signal.SIGALRM)
        try:
            signal.setitimer(signal.ITIMER_REAL, 10)
            with self.assertRaises(research.ConfigError):
                with research._record_time_budget():
                    self.fail('Occupied timer was silently replaced')
            self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 0)
            self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)

    @unittest.skipUnless(hasattr(signal, 'setitimer'), 'POSIX timers required')
    def test_worker_interrupts_regex_holds_and_processes_next_record(self):
        for stage in ('text', 'payload_prescan', 'parse', 'wall_wait'):
            with self.subTest(stage=stage):
                # A separate process bounds the test itself if the budget is
                # absent or only checks elapsed time after the regex returns.
                try:
                    result = subprocess.run([sys.executable, str(Path(__file__).resolve()),
                                             '--worker-deadline-probe', stage],
                                            capture_output=True, text=True, timeout=5, check=True)
                except subprocess.TimeoutExpired:
                    self.fail('Worker did not interrupt regex work')
                data = json.loads(result.stdout)
                self.assertEqual(data['statuses'], [['held', 'record_time_budget_exceeded'], ['processed', '']])
                self.assertEqual(data['written_records'], 1)
                self.assertEqual(data['checkpoints'], [1, 2])
                self.assertEqual(data['timer'], [0.0, 0.0])
                self.assertTrue(data['handler_restored'])
                self.assertTrue(data['flags_reset'])
                self.assertEqual(data['interrupted_operations'], 1)


def worker_deadline_probe(stage):
    """Run actual parser/event-row code with invented records and in-memory storage."""
    clean = Sanitizer(invented_policy())
    trigger = 'invented-lane-b-regex-stall'
    sources = []
    for sequence, content in enumerate((trigger, 'An invented safe message.'), 1):
        record = {'type': 'request', 'body': json.dumps({'messages': [{'role': 'user', 'content': content}]})}
        raw = canonical(record)
        sources.append({'id': str(sequence) * 64, 'seq': sequence, 'timestamp': 1, 'user_id': 1,
                        'record_json': raw, 'content_sha256': hashlib.sha256(raw.encode()).hexdigest()})
    revision = {'revision_id': 'rev_' + 'b' * 32, 'schema_version': research.SCHEMA_VERSION, 'config_json': '{}'}
    statuses, written, checkpoints = [], set(), []
    interrupted, flags_reset = [], []
    original_text = clean.text
    original_scan = clean.holds_backslash_paths
    original_parse = research.derive_events
    original_handler = signal.getsignal(signal.SIGALRM)

    def regex_stall():
        try:
            re.search(r'(a+)+$', 'a' * 100000 + '!')
        except Exception:
            # An interrupt that subclasses Exception could be swallowed by
            # application handlers; the worker deadline must bypass them.
            pass
        finally:
            interrupted.append(1)

    def text(value, field='content'):
        if stage == 'text' and value == trigger:
            regex_stall()
        return original_text(value, field)

    def text_or_wait(value, field='content'):
        if stage == 'wall_wait' and value == trigger:
            try:
                select.select([], [], [], 10)  # No CPU work: prove a wall-clock, not CPU, budget.
            finally:
                interrupted.append(1)
        return text(value, field)

    def scan(payload):
        if stage == 'payload_prescan' and clean.refs.recording and trigger in canonical(payload):
            regex_stall()
        return original_scan(payload)

    def parse(record, refs):
        if trigger not in canonical(record):
            flags_reset.append(not clean.refs.recording and not clean.record_backslash_paths)
        elif stage == 'parse':
            regex_stall()
        return original_parse(record, refs)

    def rows(query):
        if 'AS expected_sha256' in query:
            return [{'id': row['id'], 'seq': row['seq'], 'expected_sha256': row['content_sha256']} for row in sources]
        if 'SELECT attempt_count' in query:
            return [{'attempt_count': 2, 'retry_epoch': 1}]
        source = next(row for row in sources if research.db.literal(row['id']) in query)
        if 'length(record_json)' in query:
            return [{'bytes': len(source['record_json'].encode())}]
        return [source]

    def insert(table, values):
        assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), 'Storage write was under the record timer'
        if table == 'research_processing':
            status = values[0]
            statuses.append([status['status'], status['failure_class']])
            if status['status'] == 'held':
                assert status['event_count'] == 0 and status['pipeline_id'] == '' and status['attempt_count'] == 0
                assert status['retry_epoch'] == 1
        if table == 'research_events':
            written.update(row['record_id'] for row in values)

    def checkpoint(key, value=None):
        if value:
            assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
            checkpoints.append(value['seq'])

    config = SimpleNamespace(sanitisation_available=True, sanitiser=lambda: clean, identity_enabled=False)
    with mock.patch.object(research, 'MAX_RECORD_SECONDS', 1), \
            mock.patch.object(research, 'ResearchConfig', return_value=config), \
            mock.patch.object(research, '_worker_revision', return_value=revision), \
            mock.patch.object(research, '_checkpoint', side_effect=checkpoint), \
            mock.patch.object(research.db, 'rows', side_effect=rows), \
            mock.patch.object(research.db, 'insert', side_effect=insert), \
            mock.patch.object(research.db, 'execute', side_effect=AssertionError('No network')), \
            mock.patch.object(research, 'derive_events', side_effect=parse), \
            mock.patch.object(clean, 'text', side_effect=text_or_wait), \
            mock.patch.object(clean, 'holds_backslash_paths', side_effect=scan):
        result = research.process_once({})
    assert result['records'] == 2
    print(json.dumps({'statuses': statuses, 'written_records': len(written), 'checkpoints': checkpoints,
                      'timer': signal.getitimer(signal.ITIMER_REAL), 'flags_reset': all(flags_reset) and bool(flags_reset),
                      'handler_restored': signal.getsignal(signal.SIGALRM) == original_handler,
                      'interrupted_operations': len(interrupted)}))


class BudgetTeardownTests(unittest.TestCase):
    def test_handler_is_restored_when_the_alarm_fires_during_cancellation(self):
        import signal
        previous = signal.getsignal(signal.SIGALRM)
        real = signal.setitimer
        calls = []

        def setitimer(which, seconds, *rest):
            calls.append(seconds)
            result = real(which, 0)
            if seconds == 0 and calls.count(0) == 1:
                # A real timer fires at most once; the first cancellation is hit.
                raise research._RecordDeadline()
            return result

        with mock.patch.object(research.signal, 'setitimer', side_effect=setitimer):
            with self.assertRaises(research._RecordDeadline):
                with research._record_time_budget():
                    pass
        self.assertIs(signal.getsignal(signal.SIGALRM), previous)


class CpuTimeBudgetTests(unittest.TestCase):
    """Council round 1 (Opus): the budget counts CPU time, with a wall backstop."""

    def test_waiting_does_not_spend_the_budget_but_computing_does(self):
        import signal
        with mock.patch.object(research, 'MAX_RECORD_SECONDS', 1):
            with research._record_time_budget():
                self.assertGreater(signal.getitimer(signal.ITIMER_PROF)[0], 0)
                self.assertGreater(signal.getitimer(signal.ITIMER_REAL)[0], 1)
                time.sleep(1.3)  # idle wall time beyond the budget: no interrupt
            with self.assertRaises(research._RecordDeadline):
                with research._record_time_budget():
                    while True:
                        sum(range(10000))
        self.assertEqual(signal.getitimer(signal.ITIMER_PROF), (0.0, 0.0))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertIs(signal.getsignal(signal.SIGPROF), signal.SIG_DFL)

    def assert_clean_state(self, previous):
        import signal
        self.assertEqual(signal.getitimer(signal.ITIMER_PROF), (0.0, 0.0))
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual((signal.getsignal(signal.SIGALRM), signal.getsignal(signal.SIGPROF)), previous)
        self.assertFalse(research._BUDGET['active'])
        with research._record_time_budget():  # the next record can start its own budget
            pass

    def test_a_deadline_disarms_both_timers_wherever_it_lands(self):
        # Council round 3 (Astra): a timer could fire at cleanup entry, before
        # any cancellation ran. The handler now disarms both timers itself.
        import signal
        previous = (signal.getsignal(signal.SIGALRM), signal.getsignal(signal.SIGPROF))
        for signum in (signal.SIGALRM, signal.SIGPROF):
            with self.subTest(signum=signum):
                with self.assertRaises(research._RecordDeadline):
                    with research._record_time_budget():
                        research._interrupt_record(signum, None)
                self.assert_clean_state(previous)

    def test_a_second_signal_during_cleanup_is_ignored(self):
        import signal
        previous = (signal.getsignal(signal.SIGALRM), signal.getsignal(signal.SIGPROF))
        real = signal.setitimer

        def setitimer(which, seconds, *rest):
            result = real(which, seconds, *rest)
            if seconds == 0:
                research._interrupt_record(signal.SIGPROF, None)  # pending signal arriving late
            return result

        with mock.patch.object(research.signal, 'setitimer', side_effect=setitimer):
            with research._record_time_budget():
                pass
        self.assert_clean_state(previous)
        self.assertIsNone(research._interrupt_record(signal.SIGALRM, None))


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--worker-deadline-probe':
        worker_deadline_probe(sys.argv[2])
    else:
        unittest.main()
