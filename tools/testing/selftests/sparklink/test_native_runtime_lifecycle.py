#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Native virtual verdict tests; no USB, SDK, KVM or hardware evidence."""
import unittest
from run_runtime_lifecycle import assess_native

GOOD = '''NATIVE_RAW_STATUS: fe preserved
NATIVE_ADD_SECOND
NATIVE_HOST: index=0 queries=18 features=80 version=5 dialect_reject=1
NATIVE_HOST: index=1 queries=18 features=80 version=5 dialect_reject=1
NATIVE_REMOVE_FIRST
NATIVE_READD_FIRST
NATIVE_LIFETIME: old=1 new=3 unaffected=2
NATIVE_LIFECYCLE: PASS
RUNTIME_KERNEL_LOG_BEGIN
[    0.000000] Linux version synthetic-verdict-fixture
RUNTIME_KERNEL_LOG_END
RUNTIME_GUEST_EXIT: 0
'''


EVENTS = ('NATIVE_EVENTS: index=0 retained=32 first=9 last=40 lost=8 payload=278 '
          'fanout=2 fault_retry=1 poll=1\n'
          'NATIVE_EVENTS: index=1 retained=32 first=9 last=40 lost=8 payload=278 '
          'fanout=2 fault_retry=1 poll=1\n'
          'NATIVE_EVENTS_REPLUG: seq=9 lost=8 old_hup=1 new_generation=1\n')


class NativeVerdict(unittest.TestCase):
    def test_missing_full_kernel_log(self):
        self.assertTrue(assess_native(GOOD.replace('RUNTIME_KERNEL_LOG_BEGIN', 'missing'), 0))

    def test_missing_early_kernel_log(self):
        self.assertTrue(assess_native(GOOD.replace('[    0.000000]', '[    1.000000]'), 0))

    def test_duplicate_kernel_log(self):
        self.assertTrue(assess_native(GOOD + 'RUNTIME_KERNEL_LOG_END\n', 0))
    def test_event_stream(self):
        self.assertEqual(assess_native(GOOD + EVENTS, 0, events=True), [])

    def test_missing_event_stream(self):
        self.assertTrue(assess_native(GOOD, 0, events=True))

    def test_event_fanout_missing(self):
        self.assertTrue(assess_native(GOOD + EVENTS.replace('fanout=2', 'fanout=1'), 0, events=True))

    def test_event_payload_truncated(self):
        self.assertTrue(assess_native(GOOD + EVENTS.replace('payload=278', 'payload=240'), 0, events=True))

    def test_event_loss_hidden(self):
        self.assertTrue(assess_native(GOOD + EVENTS.replace('lost=8', 'lost=0'), 0, events=True))

    def test_event_owner_duplicate(self):
        self.assertTrue(assess_native(GOOD + EVENTS.replace('index=1', 'index=0'), 0, events=True))

    def test_event_replug_missing(self):
        self.assertTrue(assess_native(GOOD + EVENTS.split('NATIVE_EVENTS_REPLUG')[0], 0, events=True))

    def test_event_unexpected(self):
        self.assertTrue(assess_native(GOOD + EVENTS, 0))

    def test_complete(self):
        self.assertEqual(assess_native(GOOD, 0), [])

    def test_qemu_error(self):
        self.assertTrue(assess_native(GOOD, 124))

    def test_kernel_fault(self):
        self.assertTrue(assess_native(GOOD + '[1.2] WARNING: at usb.c\n', 0))

    def test_failure_even_with_pass(self):
        self.assertTrue(assess_native(GOOD + 'NATIVE_FAILURE: stale retargeted\n', 0))

    def test_missing_remove(self):
        self.assertTrue(assess_native(GOOD.replace('NATIVE_REMOVE_FIRST\n', ''), 0))

    def test_duplicate_pass(self):
        self.assertTrue(assess_native(GOOD + 'NATIVE_LIFECYCLE: PASS\n', 0))

    def test_wrong_marker_order(self):
        self.assertTrue(assess_native(GOOD.replace('NATIVE_ADD_SECOND', 'NATIVE_READD_FIRST', 1), 0))

    def test_missing_host(self):
        self.assertTrue(assess_native(GOOD.replace('NATIVE_HOST: index=1', 'MISSING_HOST: index=1'), 0))

    def test_duplicate_owner(self):
        self.assertTrue(assess_native(GOOD.replace('NATIVE_HOST: index=1', 'NATIVE_HOST: index=0'), 0))

    def test_missing_feature_bits(self):
        self.assertTrue(assess_native(GOOD.replace('features=80', 'features=64'), 0))

    def test_status_alias(self):
        self.assertTrue(assess_native(GOOD.replace('fe preserved', '03 preserved'), 0))

    def test_reused_generation(self):
        self.assertTrue(assess_native(GOOD.replace('new=3', 'new=1'), 0))

    def test_unaffected_generation_changed(self):
        self.assertTrue(assess_native(GOOD.replace('unaffected=2', 'unaffected=3'), 0))

    def test_missing_guest_exit(self):
        self.assertTrue(assess_native(GOOD.replace('RUNTIME_GUEST_EXIT: 0\n', ''), 0))


FAULT = GOOD.replace('NATIVE_RAW_STATUS: fe preserved', 'NATIVE_FAULT: id=0 removed errno=71').replace(
    'NATIVE_REMOVE_FIRST', 'NATIVE_FAULT_FIRST').replace(
    'NATIVE_HOST: index=0 queries=18 features=80 version=5 dialect_reject=1\n', '')


class NativeFaultVerdict(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(assess_native(FAULT, 0, True), [])

    def test_normal_gate_not_fault_evidence(self):
        self.assertTrue(assess_native(GOOD, 0, True))

    def test_wrong_error(self):
        self.assertTrue(assess_native(FAULT.replace('errno=71', 'errno=5'), 0, True))

    def test_missing_fault(self):
        self.assertTrue(assess_native(FAULT.replace('NATIVE_FAULT: id=0 removed errno=71', ''), 0, True))

    def test_missing_unaffected_queries(self):
        self.assertTrue(assess_native(FAULT.replace('queries=18', 'queries=17'), 0, True))

    def test_fault_does_not_replace_normal_gate(self):
        self.assertTrue(assess_native(FAULT, 0))

    def test_kernel_error_still_fails(self):
        self.assertTrue(assess_native(FAULT + '[1.0] Oops: deadlock\n', 0, True))


if __name__ == '__main__':
    unittest.main()

DISCOVERY = ("NATIVE_CONTROLLER_STATE: index=0 setup_then_ready=1 version=5 features=80\n"
             "NATIVE_CONTROLLER_STATE: index=1 setup_then_ready=1 version=5 features=80\n"
             "NATIVE_CONTROLLER_FAULT: index=0 ready_cleared=1 errno=110\n"
             "NATIVE_DISCOVERY: index=0 cycles=5 failures=4 stop_failure=1 cancel=1 power=-42 snapshots=1 raw_reject=1 no_rsp=1\n"
             "NATIVE_DISCOVERY: index=1 cycles=5 failures=4 stop_failure=1 cancel=1 power=-42 snapshots=1 raw_reject=1 no_rsp=1\n"
             "NATIVE_DISCOVERY_TIMEOUT: index=0 errno=110 radio_unknown=1\n")
DISCOVERY_GOOD = GOOD.replace('NATIVE_REMOVE_FIRST', DISCOVERY + 'NATIVE_REMOVE_FIRST').replace(
    'NATIVE_LIFETIME:', 'NATIVE_DISCOVERY_REPLUG: fault_reset=1 old_generation=1\nNATIVE_LIFETIME:')
class DiscoveryVerdict(unittest.TestCase):
    def test_full(self): self.assertEqual(assess_native(DISCOVERY_GOOD, 0, discovery=True), [])
    def test_missing(self): self.assertTrue(assess_native(GOOD, 0, discovery=True))
    def test_duplicate_owner(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace('index=1 cycles', 'index=0 cycles'), 0, discovery=True))
    def test_truncated_fields(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace('failures=4', 'failures=3'), 0, discovery=True))
    def test_unexpected(self): self.assertTrue(assess_native(DISCOVERY_GOOD, 0))
    def test_extra_malformed(self): self.assertTrue(assess_native(DISCOVERY_GOOD+'NATIVE_DISCOVERY: invalid\n', 0, discovery=True))
    def test_missing_fault(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace('NATIVE_DISCOVERY_TIMEOUT', 'missing'), 0, discovery=True))
    def test_wrong_radio(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace('radio_unknown=1', 'radio_unknown=0'), 0, discovery=True))
    def test_wrong_order(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace(DISCOVERY, '')+DISCOVERY, 0, discovery=True))
    def test_wrong_replug(self): self.assertTrue(assess_native(DISCOVERY_GOOD.replace('fault_reset=1', 'fault_reset=0'), 0, discovery=True))
