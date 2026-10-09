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
RUNTIME_GUEST_EXIT: 0
'''


class NativeVerdict(unittest.TestCase):
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
