#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Regression tests for suite/runner verdicts; no VM or device is opened."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from qemu_verdict import assess


SOURCE = Path(__file__).resolve().parent
EXPECTED = ["test_one", "test_two"]


def good_console():
    return "\n".join([
        "SPARKLINK_USB_GATE: PASS expected=2 found=2 bound=2",
        "SPARKLINK_CASE_BEGIN: test_one",
        "  OK:   intentional successful assertion",
        "SPARKLINK_CASE_END: test_one PASS",
        "SPARKLINK_CASE_BEGIN: test_two",
        "SPARKLINK_CASE_END: test_two PASS",
        "=== All tests completed ===",
        "SPARKLINK_TEST_SUMMARY: cases=2 failed=0 skipped=0",
        "SPARKLINK_KERNEL_LOG_BEGIN",
        "[    0.000000] test kernel ring",
        "SPARKLINK_KERNEL_LOG_END",
        "QEMU_TEST_RESULT: PASS (exit=0)", "",
    ])


class ConsoleVerdict(unittest.TestCase):
    def verdict(self, log, exit_status=0):
        return assess(log, EXPECTED, exit_status, 2)[0]

    def test_complete_clean_run_passes(self):
        self.assertEqual(self.verdict(good_console()), 0)

    def test_kernel_ring_is_required_even_when_console_printk_is_quiet(self):
        for marker in ("SPARKLINK_KERNEL_LOG_BEGIN", "SPARKLINK_KERNEL_LOG_END",
                       "[    0.000000] test kernel ring"):
            with self.subTest(marker=marker):
                self.assertEqual(self.verdict(good_console().replace(marker, "")), 1)
        self.assertEqual(self.verdict(good_console() + "SPARKLINK_KERNEL_LOG_END\n"), 1)
        self.assertEqual(self.verdict(good_console().replace(
            "SPARKLINK_KERNEL_LOG_BEGIN", "TEMP").replace(
            "SPARKLINK_KERNEL_LOG_END", "SPARKLINK_KERNEL_LOG_BEGIN").replace(
            "TEMP", "SPARKLINK_KERNEL_LOG_END")), 1)

    def test_fault_in_quiet_kernel_ring_still_fails(self):
        self.assertEqual(self.verdict(good_console().replace(
            "test kernel ring", "WARNING: CPU: 0 PID: 1")), 1)

    def test_false_pass_marker_cannot_hide_assertion(self):
        self.assertEqual(self.verdict(good_console() + "  FAIL: intentional\n"), 1)

    def test_failed_case_without_failure_text_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "test_one PASS", "test_one FAIL")), 1)

    def test_summary_failure_without_failure_text_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace("failed=0", "failed=1")), 1)

    def test_kernel_fault_even_after_pass_is_rejected(self):
        for fault in ("BUG: sleeping function called from invalid context",
                      "WARNING: CPU: 0 PID: 1", "Kernel panic - not syncing",
                      "Oops: 0000", "KASAN: use-after-free", "KCSAN: data-race",
                      "UBSAN: array-index-out-of-bounds",
                      "watchdog: BUG: soft lockup - CPU#0 stuck"):
            with self.subTest(fault=fault):
                self.assertEqual(self.verdict(good_console() +
                                             "[    1.234] " + fault + "\n"), 1)
        self.assertEqual(self.verdict(good_console() +
            "[    1.234][    T1] WARNING: CPU: 0 PID: 1\n"), 1)

    def test_timeout_with_complete_pass_log_is_rejected(self):
        self.assertEqual(self.verdict(good_console(), 124), 1)

    def test_launch_error_with_stale_pass_log_is_rejected(self):
        self.assertEqual(self.verdict(good_console(), 1), 1)

    def test_missing_case_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "SPARKLINK_CASE_BEGIN: test_two\nSPARKLINK_CASE_END: test_two PASS\n", "")), 1)

    def test_replaced_case_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace("test_two", "test_other")), 1)

    def test_duplicate_case_is_rejected(self):
        self.assertEqual(self.verdict(good_console() +
            "SPARKLINK_CASE_BEGIN: test_two\nSPARKLINK_CASE_END: test_two PASS\n"), 1)

    def test_crashed_case_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "SPARKLINK_CASE_END: test_two PASS\n", "")), 1)

    def test_missing_summary_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "SPARKLINK_TEST_SUMMARY: cases=2 failed=0 skipped=0\n", "")), 1)

    def test_truncated_suite_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "=== All tests completed ===\n", "")), 1)

    def test_missing_or_ambiguous_guest_result_is_rejected(self):
        for log in (good_console().replace("QEMU_TEST_RESULT: PASS (exit=0)\n", ""),
                    good_console() + "QEMU_TEST_RESULT: PASS (exit=0)\n",
                    good_console().replace("exit=0", "exit=1")):
            with self.subTest(log=log):
                self.assertEqual(self.verdict(log), 1)

    def test_usb_count_or_binding_mismatch_is_rejected(self):
        for old, new in (("expected=2", "expected=1"), ("found=2", "found=1"),
                         ("bound=2", "bound=1")):
            with self.subTest(new=new):
                self.assertEqual(self.verdict(good_console().replace(old, new)), 1)

    def test_missing_usb_gate_is_rejected(self):
        self.assertEqual(self.verdict(good_console().replace(
            "SPARKLINK_USB_GATE: PASS expected=2 found=2 bound=2\n", "")), 1)

    def test_skip_is_explicit_and_never_full_pass(self):
        log = good_console().replace("test_two PASS", "test_two SKIP").replace(
            "skipped=0", "skipped=1").replace("PASS (exit=0)", "SKIP (exit=4)")
        log += "  SKIP: unsupported capability\n"
        self.assertEqual(self.verdict(log), 4)
        self.assertEqual(self.verdict(log.replace("SKIP (exit=4)", "PASS (exit=0)")), 1)

    def test_unreported_skip_is_rejected(self):
        self.assertEqual(self.verdict(good_console() + "  SKIP: missing backend\n"), 1)


class VerdictCli(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sparklink-verdict-")
        self.directory = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_cli_rejects_false_pass_artifact(self):
        console = self.directory / "false-pass.log"
        manifest = self.directory / "expected.txt"
        console.write_text(good_console() + "  FAIL: deliberately failing artifact\n")
        manifest.write_text("\n".join(EXPECTED) + "\n")
        result = subprocess.run(["python3", SOURCE / "qemu_verdict.py", "--console",
                                console, "--expected-cases", manifest, "--qemu-exit",
                                "0", "--expected-usb", "2"],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("QEMU_VERDICT: FAIL", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
