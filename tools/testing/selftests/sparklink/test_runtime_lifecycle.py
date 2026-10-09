#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Guard against false success in the virtual hotplug evidence verifier."""
import unittest

from run_runtime_lifecycle import assess

A = '01:02:03:04:05:06'
B = '11:12:13:14:15:16'
NEW = '21:22:23:24:25:26'
GOOD = f'''RUNTIME_QUERY: index=0 addr={A}
RUNTIME_ADD_SECOND
RUNTIME_QUERY: index=1 addr={B}
RUNTIME_HOST_BURST: index=0 mac=12 reset=2 submitted=13 resolved=13 timeouts=0
RUNTIME_HOST_BURST: index=1 mac=12 reset=2 submitted=13 resolved=13 timeouts=0
RUNTIME_REMOVE_FIRST
RUNTIME_QUERY: index=1 addr={B}
RUNTIME_READD_FIRST
RUNTIME_QUERY: index=0 addr={NEW}
RUNTIME_QUERY: index=1 addr={B}
RUNTIME_LIFECYCLE: PASS
RUNTIME_GUEST_EXIT: 0
'''


class LifecycleVerdict(unittest.TestCase):
    def test_complete_clean_run(self):
        self.assertEqual(assess(GOOD, 0), [])

    def test_timeout_after_pass(self):
        self.assertTrue(assess(GOOD, 124))

    def test_kernel_fault_after_pass(self):
        self.assertTrue(assess(GOOD + '[ 1.23] BUG: scheduling while atomic\n', 0))

    def test_guest_failure_even_with_pass(self):
        self.assertTrue(assess(GOOD + 'RUNTIME_FAILURE: old fd retargeted\n', 0))

    def test_missing_hotplug_phase(self):
        self.assertTrue(assess(GOOD.replace('RUNTIME_REMOVE_FIRST\n', ''), 0))

    def test_duplicate_pass(self):
        self.assertTrue(assess(GOOD + 'RUNTIME_LIFECYCLE: PASS\n', 0))

    def test_unaffected_identity_changed(self):
        self.assertTrue(assess(GOOD.replace(f'index=1 addr={B}\nRUNTIME_READD',
                                          f'index=1 addr={A}\nRUNTIME_READD'), 0))

    def test_missing_query(self):
        self.assertTrue(assess(GOOD.replace(f'RUNTIME_QUERY: index=0 addr={NEW}\n', ''), 0))

    def test_missing_guest_exit(self):
        self.assertTrue(assess(GOOD.replace('RUNTIME_GUEST_EXIT: 0\n', ''), 0))

    def test_missing_host_burst(self):
        self.assertTrue(assess(GOOD.replace('RUNTIME_HOST_BURST: index=0',
                                          'MISSING_HOST_BURST: index=0'), 0))

    def test_duplicate_host_owner(self):
        self.assertTrue(assess(GOOD.replace('RUNTIME_HOST_BURST: index=1',
                                          'RUNTIME_HOST_BURST: index=0'), 0))

    def test_wrong_host_response_count(self):
        self.assertTrue(assess(GOOD.replace('mac=12', 'mac=11'), 0))

    def test_lost_host_transaction(self):
        self.assertTrue(assess(GOOD.replace('resolved=13', 'resolved=12'), 0))

    def test_host_timeout_hidden_by_pass(self):
        self.assertTrue(assess(GOOD.replace('timeouts=0', 'timeouts=1'), 0))


if __name__ == '__main__':
    unittest.main()
