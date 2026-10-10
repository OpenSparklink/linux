# SPDX-License-Identifier: GPL-2.0-only
import unittest
from run_native_open_test import assess_userfault


def golden():
    return '\n'.join([
        'RPC_FAULT_ARMED: mode=query id=1 generation=2 kernel_wp=1 thread=1 epoll_empty=1',
        'RPC_FAULT_QUERY: elapsed_ms=0.001 free=1 copy_blocked=1',
        'RPC_FAULT_WAKE: mode=query elapsed_ms=0.001 event_hup=1 snoop_hup=1 copy_blocked=1',
        'RPC_FAULT_CASE: mode=query copy_release=1 result=snapshot get=1 put=1 close=1 sends=0 old_fd=ENODEV new_lease=1 survivor=1',
        'RPC_FAULT_ARMED: mode=acquire id=1 generation=4 kernel_wp=1 thread=1 epoll_empty=1',
        'RPC_FAULT_WAKE: mode=acquire elapsed_ms=0.001 event_hup=1 snoop_hup=1 copy_blocked=1',
        'RPC_FAULT_CASE: mode=acquire copy_release=1 result=ENODEV get=1 put=1 close=1 sends=0 old_fd=ENODEV new_lease=1 survivor=1',
        'NATIVE_HOST: index=0 queries=18 features=80 version=5 dialect_reject=1',
        'RPC_FAULT_LIFECYCLE: PASS synthetic_only=1 cases=2',
        'NATIVE_OPEN_MODULE_EXIT: 0', 'RUNTIME_GUEST_EXIT: 0',
        'RUNTIME_KERNEL_LOG_BEGIN', '[    0.000000] Linux version fixture', 'RUNTIME_KERNEL_LOG_END', ''])


class UsercopyVerdict(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(assess_userfault(golden(), 0), [])

    def test_missing_duplicate(self):
        lines = golden().splitlines()
        for i, line in enumerate(lines):
            with self.subTest(line=line):
                self.assertTrue(assess_userfault('\n'.join(lines[:i] + lines[i + 1:]), 0))
                if not line.startswith('['):
                    self.assertTrue(assess_userfault(golden() + line + '\n', 0))

    def test_proof(self):
        for before, after in [('kernel_wp=1', 'kernel_wp=0'), ('thread=1', 'thread=0'),
                              ('epoll_empty=1', 'epoll_empty=0'), ('event_hup=1', 'event_hup=0'),
                              ('snoop_hup=1', 'snoop_hup=0'), ('copy_blocked=1', 'copy_blocked=0'),
                              ('result=ENODEV', 'result=success'), ('get=1 put=1', 'get=1 put=0')]:
            with self.subTest(before=before):
                self.assertTrue(assess_userfault(golden().replace(before, after), 0))

    def test_timing_identity(self):
        for bad in ['200', '-1', 'nan', 'inf', 'bad']:
            self.assertTrue(assess_userfault(golden().replace('0.001', bad), 0))
        for before, after in [('id=1', 'id=0'), ('generation=2', 'generation=0'),
                              ('generation=4', 'generation=2'), ('generation=4', 'generation=18446744073709551616')]:
            self.assertTrue(assess_userfault(golden().replace(before, after), 0))

    def test_phases(self):
        lines = golden().splitlines()
        lines[0], lines[1] = lines[1], lines[0]
        self.assertTrue(assess_userfault('\n'.join(lines), 0))
        self.assertTrue(assess_userfault(golden().replace('RPC_FAULT_LIFECYCLE: PASS synthetic_only=1 cases=2\n', '') +
                                       'RPC_FAULT_LIFECYCLE: PASS synthetic_only=1 cases=2\n', 0))

    def test_process_failures(self):
        self.assertTrue(assess_userfault(golden(), 1))
        for marker in ['RPC_FAULT_QUERY_BLOCKED:', 'RPC_FAULT_WAKE_TIMEOUT:', 'RPC_FAULT_LATE_LEASE:',
                       'NATIVE_FAILURE:', 'BUG:', 'WARNING:', 'RUNTIME_GUEST_EXIT: 1', 'NATIVE_OPEN_MODULE_EXIT: 1']:
            with self.subTest(marker=marker):
                self.assertTrue(assess_userfault(golden() + marker + '\n', 0))


if __name__ == '__main__':
    unittest.main()
