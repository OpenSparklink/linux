# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed assessor tests, independent of QEMU availability."""
import unittest
from run_native_open_test import assess


def golden():
    lines = []
    for i, result in enumerate([0, -5, -19, -5]):
        lines += [f'NATIVE_OPEN_SNAPSHOT: slot={i} elapsed_ms=0.001',
                  f'NATIVE_OPEN_PENDING: slot={i} id=1 generation={i + 2} snapshot_ms=0.001 '
                  'lease_eagain=1 refs=1 sends=0']
        if i >= 2:
            lines += [f'NATIVE_OPEN_RETIRING: slot={i} blocked=1 admission_closed=1 close=0 put=0']
        lines += [f'NATIVE_OPEN_CASE: slot={i} mode={i % 2} retiring={int(i >= 2)} result={result} '
                  f'close={int(i % 2 == 0)} get=1 put=1 sends=0 survivor=1 stale=1']
    return '\n'.join(lines + [
        'NATIVE_HOST: index=0 queries=18 features=80 version=5 dialect_reject=1',
        'NATIVE_OPEN_LIFECYCLE: PASS synthetic_only=1 cases=4',
        'NATIVE_OPEN_MODULE_EXIT: 0', 'RUNTIME_GUEST_EXIT: 0',
        'RUNTIME_KERNEL_LOG_BEGIN', '[    0.000000] Linux version fixture', 'RUNTIME_KERNEL_LOG_END', ''])


class NativeOpenVerdict(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(assess(golden(), 0), [])

    def test_missing_each_record(self):
        lines = golden().splitlines()
        for i in range(len(lines)):
            with self.subTest(i=i):
                self.assertTrue(assess('\n'.join(lines[:i] + lines[i + 1:]), 0))

    def test_duplicate_each_record(self):
        for line in golden().splitlines():
            if line.startswith('['):
                continue  # Kernel logs legitimately contain many boot records.
            with self.subTest(line=line):
                self.assertTrue(assess(golden() + line + '\n', 0))

    def test_measurement(self):
        for value in ['200', '-1', 'nan', 'inf', 'bad']:
            with self.subTest(value=value):
                self.assertTrue(assess(golden().replace('0.001', value), 0))

    def test_identity(self):
        for bad in ['id=0', 'id=2']:
            self.assertTrue(assess(golden().replace('id=1', bad), 0))
        for bad in ['generation=0', 'generation=18446744073709551616', 'generation=2']:
            self.assertTrue(assess(golden().replace('generation=3', bad), 0))

    def test_phases(self):
        lines = golden().splitlines()
        lines[1], lines[2] = lines[2], lines[1]
        self.assertTrue(assess('\n'.join(lines), 0))
        self.assertTrue(assess(golden().replace('NATIVE_OPEN_LIFECYCLE: PASS synthetic_only=1 cases=4\n', '') +
                               'NATIVE_OPEN_LIFECYCLE: PASS synthetic_only=1 cases=4\n', 0))

    def test_lifetime(self):
        for before, after in [('close=0 put=0', 'close=1 put=0'), ('get=1 put=1', 'get=1 put=2'),
                              ('sends=0', 'sends=1'), ('result=-19', 'result=0'),
                              ('lease_eagain=1', 'lease_eagain=0')]:
            with self.subTest(before=before):
                self.assertTrue(assess(golden().replace(before, after), 0))

    def test_process_kernel_failures(self):
        self.assertTrue(assess(golden(), 1))
        for marker in ['NATIVE_FAILURE: fixture', 'BUG: fixture', 'WARNING: fixture',
                       'RUNTIME_GUEST_EXIT: 1', 'NATIVE_OPEN_MODULE_EXIT: 1']:
            with self.subTest(marker=marker):
                self.assertTrue(assess(golden() + marker + '\n', 0))


if __name__ == '__main__':
    unittest.main()
