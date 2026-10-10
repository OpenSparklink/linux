# SPDX-License-Identifier: GPL-2.0-only
import unittest
from run_daemon_lifecycle import assess


def view(index, generation):
    return (f'Adapter /org/sparklink/slk{index}_g{generation}:\n  State:       Ready\n'
            f'  Generation:  {generation}\n  Address:     02:73:00:00:00:02\n  Profile:     1\n')


GOOD = ('DAEMON_UID: 1000\n' + view(0, 1) + 'DAEMON_ADD_SECOND\n' + view(1, 2) +
        'DAEMON_REMOVE_FIRST\n' + view(1, 2) + 'DAEMON_STALE_SELECTION: rejected\n' +
        'DAEMON_READD_FIRST\n' + view(0, 3) + view(1, 2) +
        'DAEMON_HOTPLUG: independent=2 same_process=1 new_generation=1\n'
        'DAEMON_LIFECYCLE: PASS\nDAEMON_GUEST_EXIT: 0\n'
        'DAEMON_KERNEL_LOG_BEGIN\n[    0.000000] early kernel\nDAEMON_KERNEL_LOG_END\n')


class DaemonVerdict(unittest.TestCase):
    def test_complete(self): self.assertEqual(assess(GOOD, 0), [])
    def test_exit(self): self.assertTrue(assess(GOOD, 1))
    def test_root(self): self.assertTrue(assess(GOOD.replace('UID: 1000', 'UID: 0'), 0))
    def test_setup(self): self.assertTrue(assess(GOOD.replace('State:       Ready', 'State:       Setup', 1), 0))
    def test_restart(self): self.assertTrue(assess(GOOD.replace('same_process=1', 'same_process=0'), 0))
    def test_stale(self): self.assertTrue(assess(GOOD.replace('STALE_SELECTION: rejected', 'STALE_SELECTION: accepted'), 0))
    def test_generation_reuse(self): self.assertTrue(assess(GOOD.replace(view(0, 3), view(0, 1)), 0))
    def test_changed_survivor(self): self.assertTrue(assess(GOOD.replace(view(1, 2), view(1, 4), 1), 0))
    def test_failure(self): self.assertTrue(assess(GOOD + 'DAEMON_FAILURE: assertion\n', 0))
    def test_missing_log(self): self.assertTrue(assess(GOOD.replace('DAEMON_KERNEL_LOG_END', 'missing'), 0))
    def test_truncated_log(self): self.assertTrue(assess(GOOD.replace('[    0.000000]', '[    1.000000]'), 0))
    def test_duplicate(self): self.assertTrue(assess(GOOD + 'DAEMON_LIFECYCLE: PASS\n', 0))


if __name__ == '__main__': unittest.main()
