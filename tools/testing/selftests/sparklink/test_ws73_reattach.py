#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Deterministic re-enumeration interleavings. No USB I/O or RF evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('reattach_lab', Path(__file__).with_name('ws73-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class Monitor:
    def __init__(self):
        self.attached = False
        self.calls = []
        self.on_set = lambda: None

    def execute(self, command, args):
        self.calls.append((command, args))
        if command == 'qom-get':
            return self.attached
        if command == 'qom-set':
            assert args['property'] == 'host-retry' and args['value'] is True
            self.on_set()
            return {}
        raise AssertionError('reattach must never add/delete a USB host object')


class ReattachmentTests(unittest.TestCase):
    def setUp(self):
        self.addresses = {'1-2.1': 7, '1-2.2': 8}
        self.records = []
        self.owned = False
        self.monitor = Monitor()
        self.watcher = lab.ReattachmentWatcher(self.addresses, self.records,
                                               owned=lambda pid, node: self.owned)
        self.device = dict(path='1-2.1', bus=1, address=9,
                           node='/dev/bus/usb/001/009', writable=True, interfaces=[])

    def poll(self, now=0):
        return self.watcher.poll(0, '1-2.1', self.device, 123, self.monitor, now)

    def pulses(self):
        return [c for c in self.monitor.calls if c[0] == 'qom-set']

    def test_complete_auto_open_preserves_object_and_other_port(self):
        self.monitor.attached = self.owned = True
        self.assertTrue(self.poll())
        self.assertEqual(self.addresses, {'1-2.1': 9, '1-2.2': 8})
        self.assertEqual(self.records[0]['action'], 'observed-own-live-auto-reattach')
        self.assertEqual(len(self.monitor.calls), 1)

    def test_fd_open_before_attach_is_waited_without_retry(self):
        self.owned = True
        self.assertFalse(self.poll())
        self.assertFalse(self.poll(7))
        self.assertFalse(self.pulses())
        self.monitor.attached = True
        self.assertTrue(self.poll(8))

    def test_usbfs_before_visible_owned_fd_is_waited(self):
        self.device['interfaces'] = [dict(driver='usbfs')]
        self.assertFalse(self.poll())
        self.assertFalse(self.poll(7))
        self.assertFalse(self.pulses())
        self.monitor.attached = self.owned = True
        self.assertTrue(self.poll(8))

    def test_attached_before_owned_fd_is_not_confirmation(self):
        self.monitor.attached = True
        self.assertFalse(self.poll())
        self.assertFalse(self.poll(7))
        self.assertEqual(self.addresses['1-2.1'], 7)
        self.assertFalse(self.pulses())
        self.owned = True
        self.assertTrue(self.poll(8))

    def test_retry_is_single_pulse_after_settle_not_confirmation(self):
        self.assertFalse(self.poll())
        self.assertFalse(self.poll(5.9))
        self.assertFalse(self.pulses())
        self.assertFalse(self.poll(6))
        self.assertFalse(self.poll(10))
        self.assertEqual(len(self.pulses()), 1)
        self.assertEqual(self.addresses['1-2.1'], 7)
        self.monitor.attached = self.owned = True
        self.assertTrue(self.poll(11))

    def test_concurrent_opener_wins_before_retry_setter(self):
        self.poll()
        def open_between_observation_and_setter():
            self.monitor.attached = self.owned = True
        self.monitor.on_set = open_between_observation_and_setter
        self.assertFalse(self.poll(6))
        self.assertTrue(self.poll(7))
        self.assertEqual(len(self.pulses()), 1)

    def test_unknown_usbfs_binding_never_pulses_and_expires(self):
        self.device['interfaces'] = [dict(driver='usbfs')]
        self.poll()
        self.poll(6)
        with self.assertRaisesRegex(ValueError, 'ownership did not settle'):
            self.poll(20)
        self.assertFalse(self.pulses())
        self.assertEqual(self.addresses['1-2.1'], 7)
        self.assertEqual(self.records[0]['action'], 'ownership-deadline')

    def test_foreign_driver_rejected_before_qmp(self):
        self.device['interfaces'] = [dict(driver='other_driver')]
        with self.assertRaisesRegex(ValueError, 'no detach'):
            self.poll()
        self.assertFalse(self.monitor.calls)
        self.assertEqual(self.records[0]['action'], 'foreign-driver-rejected')

    def test_permission_wait_has_deadline_without_qmp(self):
        self.device['writable'] = False
        self.poll()
        self.poll(6)
        with self.assertRaisesRegex(ValueError, 'permissions did not settle'):
            self.poll(20)
        self.assertFalse(self.monitor.calls)
        self.assertEqual(self.records[0]['action'], 'permission-deadline')

    def test_permission_settlement_can_then_accept_owned_device(self):
        self.device['writable'] = False
        self.poll()
        self.device['writable'] = True
        self.monitor.attached = self.owned = True
        self.assertTrue(self.poll(4))

    def test_second_reenumeration_gets_new_retry_budget_and_deadline(self):
        self.poll()
        self.poll(6)
        self.device['address'] = 10
        self.device['node'] = '/dev/bus/usb/001/010'
        self.poll(19)
        self.poll(20)
        self.assertEqual(len(self.pulses()), 1)
        self.poll(25)
        self.assertEqual(len(self.pulses()), 2)
        self.assertEqual(len(self.records), 2)

    def test_missing_device_clears_pending_without_mutating_survivor(self):
        self.poll()
        self.assertFalse(self.watcher.poll(0, '1-2.1', None, 123, self.monitor, 20))
        self.assertFalse(self.watcher.pending)
        self.assertEqual(self.addresses['1-2.2'], 8)
        self.poll(21)
        self.assertEqual(len(self.records), 2)

    def test_unchanged_device_never_queries_or_mutates(self):
        self.device['address'] = 7
        self.assertFalse(self.poll())
        self.assertFalse(self.records)
        self.assertFalse(self.monitor.calls)

    def test_wrong_topology_rejected(self):
        for field, value in [('bus', 2), ('path', '1-2.2')]:
            with self.subTest(field=field):
                d = copy.deepcopy(self.device)
                d[field] = value
                with self.assertRaisesRegex(ValueError, 'topology changed'):
                    self.watcher.poll(0, '1-2.1', d, 123, self.monitor, 0)
        self.assertFalse(self.monitor.calls)

    def test_malformed_attached_and_backwards_clock_rejected(self):
        self.monitor.attached = 1
        with self.assertRaisesRegex(ValueError, 'attached state'):
            self.poll(1)
        self.monitor.attached = False
        with self.assertRaisesRegex(ValueError, 'clock moved backwards'):
            self.poll(0)

    def test_invalid_deadline_configuration_rejected(self):
        for settle, timeout in [(0, 20), (6, 6), (20, 6)]:
            with self.assertRaises(ValueError):
                lab.ReattachmentWatcher({}, [], settle_seconds=settle, timeout_seconds=timeout)


if __name__ == '__main__':
    unittest.main()
