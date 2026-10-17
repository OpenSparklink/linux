# SPDX-License-Identifier: GPL-2.0-only
import unittest
from run_runtime_lifecycle import assess_native
from test_native_runtime_lifecycle import EVENTS, event_log


def golden():
    return event_log(EVENTS.replace('NATIVE_EVENTS:', 'NATIVE_LINK_EVENTS:')
                     .replace('payload=278', 'kinds=4 lengths=32/11/4')
                     .replace('fault_retry=1 poll=1', 'fault_retry=1 poll=1 setup=1'))


class LinkEventVerdict(unittest.TestCase):
    def assess(self, log):
        return assess_native(log, 0, events=True, link_events=True)

    def test_complete(self):
        self.assertEqual(self.assess(golden()), [])

    def test_no_discovery_substitute(self):
        self.assertTrue(self.assess(event_log()))
        self.assertTrue(assess_native(golden(), 0, events=True))

    def test_attribution_and_body(self):
        for before, after in [('index=1 retained', 'index=0 retained'), ('kinds=4', 'kinds=2'),
                              ('lengths=32/11/4', 'lengths=11/4'), ('setup=1', 'setup=0'),
                              ('lost=8', 'lost=0'), ('fanout=2', 'fanout=1')]:
            with self.subTest(before=before):
                self.assertTrue(self.assess(golden().replace(before, after)))

    def test_missing_duplicate(self):
        line = next(x for x in golden().splitlines() if x.startswith('NATIVE_LINK_EVENTS:'))
        self.assertTrue(self.assess(golden().replace(line + '\n', '', 1)))
        self.assertTrue(self.assess(golden() + line + '\n'))

    def test_lifetime(self):
        for before, after in [('new=3', 'new=1'), ('generation=3 last=40', 'generation=1 last=40'),
                              ('NATIVE_EVENTS_REPLUG:', 'missing:'), ('NATIVE_REMOVE_FIRST', 'missing')]:
            self.assertTrue(self.assess(golden().replace(before, after)))


if __name__ == '__main__':
    unittest.main()
