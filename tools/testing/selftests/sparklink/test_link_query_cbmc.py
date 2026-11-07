#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verdict-parser fixtures only; does not run or qualify CBMC/WS73."""
import copy
import json
import unittest
from run_link_query_cbmc import PROPERTIES, audit


def fixture():
    return [{'result': [dict(property='main.assertion.'+str(n), description=name, status='SUCCESS')
                        for n, name in enumerate(sorted(PROPERTIES))]}, {'cProverStatus': 'success'}]


class Verdict(unittest.TestCase):
    def test_complete_properties_required(self):
        self.assertTrue(audit(json.dumps(fixture()), b'', 0))
        for case in ('missing', 'duplicate', 'unknown', 'failure', 'unwind', 'warning', 'unsupported', 'no-terminal', 'wrong-terminal', 'empty'):
            value = fixture()
            if case == 'missing': value[0]['result'].pop()
            elif case == 'duplicate': value[0]['result'].append(copy.deepcopy(value[0]['result'][0]))
            elif case in ('unknown', 'failure'): value[0]['result'][0]['status'] = case.upper()
            elif case == 'unwind': value[0]['result'].append(dict(property='memcmp.unwind.0', description='unwinding assertion', status='FAILURE'))
            elif case == 'warning': value.append(dict(messageType='WARNING', messageText='warning'))
            elif case == 'unsupported': value.append(dict(messageType='STATUS-MESSAGE', messageText='Unsupported operation'))
            elif case == 'no-terminal': value.pop()
            elif case == 'wrong-terminal': value[-1]['cProverStatus'] = 'failure'
            else: value = []
            with self.subTest(case=case): self.assertFalse(audit(json.dumps(value), b'', 0))
        self.assertFalse(audit(json.dumps(fixture()), b'warning', 0))
        self.assertFalse(audit(json.dumps(fixture()), b'', 10))
        for raw in ('{', '{}', '[null]', '[{"result":[null]}]'):
            self.assertFalse(audit(raw, b'', 0))

    def test_mutant_requires_exact_property_counterexample_and_exit(self):
        value = fixture()
        failed = next(p for p in value[0]['result'] if p['description'] == 'LQI_LE16_handle')
        failed.update(status='FAILURE', trace=[dict(stepType='assignment')])
        value[-1]['cProverStatus'] = 'failure'
        self.assertTrue(audit(json.dumps(value), b'', 10, 'LQI_LE16_handle'))
        self.assertFalse(audit(json.dumps(value), b'', 0, 'LQI_LE16_handle'))
        self.assertFalse(audit(json.dumps(value), b'', 10, 'LQI_failure_atomic'))
        failed['trace'] = []
        self.assertFalse(audit(json.dumps(value), b'', 10, 'LQI_LE16_handle'))


if __name__ == '__main__':
    unittest.main()
