#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic supervisor negative controls; no codec or hardware qualification."""
import copy
import importlib.util
from pathlib import Path
import unittest

path=Path(__file__).resolve().parents[1]/'run_ws73_codec_fuzz.py'
spec=importlib.util.spec_from_file_location('codec_fuzz',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
GOOD='#14\tDONE   cov: 260 ft: 417\nDone 14 runs in 0 second(s)\nstat::number_of_executed_units: 14\n'


class VerdictTests(unittest.TestCase):
    def test_complete_bounded_control(self):
        self.assertTrue(module.completed(GOOD,0))
    def test_missing_truncated_or_replaced_counts_fail(self):
        for text in ['',GOOD[:20],GOOD.replace('stat::number_of_executed_units: 14','stat::number_of_executed_units: 13'),GOOD.replace('DONE','INITED'),GOOD.replace('Done 14','Done 0')]:
            self.assertFalse(module.completed(text,0))
    def test_exit_and_timeout_are_not_pass(self):
        for code in [1,77,-11,'TIMEOUT']:self.assertFalse(module.completed(GOOD,code))
    def test_sanitizer_and_unsupported_even_with_masked_exit_fail(self):
        for text in ['ERROR: AddressSanitizer','runtime error: overflow','UndefinedBehaviorSanitizer:','LeakSanitizer has encountered a fatal error','unsupported instrumentation','libFuzzer: deadly signal']:
            self.assertFalse(module.completed(GOOD+text,0))
    def test_coverage_requires_every_actual_target(self):
        data={'data':[{'functions':[{'name':n,'count':1} for n in module.REQUIRED]}]}
        self.assertEqual(set(module.coverage_counts(data)),set(module.REQUIRED))
        for name in module.REQUIRED:
            d=copy.deepcopy(data);next(f for f in d['data'][0]['functions'] if f['name']==name)['count']=0
            with self.assertRaises(ValueError):module.coverage_counts(d)
        data['data'][0]['functions'].pop()
        with self.assertRaises(ValueError):module.coverage_counts(data)


if __name__=='__main__':unittest.main()
