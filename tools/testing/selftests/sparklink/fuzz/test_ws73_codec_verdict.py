#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic supervisor negative controls; no codec or hardware qualification."""
import copy
import importlib.util
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

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


class MetadataSupervisionTests(unittest.TestCase):
    """Actual supervisor/process groups; fake Git is an explicit failure fixture."""

    def run_git_failure(self, body):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        executable = root/'git'
        output = root/'result'
        executable.write_text('#!'+sys.executable+'\n'+body)
        executable.chmod(0o755)
        args = argparse.Namespace(output=output, contract='ws73', runs=1000, seed=730111)
        with patch.dict(os.environ, {'PATH':str(root)+os.pathsep+os.environ['PATH']}), \
             patch.object(module, 'METADATA_TIMEOUT_SECONDS', 0.2):
            started = time.monotonic()
            self.assertEqual(module.run(args), 1)
            self.assertLess(time.monotonic()-started, 5)
        report = json.loads((output/'report.json').read_text())
        self.assertFalse(report['accepted_exploration'])
        self.assertFalse(report['proof'])
        self.assertFalse(report['physical_acceptance'])
        self.assertEqual(report['status'], 'FAILED_OR_UNVERIFIED')
        self.assertTrue(report['completed'])
        self.assertNotIn('compile', [p['name'] for p in report['phases']])
        return output, report

    def test_metadata_error_preserves_initial_receipt_and_stderr(self):
        output, report = self.run_git_failure(
            'import sys\n'
            'print("explicit metadata failure",file=sys.stderr);sys.exit(19)\n')
        self.assertEqual(report['phases'][0]['exit'], 19)
        self.assertIn('explicit metadata failure', (output/'source-commit.log').read_text())
        self.assertIsNone(report['source_commit'])

    def test_status_timeout_reaps_inherited_pipe_child_and_keeps_receipt(self):
        # This process has its own session. Its child deliberately inherits the
        # output pipe that plain subprocess.run(timeout=...) may fail to drain.
        output, report = self.run_git_failure(
            'import json,pathlib,subprocess,sys,time\n'
            'if sys.argv[1]=="rev-parse": print("a"*40);sys.exit(0)\n'
            'p=pathlib.Path(__file__).parent/"result/report.json"\n'
            'r=json.loads(p.read_text());assert not r["accepted_exploration"]\n'
            'assert r["phases"][-1]["name"]=="source-worktree"\n'
            'child=subprocess.Popen([sys.executable,"-c","import time;time.sleep(30)"])\n'
            'print("child_pid="+str(child.pid),flush=True);time.sleep(30)\n')
        self.assertEqual(report['phases'][-1]['exit'], 'TIMEOUT')
        self.assertEqual(report['source_commit'], 'a'*40)
        self.assertIsNone(report['source_worktree_status'])
        child = int((output/'source-worktree.log').read_text().split('child_pid=')[1].strip())
        stat = Path('/proc')/str(child)/'stat'
        if stat.exists():
            self.assertEqual(stat.read_text().rsplit(')', 1)[1].split()[0], 'Z')


if __name__=='__main__':unittest.main()
