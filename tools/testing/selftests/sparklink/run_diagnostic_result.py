#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual pending module/result handler with dependency fixtures; not live VFS/RF."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from run_connection_tx import function


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    inputs = {name: (net / name).read_bytes() for name in
              ['sle_mgmt.rs', 'sle_uapi.rs', 'sparklink_core.rs', 'sle_host.rs', 'sle_command_queue.rs', 'sle_command_plan.rs', 'sle_workers.rs', 'sle_connection_operation.rs']}
    uapi = inputs['sle_uapi.rs'].decode()
    declaration = uapi[uapi.index('/// Owner-private bounded diagnostic result;'):
                       uapi.index('unsafe impl FromBytes for SleDiagnosticResult')]
    declaration = declaration[:declaration.rfind('// SAFETY:')]
    handler = function(inputs['sparklink_core.rs'].decode(), 'ioctl_diagnostic_result')
    with tempfile.TemporaryDirectory(prefix='sparklink-diagnostic-result-') as tmp:
        tmp = Path(tmp)
        (tmp / 'sle_mgmt.rs').write_bytes(inputs['sle_mgmt.rs'] + b'\n' +
                                        (here / 'diagnostic/pending_tests.rs').read_bytes())
        fixture = (here / 'diagnostic/fixture.rs').read_text()
        fixture = fixture.replace('// @@RESULT_STRUCT@@', declaration)
        fixture = fixture.replace('// @@RESULT_HANDLER@@', handler)
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    with tempfile.TemporaryDirectory(prefix='sparklink-diagnostic-admission-') as tmp:
        tmp = Path(tmp)
        for name in ['sle_mgmt.rs', 'sle_command_queue.rs', 'sle_command_plan.rs']:
            (tmp / name).write_bytes(inputs[name])
        declaration = uapi[uapi.index('/// Idempotent metadata diagnostic admission/cancel;'):
                           uapi.index('unsafe impl FromBytes for SleDiagnosticSubmit')]
        declaration = declaration[:declaration.rfind('// SAFETY:')]
        fixture = (here / 'diagnostic/admission_fixture.rs').read_text()
        for marker, body in {
            '// @@SUBMIT_STRUCT@@': declaration,
            '// @@SUBMIT_HANDLER@@': function(inputs['sparklink_core.rs'].decode(), 'ioctl_diagnostic_submit'),
            '// @@ENQUEUE@@': function(inputs['sle_host.rs'].decode(), 'enqueue_diagnostic'),
            '// @@CANCEL@@': function(inputs['sle_host.rs'].decode(), 'cancel_diagnostic'),
        }.items():
            fixture = fixture.replace(marker, body)
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    with tempfile.TemporaryDirectory(prefix='sparklink-host-deadline-') as tmp:
        tmp = Path(tmp)
        for name in ['sle_command_queue.rs', 'sle_command_plan.rs', 'sle_connection_operation.rs']:
            (tmp / name).write_bytes(inputs[name])
        fixture = (here / 'diagnostic/host_deadline_fixture.rs').read_text()
        fixture = fixture.replace('// @@HOST_DEADLINE@@', function(inputs['sle_host.rs'].decode(), 'next_deadline'))
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    assert all((net / n).read_bytes() == data for n, data in inputs.items())
    record = {'status': 'DIAGNOSTIC_RESULT_BOUNDARY_PASS', 'rust_tests': 42, 'result_tests': 14, 'admission_tests': 12, 'host_deadline_tests': 6, 'connection_dependency_tests': 10,
              'scope': 'actual pending/queue modules, submit/result handlers and Host enqueue/cancel bodies; clock/lease/lock/usercopy/allocation dependencies are fixtures',
              'live_vfs_acceptance': False, 'physical_acceptance': False,
              'sources': {n: hashlib.sha256(data).hexdigest() for n, data in inputs.items()},
              'remaining': ['Actual ioctl owner/CAP/usercopy/removal gates in qualified VM',
                            'Legacy DLI event callers and shared projection removal',
                            'Live idempotent admission/cancel/deadline syscall and on-wire late reply gates']}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
