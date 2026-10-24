#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual pending module/result handler with dependency fixtures; not live VFS/RF."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from run_connection_tx import function
from security_relay_fixture import write_fixture


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    executed=[];executed_names=[]
    def execute(binary):
        text=subprocess.check_output([str(binary),'--test-threads=1'],text=True)
        rows=re.findall(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;',text)
        assert len(rows)==1 and int(rows[0])>0,'complete default test harness result required'
        names=re.findall(r'(?m)^test (\S+) \.\.\. ok$',text)
        assert len(names)==int(rows[0]),'all successful case identities required'
        executed.append(int(rows[0]));executed_names.append(names);print(text)
    inputs = {name: (net / name).read_bytes() for name in
              ['sle_mgmt.rs', 'sle_runtime_address.rs', 'sle_link_command.rs', 'sle_uapi.rs', 'sparklink_core.rs', 'sle_host.rs', 'sle_command_queue.rs', 'sle_command_plan.rs', 'sle_workers.rs', 'sle_connection_operation.rs', 'sle_link_observation.rs', 'sle_security_relay.rs', 'sle_security_relay_state.rs']}
    uapi = inputs['sle_uapi.rs'].decode()
    declaration = uapi[uapi.index('/// Owner-private bounded diagnostic result;'):
                       uapi.index('unsafe impl FromBytes for SleDiagnosticResult')]
    declaration = declaration[:declaration.rfind('// SAFETY:')]
    handler = function(inputs['sparklink_core.rs'].decode(), 'ioctl_diagnostic_result')
    with tempfile.TemporaryDirectory(prefix='sparklink-diagnostic-result-') as tmp:
        tmp = Path(tmp)
        for dependency in ["sle_link_command.rs", "sle_connection_operation.rs"]:
            (tmp / dependency).write_bytes(inputs[dependency])
        (tmp / 'sle_mgmt.rs').write_bytes(inputs['sle_mgmt.rs'] + b'\n' +
                                        (here / 'diagnostic/pending_tests.rs').read_bytes())
        fixture = (here / 'diagnostic/fixture.rs').read_text()
        fixture = fixture.replace('// @@RESULT_STRUCT@@', declaration)
        fixture = fixture.replace('// @@RESULT_HANDLER@@', handler)
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        execute(tmp/'test')
    with tempfile.TemporaryDirectory(prefix='sparklink-diagnostic-admission-') as tmp:
        tmp = Path(tmp)
        for dependency in ["sle_link_command.rs", "sle_connection_operation.rs"]:
            (tmp / dependency).write_bytes(inputs[dependency])
        write_fixture(here.parents[3], tmp)
        for name in ['sle_mgmt.rs', 'sle_command_queue.rs', 'sle_command_plan.rs']:
            (tmp / name).write_bytes(inputs[name])
        declaration = uapi[uapi.index('/// Idempotent metadata diagnostic admission/cancel;'):
                           uapi.index('unsafe impl FromBytes for SleDiagnosticSubmit')]
        declaration = declaration[:declaration.rfind('// SAFETY:')]
        fixture = (here / 'diagnostic/admission_fixture.rs').read_text()
        for marker, body in {
            '// @@SUBMIT_STRUCT@@': declaration,
            '// @@PARAMETERS@@': function(inputs['sparklink_core.rs'].decode(), 'diagnostic_parameters'),
            '// @@SUBMIT_HANDLER@@': function(inputs['sparklink_core.rs'].decode(), 'ioctl_diagnostic_submit'),
            '// @@ENQUEUE@@': function(inputs['sle_host.rs'].decode(), 'enqueue_diagnostic'),
            '// @@CANCEL@@': function(inputs['sle_host.rs'].decode(), 'cancel_diagnostic'),
        }.items():
            fixture = fixture.replace(marker, body)
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        execute(tmp/'test')
    with tempfile.TemporaryDirectory(prefix='sparklink-host-deadline-') as tmp:
        tmp = Path(tmp)
        for dependency in ["sle_link_command.rs", "sle_connection_operation.rs"]:
            (tmp / dependency).write_bytes(inputs[dependency])
        write_fixture(here.parents[3], tmp)
        for name in ['sle_runtime_address.rs','sle_command_queue.rs', 'sle_command_plan.rs', 'sle_connection_operation.rs', 'sle_link_observation.rs']:
            (tmp / name).write_bytes(inputs[name])
        fixture = (here / 'diagnostic/host_deadline_fixture.rs').read_text()
        fixture = fixture.replace('// @@HOST_DEADLINE@@', function(inputs['sle_host.rs'].decode(), 'next_deadline')+'\n'+function(inputs['sle_host.rs'].decode(),'links_clear_for_management'))
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        execute(tmp/'test')
    assert all((net / n).read_bytes() == data for n, data in inputs.items())
    record = {'status': 'DIAGNOSTIC_RESULT_BOUNDARY_PASS', 'rust_tests': sum(executed), 'executed_phase_tests': executed, 'executed_case_names': executed_names, 'result_tests': executed[0], 'admission_tests': executed[1], 'host_deadline_tests': executed[2], 'connection_dependency_tests': sum(n.startswith('sle_connection_operation::')for n in executed_names[2]), 'link_dependency_tests': sum(n.startswith('sle_link_observation::')for n in executed_names[2]),
              'scope': 'actual pending/queue modules, submit/result handlers and Host enqueue/cancel bodies; clock/lease/lock/usercopy/allocation dependencies are fixtures. Result fixture has no physical Host; admission expiry adapter rejects expired on-wire or fault/pending compositions. Coupled Runtime/Host expiry is tested separately with actual Host in run_native_connection_host, not by these queued-only adapters.',
              'live_vfs_acceptance': False, 'physical_acceptance': False,
              'sources': {n: hashlib.sha256(data).hexdigest() for n, data in inputs.items()},
              'relay_dependency_fixture_sha256': hashlib.sha256((here / 'security_relay_fixture.py').read_bytes()).hexdigest(),
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
