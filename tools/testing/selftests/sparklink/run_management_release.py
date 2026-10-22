#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual Host predicates/core release decision with dependency fixtures."""
from security_relay_fixture import write_fixture
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile

from run_connection_tx import function


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    names = ['sle_host.rs', 'sparklink_core.rs', 'sle_management.rs', 'sle_runtime_address.rs',
             'sle_discovery_operation.rs', 'sle_command_queue.rs', 'sle_command_plan.rs', 'sle_dli.rs', 'sle_mgmt.rs', 'sle_link_observation.rs', 'sle_connection_operation.rs', 'sle_grant.rs','sle_security_relay.rs','sle_security_relay_state.rs','sle_link_command.rs']
    names += ['sle_security_relay.rs','sle_security_relay_state.rs']
    inputs = {n: (net/n).read_bytes() for n in names}
    revoke = function(inputs['sparklink_core.rs'].decode(), 'revoke_management')
    marker = '        {\n            let mut host = owner.host.lock();'
    start = revoke.index(marker)
    brace = revoke.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (revoke[end] == '{') - (revoke[end] == '}')
        end += 1
    early = "owner.host.lock().revoke_connections();"
    assert early in revoke[:start]
    decision = early + "\n" + revoke[start:end]
    assert 'gate.settled(0)' in decision and 'policy_untouched()' in decision
    acquire = function(inputs['sparklink_core.rs'].decode(), 'ioctl_management')
    marker = '        {\n            // Copyout may sleep'
    start = acquire.index(marker); brace = acquire.index('{', start); end, depth = brace+1, 1
    while depth:
        depth += (acquire[end]=='{')-(acquire[end]=='}'); end += 1
    commit = acquire[start:end]
    methods = '\n'.join(function(inputs['sle_host.rs'].decode(), n) for n in
                        ['link_command_current','link_snapshot','address_metadata_valid','validate_relay','admits_data','validate_connection_cleanup','revoke_connections','observe_link','links_clear_for_management','quiet', 'resume_management', 'policy_untouched', 'query_policy_untouched', 'policy_unsubmitted',
                         'cancel_unsubmitted_policy', 'controller_status', 'discovery_radio',
                         'current_recipe', 'can_send', 'retained_revocation',
                         'retained_revocation_ready', 'next', 'cancel_recipe_progress', 'enqueue_recipe_until', 'enqueue_recipe',
                         'begin_revoke', 'revocation_result', 'latch_fault', 'fail'])
    fixture = (here/'diagnostic/management_release_fixture.rs').read_text()
    fixture = fixture.replace('// @@HOST_METHODS@@', methods.replace('Error::from_errno(', 'error_from_errno(')).replace('// @@CORE_DECISION@@', decision.replace('Error::from_errno(', 'error_from_errno(')).replace('// @@CORE_COMMIT@@', commit)
    host = inputs['sle_host.rs'].decode()
    start = host.index('struct InFlight {')
    end = host.index('\n}', start)+2
    fixture = fixture.replace('// @@IN_FLIGHT@@', host[start:end])
    variants = '\n'.join(re.search(r'(?m)^    '+name+r' = 0x[0-9A-F]+,', inputs['sle_dli.rs'].decode()).group() for name in ['EnableBroadcast', 'EnableScan', 'SetScanParam', 'CreateConnection'])
    fixture = fixture.replace('// @@OPCODES@@', variants)
    timeout = re.search(r'(?m)^pub\(crate\) const CMD_TIMEOUT_MS: u32 = [0-9_]+;', inputs['sle_mgmt.rs'].decode()).group()
    fixture = fixture.replace('// @@TIMEOUT@@', timeout)
    with tempfile.TemporaryDirectory(prefix='sparklink-management-release-') as tmp:
        tmp = Path(tmp); write_fixture(here.parents[3], tmp)
        for n in names[2:]:
            (tmp/n).write_bytes(inputs[n])
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp/'fixture.rs'), '-o', str(tmp/'test')], check=True)
        result = subprocess.check_output([str(tmp/'test'), '--test-threads=1'], text=True)
        print(result)
    assert all((net/n).read_bytes() == b for n, b in inputs.items())
    record = {'status': 'MANAGEMENT_RELEASE_SOURCE_BOUNDARIES_PASS', 'rust_tests': int(re.search(r'test result: ok\. (\d+) passed; 0 failed;', result)[1]),
              'scope': 'actual Host predicates/TX selection/InFlight/domain revocation and core fast-release block; source queue/operation/lease modules and opcode/timeout constants; locks, clock scaling, dependency error adapters and surrounding transport dependencies are fixtures',
              'live_ioctl_acceptance': False, 'fd_close_acceptance': False,
              'automatic_fault_recovery_acceptance': False, 'physical_acceptance': False,
              'sources': {n: hashlib.sha256(b).hexdigest() for n, b in inputs.items()}}
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
