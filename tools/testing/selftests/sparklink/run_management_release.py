#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual Host predicates/core release decision with dependency fixtures."""
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
    names = ['sle_host.rs', 'sparklink_core.rs', 'sle_management.rs',
             'sle_discovery_operation.rs', 'sle_command_queue.rs', 'sle_command_plan.rs']
    inputs = {n: (net/n).read_bytes() for n in names}
    revoke = function(inputs['sparklink_core.rs'].decode(), 'revoke_management')
    marker = '        {\n            let host = owner.host.lock();'
    start = revoke.index(marker)
    brace = revoke.index('{', start)
    end, depth = brace + 1, 1
    while depth:
        depth += (revoke[end] == '{') - (revoke[end] == '}')
        end += 1
    decision = revoke[start:end]
    assert 'gate.settled(0)' in decision and 'policy_untouched()' in decision
    methods = '\n'.join(function(inputs['sle_host.rs'].decode(), n) for n in
                        ['quiet', 'policy_untouched', 'controller_status', 'discovery_radio'])
    fixture = (here/'diagnostic/management_release_fixture.rs').read_text()
    fixture = fixture.replace('// @@HOST_METHODS@@', methods).replace('// @@CORE_DECISION@@', decision)
    with tempfile.TemporaryDirectory(prefix='sparklink-management-release-') as tmp:
        tmp = Path(tmp)
        for n in names[2:]:
            (tmp/n).write_bytes(inputs[n])
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp/'fixture.rs'), '-o', str(tmp/'test')], check=True)
        subprocess.run([str(tmp/'test'), '--test-threads=1'], check=True)
    assert all((net/n).read_bytes() == b for n, b in inputs.items())
    record = {'status': 'MANAGEMENT_RELEASE_SOURCE_BOUNDARIES_PASS', 'rust_tests': 10,
              'scope': 'actual Host predicates and core fast-release block; source queue/operation/lease modules, lock and surrounding transport dependencies are fixtures',
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
