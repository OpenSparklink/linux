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
              ['sle_mgmt.rs', 'sle_uapi.rs', 'sparklink_core.rs']}
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
    assert all((net / n).read_bytes() == data for n, data in inputs.items())
    record = {'status': 'DIAGNOSTIC_RESULT_BOUNDARY_PASS', 'rust_tests': 10,
              'scope': 'actual pending module and result handler; clock/lease/lock/usercopy/allocation dependencies are fixtures',
              'live_vfs_acceptance': False, 'physical_acceptance': False,
              'sources': {n: hashlib.sha256(data).hexdigest() for n, data in inputs.items()},
              'remaining': ['Actual ioctl owner/CAP/usercopy/removal gates in qualified VM',
                            'Legacy DLI event callers and shared projection removal',
                            'Full request admission copyout/cancel/idempotency contract']}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
