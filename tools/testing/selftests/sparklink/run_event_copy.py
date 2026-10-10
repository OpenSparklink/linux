#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual event module and read_iter with copy/locking dependency fixtures.

This is not a live VFS fault, lockdep, broadcast routing or RF qualification.
"""
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
    inputs = {name: (net / name).read_bytes()
              for name in ['sle_event.rs', 'sparklink_core.rs']}
    with tempfile.TemporaryDirectory(prefix='sparklink-event-copy-') as tmp:
        tmp = Path(tmp)
        (tmp / 'sle_event.rs').write_bytes(inputs['sle_event.rs'])
        source = (here / 'event-copy/fixture.rs').read_text()
        source = source.replace('// @@READ_ITER@@',
                                function(inputs['sparklink_core.rs'].decode(), 'read_iter'))
        (tmp / 'fixture.rs').write_text(source)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'),
                        '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    assert all((net / name).read_bytes() == data for name, data in inputs.items())
    record = {'status': 'EVENT_RECORD_COPY_BOUNDARY_PASS', 'rust_tests': 9,
              'scope': 'actual complete event module and read_iter; copy/lock dependencies are fixtures',
              'live_vfs_fault_acceptance': False, 'physical_acceptance': False,
              'sources': {name: hashlib.sha256(data).hexdigest()
                          for name, data in inputs.items()},
              'remaining': ['Legacy DLI_POLL_EVENT consumer migration/fault retention',
                            'Live usercopy faults, removal wakeup and complete event ownership gates']}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
