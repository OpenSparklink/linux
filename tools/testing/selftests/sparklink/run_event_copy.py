#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual event/read_iter and legacy poll with dependency fixtures.

This is not a live VFS fault, lockdep, broadcast routing or RF qualification.
"""
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
    inputs = {name: (net / name).read_bytes()
              for name in ['sle_event.rs', 'sparklink_core.rs', 'sle_uapi.rs']}
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
    with tempfile.TemporaryDirectory(prefix='sparklink-legacy-dli-copy-') as tmp:
        tmp = Path(tmp)
        core = inputs['sparklink_core.rs'].decode()
        uapi = inputs['sle_uapi.rs'].decode()
        declaration = uapi[uapi.index('/// DLI event returned to userspace via DLI_POLL_EVENT ioctl.'):
                           uapi.index('/// DLI command sent to the controller via DLI_SEND_CMD ioctl.')]
        fixture = (here / 'event-copy/legacy_poll_fixture.rs').read_text()
        for marker, body in {
            '// @@WIRE@@': declaration,
            '// @@SIZE@@': re.search(r'(?m)^pub\(crate\) const DLI_RING_SIZE:.*$', core).group(),
            '// @@RING@@': '\n'.join(function(core, name) for name in ['push_dli_event',
                                                                        'peek_dli_event',
                                                                        'pop_dli_event']),
            '// @@HANDLER@@': function(core, 'ioctl_legacy_dli_poll'),
        }.items():
            fixture = fixture.replace(marker, body)
        (tmp / 'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'),
                        '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    assert all((net / name).read_bytes() == data for name, data in inputs.items())
    record = {'status': 'EVENT_RECORD_COPY_BOUNDARY_PASS', 'rust_tests': 15,
              'read_iter_tests': 9, 'legacy_dli_poll_tests': 6,
              'scope': 'actual complete event/read_iter, canonical legacy DLI event and ring/poll handler; copy/lock/controller-codec dependencies are fixtures',
              'live_vfs_fault_acceptance': False, 'physical_acceptance': False,
              'sources': {name: hashlib.sha256(data).hexdigest()
                          for name, data in inputs.items()},
              'remaining': ['Legacy DLI_POLL_EVENT consumer migration and shared projection deletion',
                            'Live legacy poll usercopy and qualified backend fallback gates',
                            'Removal wakeup, actual kernel concurrency/locks and complete event ownership gates']}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
