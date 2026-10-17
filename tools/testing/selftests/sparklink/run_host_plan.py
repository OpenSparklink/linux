#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the actual queue/recipe tests with the actual relay dependency."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from security_relay_fixture import write_fixture


def run(binary=None, output=None):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    names = ['sle_command_plan.rs', 'sle_command_queue.rs',
             'sle_security_relay.rs', 'sle_security_relay_state.rs']
    sources = {n: (root / 'net/sparklink' / n).read_bytes() for n in names}
    with tempfile.TemporaryDirectory(prefix='sparklink-host-plan-') as directory:
        tmp = Path(directory)
        write_fixture(root, tmp)
        for n in names[:2]:
            (tmp / n).write_bytes(sources[n])
        source = (here / 'sparklink_host_plan_test.rs').read_text()
        source = source.replace('../../../../net/sparklink/', '')
        # Partial-source fixture only: unrelated relay methods are covered by
        # the production Host/relay runners, not the recipe tests below.
        source = source.replace('mod sle_command_queue;', '#[allow(dead_code)] mod sle_command_queue;')
        prefix = ('#[allow(dead_code)] #[path="sle_security_relay_state.rs"] mod sle_security_relay_state;\n'
                  '#[allow(dead_code)] mod sle_security_relay { include!("relay_owner_fixture.rs"); }\n')
        # Inner crate documentation must precede module items.
        insertion = source.index('#[path')
        source = source[:insertion] + prefix + source[insertion:]
        (tmp / 'fixture.rs').write_text(source)
        target = binary.resolve() if binary else tmp / 'test'
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021',
                        '--test', '-D', 'warnings', str(tmp / 'fixture.rs'),
                        '-o', str(target)], check=True)
        if not binary:
            subprocess.run([str(target), '--test-threads=1'], check=True)
    assert all((root / 'net/sparklink' / n).read_bytes() == data for n, data in sources.items())
    record = {'status': 'COMPILED' if binary else 'HOST_PLAN_SOURCE_PASS',
              'scope': 'Actual recipe/queue with actual Command/relay state; C kref, lock, allocation and clock dependencies are fixtures; not live kernel or RF',
              'sources': {n: hashlib.sha256(data).hexdigest() for n, data in sources.items()},
              'dependency_fixture_sha256': hashlib.sha256((here / 'security_relay_fixture.py').read_bytes()).hexdigest()}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, help='Build only; selftests execute the binary separately')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    run(args.binary, args.output)
