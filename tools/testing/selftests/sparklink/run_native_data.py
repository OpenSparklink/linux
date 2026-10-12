#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual native ACB bodies and budget/queue; explicit USB/locking fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_connection_tx import function


def run(output):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    net = root / 'net/sparklink'
    files = [net / n for n in ['sle_native.rs', 'sle_link_observation.rs',
                             'sle_data_credit.rs', 'sle_native_data.rs', 'sle_host.rs', 'sle_sessions.rs', 'sle_grant.rs']]
    files.append(here / 'native-data/fixture.rs')
    originals = {p: p.read_bytes() for p in files}
    fixture = originals[files[-1]].decode()
    fixture = fixture.replace('// @@ADMITTED@@', function((net/'sle_host.rs').read_text(), 'admits_data'))
    # The existing balanced-body extractor accepts Rust fn signatures, not
    # extern ABI spelling. Only normalize the signature; preserve whole bodies.
    source = re.sub(r'unsafe extern "C" fn (\w+)', r'unsafe fn \1', originals[files[0]].decode())
    start = source.index('struct NativeTxTicket {')
    end = source.index('\n}', start) + 2
    fixture = fixture.replace('// @@TICKET@@', source[start:end])
    for marker, name in [('RECEIVE', 'sparklink_native_receive_rust'),
                         ('SEND', 'sparklink_native_acb_send_rust'),
                         ('SEND_COMMON', 'native_acb_send'),
                         ('GUARDED_SEND', 'sparklink_native_acb_send_guarded_rust'),
                         ('COMMIT', 'sparklink_native_tx_commit_rust'),
                         ('TAKE', 'sparklink_native_acb_take_rust')]:
        fixture = fixture.replace('// @@' + marker + '@@', function(source, name))
    with tempfile.TemporaryDirectory(prefix='sparklink-native-data-') as directory:
        tmp = Path(directory)
        (tmp / 'fixture.rs').write_text(fixture)
        for p in files[1:-1]:
            (tmp / p.name).write_bytes(originals[p])
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        result = subprocess.check_output([str(tmp / 'test'), '--test-threads=1'], text=True)
        print(result)
    assert all(p.read_bytes() == data for p, data in originals.items())
    count = re.search(r'test result: ok\. (\d+) passed; 0 failed;', result)
    assert count
    record = {'status': 'NATIVE_ACB_PRODUCTION_SOURCE_BOUNDARIES_PASS', 'tests': int(count[1]),
              'scope': 'actual ingress/send/take and credit/queue modules; allocation, locks, owner registry and USB dependencies are fixtures',
              'real_data_acceptance': False, 'socket_acceptance': False,
              'sources': {str(p.relative_to(root)): hashlib.sha256(b).hexdigest() for p, b in originals.items()}}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
