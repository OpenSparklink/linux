#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual legacy SSAP containment; historical codec is test-only, not conformance."""
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
    paths = [net / name for name in ['sle_ssap.rs', 'sparklink_core.rs', 'sle_workers.rs']]
    inputs = {p.name: p.read_bytes() for p in paths}
    fixture = here / 'ssap'
    # Copy the entire actual production module unchanged, then append child tests.
    with tempfile.TemporaryDirectory(prefix='sparklink-ssap-') as tmp:
        tmp = Path(tmp)
        (tmp / 'sle_ssap.rs').write_bytes(inputs['sle_ssap.rs'] + b'\n' + (fixture / 'regression.rs').read_bytes())
        (tmp / 'legacy_codec.rs').write_bytes((fixture / 'legacy_codec.rs').read_bytes() + b'\n' + (fixture / 'codec_regression.rs').read_bytes())
        code = (fixture / 'kernel_fixture.rs').read_text()
        code += '#[path="sle_ssap.rs"] mod sle_ssap;\n'
        code += '#[path="legacy_codec.rs"] mod legacy_codec;\n'
        code += 'use prelude::*; struct RuntimeContext;\n'
        code += function(inputs['sparklink_core.rs'].decode(), 'ioctl_ssap_remote')
        code += '\n#[test] fn actual_remote_ioctl_rejects_without_touching_user_pointer_or_context() { for cmd in 0..=255 { assert_eq!(ioctl_ssap_remote(&RuntimeContext, cmd, usize::MAX), Err(Error(-95))); } }\n'
        (tmp / 'fixture.rs').write_text(code)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    for p in paths:
        assert p.read_bytes() == inputs[p.name], 'production input changed during tests'
    record = {'status': 'SSAP_LEGACY_CONTAINMENT_PASS', 'rust_tests': 9,
              'scope': 'actual full local database/session module with allocation dependency fixture; one historical codec test',
              'standard_ssap_acceptance': False, 'physical_acceptance': False,
              'sources': {name: hashlib.sha256(data).hexdigest() for name, data in inputs.items()},
              'remaining': ['Userspace standard codec/fragment controls, permissions and authenticated per-peer database',
                            'PDU socket owner, deadline/budget/credit/commit semantics and real peer interoperability']}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
