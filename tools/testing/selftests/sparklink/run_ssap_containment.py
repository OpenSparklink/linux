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


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    paths = [here / 'ssap/legacy_staging.rs', net / 'sparklink_core.rs', net / 'sle_workers.rs',
             here / 'retired-protocol-state/sle_conn.rs', net / 'sle_uapi.rs', net / 'sle_authorization.rs',
             net.parents[1] / 'include/uapi/linux/sparklink_ioctl.h']
    inputs = {p.name: p.read_bytes() for p in paths}
    fixture = here / 'ssap'
    # Business model and codec are historical fixtures, never a production Engine.
    for name in ('sparklink_core.rs', 'sle_workers.rs', 'sle_conn.rs', 'sle_uapi.rs',
                 'sle_authorization.rs', 'sparklink_ioctl.h'):
        text = inputs[name].decode()
        for retired in ('SL_IOCTL_SSAP_', 'SsapInner', 'SsapSession', 'RemoteServiceDb',
                        'ssap_info_exchanged', 'ssap_version_major', 'ssap_reliable_mode'):
            assert retired not in text, f'{name}: retired production dependency {retired}'
    assert 'mod sle_ssap;' not in inputs['sparklink_core.rs'].decode()
    with tempfile.TemporaryDirectory(prefix='sparklink-ssap-') as tmp:
        tmp = Path(tmp)
        (tmp / 'sle_ssap.rs').write_bytes(inputs['legacy_staging.rs'] + b'\n' + (fixture / 'regression.rs').read_bytes())
        (tmp / 'legacy_codec.rs').write_bytes((fixture / 'legacy_codec.rs').read_bytes() + b'\n' + (fixture / 'codec_regression.rs').read_bytes())
        code = (fixture / 'kernel_fixture.rs').read_text()
        code += '#[path="sle_ssap.rs"] pub mod sle_ssap;\n'
        code += '#[path="legacy_codec.rs"] mod legacy_codec;\n'
        (tmp / 'fixture.rs').write_text(code)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings', str(tmp / 'fixture.rs'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test'), '--test-threads=1'], check=True)
    for p in paths:
        assert p.read_bytes() == inputs[p.name], 'production input changed during tests'
    record = {'status': 'SSAP_LEGACY_CONTAINMENT_PASS', 'rust_tests': 8, 'production_dependency_audit': 'PASS',
              'retired_ioctl_syscall_check': 'separate ssap_removed_uapi_test in VM; not asserted by this runner',
              'scope': 'test-only historical staging/session and codec with allocator fixture; former rejection tests replaced by removed API audit; no production service DB or wire Engine',
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
