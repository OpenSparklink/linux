#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual unsupported PHY arm and isolated historical model; no hardware access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    paths = [net / 'sle_phy.rs', net / 'sparklink_core.rs',
             here / 'phy-model/legacy_model.rs', here / 'phy-model/model_tests.rs']
    contents = {str(p): p.read_bytes() for p in paths}
    core = (net / 'sparklink_core.rs').read_text()
    arm = re.search(r'(?m)^        SL_IOCTL_PHY_INFO\n.*?=> Err\([^\n]+\),',
                    core, re.S).group()
    names = re.findall(r'SL_IOCTL_PHY_[A-Z_]+', arm)
    assert len(names) == len(set(names)) == 8
    assert 'pub(crate) phy:' not in core and 's.phy.' not in core
    assert 'start_encrypt()' not in core
    with tempfile.TemporaryDirectory(prefix='sparklink-phy-model-') as temp:
        tmp = Path(temp)
        (tmp / 'channel.rs').write_bytes(contents[str(net / 'sle_phy.rs')])
        for name in ['legacy_model.rs', 'model_tests.rs']:
            (tmp / name).write_bytes(contents[str(here / 'phy-model' / name)])
        rustc = os.environ.get('RUSTC', 'rustc')
        subprocess.run([rustc, '--edition=2021', '--test', '-D', 'warnings',
                        str(tmp / 'model_tests.rs'), '-o', str(tmp / 'models')], check=True)
        subprocess.run([str(tmp / 'models')], check=True)
        # Compile the actual match arm unchanged. Identifier fixture numbers are
        # not ABI values; canonical cross-language ABI tests qualify numbering.
        constants = '\n'.join(f'const {n}:u32={i};' for i, n in enumerate(names))
        fixture = ('#[derive(Debug,PartialEq,Eq)] struct Error(i32);'
                   'impl Error { fn from_errno(n:i32)->Self {Self(n)} }'
                   'mod bindings {pub const EOPNOTSUPP:u32=95;}\n' + constants +
                   '\nfn dispatch(cmd:u32)->Result<isize,Error> {match cmd {\n' + arm +
                   '\n_=>Err(Error(-22)),}}\n#[test] fn actual_phy_rejection_arm() {' +
                   'for cmd in 0..8 {assert_eq!(dispatch(cmd),Err(Error(-95)));}' +
                   'assert_eq!(dispatch(8),Err(Error(-22)));}\n')
        (tmp / 'dispatch.rs').write_text(fixture)
        subprocess.run([rustc, '--edition=2021', '--test', '-D', 'warnings',
                        str(tmp / 'dispatch.rs'), '-o', str(tmp / 'dispatch')], check=True)
        subprocess.run([str(tmp / 'dispatch')], check=True)
    assert all(p.read_bytes() == contents[str(p)] for p in paths)
    record = {'status': 'PHY_MODEL_ISOLATION_PASS', 'model_tests': 3,
              'actual_dispatch_tests': 1, 'unsupported_commands': names,
              'scope': 'historical local model and actual rejection arm with dependency fixtures',
              'hardware_phy_acceptance': False, 'physical_acceptance': False,
              'sources': {str(p.relative_to(here.parents[3])):
                          hashlib.sha256(contents[str(p)]).hexdigest() for p in paths}}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
