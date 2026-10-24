#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Isolated historical PHY model; retired ioctl absence is a separate live VM gate."""
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
    paths = [here / 'retired-protocol-state/sle_phy.rs', net / 'sparklink_core.rs',
             here / 'phy-model/legacy_model.rs', here / 'phy-model/model_tests.rs']
    contents = {str(p): p.read_bytes() for p in paths}
    core = (net / 'sparklink_core.rs').read_text()
    assert 'pub(crate) phy:' not in core and 's.phy.' not in core
    assert 'start_encrypt()' not in core
    with tempfile.TemporaryDirectory(prefix='sparklink-phy-model-') as temp:
        tmp = Path(temp)
        (tmp / 'channel.rs').write_bytes(contents[str(here / 'retired-protocol-state/sle_phy.rs')])
        for name in ['legacy_model.rs', 'model_tests.rs']:
            (tmp / name).write_bytes(contents[str(here / 'phy-model' / name)])
        rustc = os.environ.get('RUSTC', 'rustc')
        subprocess.run([rustc, '--edition=2021', '--test', '-D', 'warnings',
                        str(tmp / 'model_tests.rs'), '-o', str(tmp / 'models')], check=True)
        subprocess.run([str(tmp / 'models')], check=True)
    assert all(p.read_bytes() == contents[str(p)] for p in paths)
    record = {'status': 'PHY_MODEL_ISOLATION_PASS', 'model_tests': 3,
              'actual_dispatch_tests': 0, 'retired_dispatch': 'run_virtual_vm.py 101 ENOTTY cases; no current PHY ioctl',
              'scope': 'historical local model only; current ENOTTY requires independent actual VM probe',
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
