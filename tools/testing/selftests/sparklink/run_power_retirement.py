#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Default PM rejection source boundary and exact historical model regression.

These are offline checks, not an implementation proof or hardware PM gate.
Actual root/ordinary ioctl/configfs rejection runs in run_virtual_vm.py.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    sources = [net/'sparklink_core.rs', net/'sle_configfs.rs',
               here/'retired-power/sle_power.rs', here/'retired-power/model_tests.rs']
    core, config = [p.read_text() for p in sources[:2]]
    assert 'mod sle_power;' not in core and 'PowerInner' not in core
    assert 's.power.' not in core and 'shared.power.' not in core
    assert 'sle_configfs::power_mode()' not in core
    assert 'POWER_MODE' not in config
    assert not (net/'sle_power.rs').exists()
    record = {'scope': 'offline source boundary and exact archived model; no hardware or comprehensive proof',
              'sources': {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}}
    with tempfile.TemporaryDirectory(prefix='sparklink-retired-power-') as temp:
        binary=Path(temp)/'tests'
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',
                        str(sources[3]),'-o',str(binary)],check=True)
        result=subprocess.run([str(binary)],text=True,capture_output=True,check=True)
        record.update(status='OFFLINE_RETIRED_POWER_BOUNDARY_PASS',historical_tests=3,stdout=result.stdout)
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    (output/'report.json').write_text(json.dumps(record,indent=2)+'\n')
    print(record['status'])


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True)
    run(parser.parse_args().output)
