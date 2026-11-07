#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual atomic native ingress/model bodies with explicit dependency fixtures."""
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
    here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
    paths=[net/'sle_native.rs',net/'sle_link_observation.rs',here/'diagnostic/link_ingress_fixture.rs']
    original={p:p.read_bytes() for p in paths}
    fixture=original[paths[2]].decode().replace('// @@INGRESS@@',function(original[paths[0]].decode(),'publish_native_event'))
    with tempfile.TemporaryDirectory(prefix='sparklink-link-ingress-') as tmp:
        tmp=Path(tmp);(tmp/'fixture.rs').write_text(fixture);(tmp/'sle_link_observation.rs').write_bytes(original[paths[1]])
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(tmp/'fixture.rs'),'-o',str(tmp/'test')],check=True)
        result=subprocess.check_output([str(tmp/'test'),'--test-threads=1'],text=True);print(result)
    assert all(p.read_bytes()==b for p,b in original.items())
    count=re.search(r'test result: ok\. (\d+) passed; 0 failed;',result);assert count
    record={'status':'NATIVE_LINK_OBSERVATION_SOURCE_BOUNDARIES_PASS','rust_tests':int(count[1]),
        'scope':'actual native ingress and per-registration observation model; IRQ locks/owner lookup/log/notifications dependency fixtures, not running kernel or RF',
        'live_kernel_acceptance':False,'connection_rf_acceptance':False,'automatic_recovery_acceptance':False,
        'sources':{str(p.relative_to(here.parents[3])):hashlib.sha256(b).hexdigest() for p,b in original.items()}}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
