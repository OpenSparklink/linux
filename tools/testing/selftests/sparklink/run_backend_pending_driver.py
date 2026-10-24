#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual WS73 early-reservation helpers; mutex/Core RPC dependencies, no USB I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_usb_discovery import block


def run(output):
    here=Path(__file__).resolve().parent;root=here.parents[3];p=root/'drivers/sparklink/ws73/usb.c';source=p.read_text()
    names=['ws73_reserve_backend_locked','ws73_reserve_backend','ws73_pending_status','ws73_cancel_backend']
    bodies=[block(source,re.search(r'(?m)^static (?:void|int) '+n+r'\(',source).start()) for n in names]
    fixture=(here/'backend_pending_driver_fixture.c').read_text().replace('/* @@HELPERS@@ */','\n'.join(bodies))
    with tempfile.TemporaryDirectory(prefix='sparklink-ws73-pending-') as tmp:
        c=Path(tmp)/'actual.c';c.write_text(fixture);exe=Path(tmp)/'test'
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(root/'include'),str(c),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
    assert p.read_text()==source
    record=dict(status='ACTUAL_WS73_PENDING_HELPERS_PASS',cases=10,source_sha256=hashlib.sha256(source.encode()).hexdigest(),function_hashes={n:hashlib.sha256(b.encode()).hexdigest() for n,b in zip(names,bodies)},scope='Actual C reservation/status/cancel helpers; mutex and Core reserve/query/update dependencies only. Not probe/boot/USB callback/module/concurrent lifetime or physical acceptance.',physical_acceptance=False,kernel_refinement_proven=False)
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
