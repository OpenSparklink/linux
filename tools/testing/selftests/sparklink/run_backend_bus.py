#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual retained Backend metadata projection and provenance conversion."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from run_usb_discovery import block
from run_connection_tx import function


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3]/'net/sparklink'
    sources = {n:(net/n).read_text() for n in ['sle_native.rs','sle_dli.rs']}
    fixture = (here/'backend_bus_fixture.rs').read_text()
    dli=sources['sle_dli.rs']; native=sources['sle_native.rs']
    fixture=fixture.replace('// @@BUS_ENUM@@','#[repr(u8)]\n#[derive(Copy,Clone,Debug,PartialEq,Eq)]\n'+block(dli,dli.index('pub enum SleBus {')))
    fixture=fixture.replace('// @@INFO_STRUCT@@',block(dli,dli.index('pub struct SleControllerInfo {')))
    fixture=fixture.replace('// @@NATIVE_INFO@@','#[derive(Clone,Copy)]\n'+block(native,native.index('pub(crate) struct NativeInfo {')))
    fixture=fixture.replace('// @@PROJECTION@@',function(native[native.index('impl SleController for NativeController'):],'info'))
    fixture=fixture.replace('// @@CONVERSION@@',function(native,'backend_bus'))
    with tempfile.TemporaryDirectory(prefix='sparklink-backend-bus-') as tmp:
        p=Path(tmp)/'actual.rs';p.write_text(fixture);exe=Path(tmp)/'test'
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
    record=dict(status='ACTUAL_BACKEND_BUS_PROJECTION_PASS',tests=4,sources={n:hashlib.sha256(s.encode()).hexdigest() for n,s in sources.items()},scope='Actual production bus enum/conversion and NativeController.info; transport/errno/controller type dependencies are fixtures. Not registration lifetime/IRQ/module/Virtual or physical qualification.',physical_acceptance=False,whole_backend_complete=False)
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
