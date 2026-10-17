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
    sources = {n:(net/n).read_text() for n in ['sle_native.rs','sle_dli.rs','sle_uapi.rs']}
    fixture = (here/'backend_bus_fixture.rs').read_text()
    dli=sources['sle_dli.rs']; native=sources['sle_native.rs']
    fixture=fixture.replace('// @@BUS_ENUM@@','#[repr(u8)]\n#[derive(Copy,Clone,Debug,PartialEq,Eq)]\n'+block(dli,dli.index('pub(crate) enum SleBus {')))
    fixture=fixture.replace('// @@INFO_STRUCT@@',block(dli,dli.index('pub(crate) struct SleControllerInfo {')))
    fixture=fixture.replace('// @@NATIVE_INFO@@','#[derive(Clone,Copy)]\n'+block(native,native.index('pub(crate) struct NativeInfo {')))
    fixture=fixture.replace('// @@PROJECTION@@',function(native[native.index('impl SleController for NativeController'):],'info'))
    fixture=fixture.replace('// @@CONVERSION@@',function(native,'backend_bus'))
    fixture=fixture.replace('// @@DEFAULT@@','impl Default for SleControllerInfo {'+function(dli[dli.index('impl Default for SleControllerInfo'):],'default')+'}')
    fixture=fixture.replace('// @@SNAPSHOT@@',block(sources['sle_uapi.rs'],sources['sle_uapi.rs'].index('pub(crate) struct SleControllerSnapshot {')))
    fixture=fixture.replace('// @@FILL_SNAPSHOT@@',function(native,'fill_snapshot').replace('super::sle_uapi::','crate::sle_uapi::'))
    with tempfile.TemporaryDirectory(prefix='sparklink-backend-bus-') as tmp:
        p=Path(tmp)/'actual.rs';p.write_text(fixture);exe=Path(tmp)/'test'
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p),'-o',str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
    historical = (here/'retired-dli-metadata/legacy_metadata.rs').read_text()
    archived_projection = (here/'retired-dli-metadata/native_info.rs').read_text()
    archived_fixture = (here/'retired-dli-metadata/backend_bus_fixture.rs').read_text()
    old = archived_fixture.replace('// @@BUS_ENUM@@','#[repr(u8)]\n#[derive(Copy,Clone,Debug,PartialEq,Eq)]\n'+block(historical,historical.index('pub enum SleBus {')))
    old=old.replace('// @@INFO_STRUCT@@',block(historical,historical.index('pub struct SleControllerInfo {')))
    old=old.replace('// @@NATIVE_INFO@@','#[derive(Clone,Copy)]\n'+block(native,native.index('pub(crate) struct NativeInfo {')))
    old=old.replace('// @@PROJECTION@@',function(archived_projection,'info'))
    old=old.replace('// @@CONVERSION@@',function(native,'backend_bus'))
    with tempfile.TemporaryDirectory(prefix='sparklink-historical-bus-') as tmp:
        p=Path(tmp)/'history.rs';p.write_text(old);exe=Path(tmp)/'test'
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p),'-o',str(exe)],check=True)
        text=subprocess.check_output([str(exe)],text=True);print(text)
        assert 'test result: ok. 5 passed; 0 failed' in text
    assert all((net/n).read_text()==s for n,s in sources.items())
    record=dict(status='ACTUAL_BACKEND_BUS_PROJECTION_PASS',tests=5,historical_tests=5,historical_scope='Exact b35 obsolete projection/types and five tests; current NativeInfo/conversion are dependencies, not current capability claims',historical_sha256={k:hashlib.sha256(v.encode()).hexdigest() for k,v in {'metadata':historical,'projection':archived_projection,'fixture':archived_fixture}.items()},sources={n:hashlib.sha256(s.encode()).hexdigest() for n,s in sources.items()},scope='Actual production bus enum/conversion, minimal NativeController.info and full five-byte/ten-byte fill_snapshot; transport/errno/controller type dependencies are fixtures. Not registration lifetime/IRQ/module/Virtual or physical qualification.',physical_acceptance=False,whole_backend_complete=False)
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
