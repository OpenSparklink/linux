#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual pending identity constructor/registry/core reservation; no USB I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_connection_tx import function
from run_usb_discovery import block


def run(output):
    here=Path(__file__).resolve().parent
    net=here.parents[3]/'net/sparklink'
    inputs={n:(net/n).read_text() for n in ['sle_dev.rs','sle_dli.rs','sparklink_core.rs','sle_usb.rs']}
    source=inputs['sle_dev.rs'];dli=inputs['sle_dli.rs'];fixture=(here/'usb-registration/pending_fixture.rs').read_text()
    identity=block(source,source.index('pub(crate) struct DeviceIdentity {')).replace('pub(crate) struct','pub struct')
    replacements={'INFO':block(dli,dli.index('pub struct SleControllerInfo {')),'INFO_DEFAULT':function(dli[dli.index('impl Default for SleControllerInfo'):],'default'),'IDENTITY':identity,'DEVICE':block(source,source.index('pub(crate) struct SleDev {')),'REGISTRY':block(source,source.index('pub(crate) struct SleDevRegistry {')),'RESERVE':function(inputs['sparklink_core.rs'],'reserve_usb_identity'),'DETACH':function(inputs['sparklink_core.rs'],'sle_detach_device')}
    replacements['CONSTANTS']='\n'.join(re.search(r'(?m)^(?:pub(?:\(crate\))? )?const '+n+r'[^\n]+',source).group() for n in ['SLE_DEV_NAME_LEN','SLE_DEV_MAX','SLE_DEV_SETUP','SLE_DEV_UP','SLE_DEV_UNREGISTERING'])
    for marker,section,name in [('DEV_NEW','impl SleDev {','new'),('DEV_IDENTITY','impl SleDev {','identity'),('BEGIN_UNREGISTER','impl SleDev {','begin_unregister'),('TEST_FLAG','impl SleDev {','test_flag'),('REG_NEW','impl SleDevRegistry {','new'),('REGISTER_PENDING','impl SleDevRegistry {','register_pending'),('GET','impl SleDevRegistry {','get'),('UNREGISTER','impl SleDevRegistry {','unregister')]:replacements[marker]=function(source[source.index(section):].replace('const fn ', 'fn '),name)
    for name,body in replacements.items():fixture=fixture.replace('// @@'+name+'@@',body)
    with tempfile.TemporaryDirectory(prefix='sparklink-usb-pending-') as directory:
        root=Path(directory);(root/'actual.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(root/'actual.rs'),'-o',str(root/'test')],check=True)
        text=subprocess.check_output([str(root/'test'),'--test-threads=1'],text=True)
    open_fixture=(here/'usb-registration/open_fixture.rs').read_text()
    open_fixture=open_fixture.replace('// @@CORE_OPEN@@',function(inputs['sparklink_core.rs'],'open_usb_runtime'))
    usb=inputs['sle_usb.rs'];usb=usb[usb.index('impl SleController for UsbController'):]
    open_fixture=open_fixture.replace('// @@USB_OPEN@@',function(usb,'open')).replace('// @@USB_CLOSE@@',function(usb,'close'))
    with tempfile.TemporaryDirectory(prefix='sparklink-usb-adoption-') as directory:
        root=Path(directory);(root/'actual.rs').write_text(open_fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(root/'actual.rs'),'-o',str(root/'test')],check=True)
        opened=subprocess.check_output([str(root/'test'),'--test-threads=1'],text=True)
    assert 'test result: ok. 6 passed; 0 failed' in opened
    assert 'test result: ok. 7 passed; 0 failed' in text
    assert all((net/n).read_text()==s for n,s in inputs.items())
    record={'status':'ACTUAL_USB_PENDING_RESERVATION_PASS','tests':13, 'pending_allocator_tests':7, 'open_adoption_tests':6,'sources':{n:hashlib.sha256(s.encode()).hexdigest() for n,s in inputs.items()},'scope':'actual constructor/pending allocator/generation/get/unregister/core reservation/exact two-phase detach and USB listener/open adoption; logging/Mutex/info types/stats dependencies, not concurrent registry or callbacks/kernel/physical USB qualification','hardware_acceptance':False}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
