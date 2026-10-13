#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual common Backend reservation/publication with controlled construction dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_usb_discovery import block
from run_connection_tx import function


def run(output):
    here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
    inputs={n:(net/n).read_text() for n in ['sle_dev.rs','sle_dli.rs','sparklink_core.rs']}
    dev=inputs['sle_dev.rs'];dli=inputs['sle_dli.rs'];core=inputs['sparklink_core.rs']
    s=(here/'backend_install_fixture.rs').read_text()
    replacements={'INFO':block(dli,dli.index('pub struct SleControllerInfo {')),'INFO_DEFAULT':function(dli[dli.index('impl Default for SleControllerInfo'):],'default'),'IDENTITY':block(dev,dev.index('pub(crate) struct DeviceIdentity {')).replace('pub(crate) struct','pub struct'),'DEVICE':block(dev,dev.index('pub(crate) struct SleDev {')),'REGISTRY':block(dev,dev.index('pub(crate) struct SleDevRegistry {')),'REGISTRATION':block(core,core.index('struct RuntimeRegistration {')),'RESERVE':function(core,'reserve_backend_identity'),'INSTALL':function(core,'install_backend_runtime'),'CANCEL':function(core,'cancel_backend_reservation'),'DETACH':function(core,'sle_detach_device')}
    replacements['CONSTANTS']='\n'.join(re.search(r'(?m)^(?:pub(?:\(crate\))? )?const '+n+r'[^\n]+',dev).group() for n in ['SLE_DEV_NAME_LEN','SLE_DEV_MAX','SLE_DEV_SETUP','SLE_DEV_UP','SLE_DEV_UNREGISTERING'])
    for marker,section,name in [('DEV_NEW','impl SleDev {','new'),('DEV_IDENTITY','impl SleDev {','identity'),('DEV_BUS','impl SleDev {','bus'),('DEV_NAME','impl SleDev {','name'),('DEV_ADDR','impl SleDev {','addr'),('DEV_UPDATE','impl SleDev {','update_hw_info'),('BEGIN_UNREGISTER','impl SleDev {','begin_unregister'),('TEST_FLAG','impl SleDev {','test_flag'),('REG_NEW','impl SleDevRegistry {','new'),('REGISTER_PENDING','impl SleDevRegistry {','register_pending'),('GET','impl SleDevRegistry {','get'),('GET_MUT','impl SleDevRegistry {','get_mut'),('UNREGISTER','impl SleDevRegistry {','unregister'),('REG_UPDATE','impl SleDevRegistry {','update_hw_info')]:
        replacements[marker]=function(dev[dev.index(section):].replace('const fn ','fn '),name)
    for k,v in replacements.items():s=s.replace('// @@'+k+'@@',v)
    with tempfile.TemporaryDirectory(prefix='sparklink-backend-install-') as tmp:
        p=Path(tmp)/'actual.rs';p.write_text(s);exe=Path(tmp)/'test'
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p),'-o',str(exe)],check=True)
        text=subprocess.check_output([str(exe),'--test-threads=1'],text=True);print(text)
    assert 'test result: ok. 10 passed; 0 failed' in text
    assert all((net/n).read_text()==s for n,s in inputs.items())
    record=dict(status='ACTUAL_COMMON_BACKEND_INSTALL_PASS',tests=10,sources={n:hashlib.sha256(s.encode()).hexdigest() for n,s in inputs.items()},scope='Actual reserve/install/cancel/retire and registry functions; std Mutex/Arc and instrumented Runtime constructor/destructor dependencies. Controlled retire/reuse/competing-install/subsystem-removal windows, not real kernel concurrency, IRQ, allocation/callback or physical qualification.',kernel_lifetime_proven=False,physical_acceptance=False,early_ws73_bootstrap_registered=False)
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
