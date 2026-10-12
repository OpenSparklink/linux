#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual complete Host connection admission/TX/reply/revoke bodies with dependency fixtures."""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from run_connection_tx import function

def run(output=None):
    here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
    names=['sle_host.rs','sle_command_queue.rs','sle_command_plan.rs','sle_discovery_operation.rs','sle_connection_operation.rs','sle_link_observation.rs','sle_mgmt.rs','sle_dli.rs','sle_workers.rs']
    inputs={n:(net/n).read_bytes() for n in names}
    source=inputs['sle_host.rs'].decode();source=source[source.index('struct InFlight {'):]
    constructor=function(source,'new_boxed');source=source.replace(constructor,'')
    # Kernel errno is the dependency adapter; all business predicates/methods
    # and queue/storage/link modules remain verbatim.
    source=source.replace('Error::from_errno(','error_from_errno(')
    fixture=(here/'connection/native_host_fixture.rs').read_text().replace('// @@ACTUAL_HOST@@',source).replace('// @@PUSH_COOKIE@@',function(inputs['sle_mgmt.rs'].decode(),'push_cookie'))
    variants='\n'.join(re.search(r'(?m)^    '+name+r' = 0x[0-9A-F]+,',inputs['sle_dli.rs'].decode()).group() for name in ['CreateConnection','EnableBroadcast','EnableScan','SetScanParam'])
    fixture=fixture.replace('// @@OPCODES@@',variants).replace('// @@TIMEOUT@@',re.search(r'(?m)^pub\(crate\) const CMD_TIMEOUT_MS: u32 = [0-9_]+;',inputs['sle_mgmt.rs'].decode()).group())
    with tempfile.TemporaryDirectory(prefix='sparklink-native-connection-host-') as tmp:
        tmp=Path(tmp)
        for n in names[1:]:(tmp/n).write_bytes(inputs[n])
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(tmp/'fixture.rs'),'-o',str(tmp/'test')],check=True)
        process=subprocess.run([str(tmp/'test'),'--test-threads=1'],text=True,capture_output=True);result=process.stdout;print(result);print(process.stderr);process.check_returncode()
    with tempfile.TemporaryDirectory(prefix='sparklink-cleanup-prepare-') as tmp:
        tmp=Path(tmp)
        fixture=(here/'connection/cleanup_prepare_fixture.rs').read_text().replace('// @@ACTUAL_PREPARE@@',function(inputs['sle_workers.rs'].decode(),'progress_connection_cleanup'))
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(tmp/'fixture.rs'),'-o',str(tmp/'test')],check=True)
        subprocess.run([str(tmp/'test'),'--test-threads=1'],check=True)
    assert all((net/n).read_bytes()==b for n,b in inputs.items())
    count=re.search(r'test result: ok\. (\d+) passed; 0 failed;',result);assert count
    record={'status':'NATIVE_CONNECTION_ACTUAL_HOST_SOURCE_PASS','tests':int(count[1]),'cleanup_prepare_tests':2,'scope':'actual Host/queue/operation/link source; clock/errno/allocation/wire-event dependencies are fixtures; not VFS, running kernel or RF','live_kernel_acceptance':False,'connection_rf_acceptance':False,'automatic_recovery_acceptance':False,'sources':{n:hashlib.sha256(b).hexdigest() for n,b in inputs.items()}}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));return record

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
