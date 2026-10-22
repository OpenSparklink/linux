#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual complete Host connection admission/TX/reply/revoke bodies with dependency fixtures."""
from security_relay_fixture import write_fixture
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from run_connection_tx import function

def run(output=None):
    here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
    names=['sle_host.rs','sle_command_queue.rs','sle_command_plan.rs','sle_discovery_operation.rs','sle_connection_operation.rs','sle_link_observation.rs','sle_mgmt.rs','sle_dli.rs','sle_workers.rs','sle_grant.rs','sle_native.rs']
    names += ['sle_security_relay.rs','sle_security_relay_state.rs','sle_ingress.rs','sle_runtime_address.rs','sle_link_command.rs']
    inputs={n:(net/n).read_bytes() for n in names}
    source=inputs['sle_host.rs'].decode();source=source[source.index('struct InFlight {'):]
    constructor=function(source,'new_boxed');source=source.replace(constructor,'')
    # Kernel errno is the dependency adapter; all business predicates/methods
    # and queue/storage/link modules remain verbatim.
    source=source.replace('Error::from_errno(','error_from_errno(').replace('.materialize(params)','.materialize(params).map_err(|e|e.to_errno())')
    fixture=(here/'connection/native_host_fixture.rs').read_text().replace('// @@ACTUAL_HOST@@',source)
    variants='\n'.join(re.search(r'(?m)^    '+name+r' = 0x[0-9A-F]+,',inputs['sle_dli.rs'].decode()).group() for name in ['CreateConnection','EnableBroadcast','EnableScan','SetScanParam','ReadMacAddr'])
    fixture=fixture.replace('// @@OPCODES@@',variants).replace('// @@TIMEOUT@@',re.search(r'(?m)^pub\(crate\) const CMD_TIMEOUT_MS: u32 = [0-9_]+;',inputs['sle_mgmt.rs'].decode()).group())
    native=inputs['sle_native.rs'].decode()
    start=native.index("struct NativeCommandTicket<'a> {");end=native.index('\n}',start)+2
    callback=function(re.sub(r'unsafe extern "C" fn (\w+)',r'unsafe fn \1',native),'sparklink_native_command_commit_rust')
    fixture=fixture.replace('// @@COMMAND_CALLBACK@@',(here/'native-ticket/command_commit.rs').read_text().replace('// @@TICKET@@',native[start:end]).replace('// @@COMMIT@@',callback).replace('super::ControllerRuntime','ControllerRuntime'))
    outcome=(here/'native-ticket/command_outcome.rs').read_text().replace('// @@SEND@@',function(native,'send_typed')).replace('super::ControllerRuntime','ControllerRuntime').replace('Error::from_errno(','error_from_errno(')
    fixture=fixture.replace('// @@COMMAND_OUTCOME@@',outcome)
    with tempfile.TemporaryDirectory(prefix='sparklink-native-connection-host-') as tmp:
        tmp=Path(tmp); write_fixture(here.parents[3], tmp)
        for n in names[1:]:(tmp/n).write_bytes(inputs[n])
        pending=(net/'sle_mgmt.rs').read_text().split('// Command storage/progress is also compiled')[0].replace('kernel::','crate::actual_host::kernel::').replace('pin_init::','crate::hardware_fault_allocator::')
        (tmp/'hardware_fault_pending.rs').write_text(pending)
        worker=(here/'connection/hardware_error_worker_fixture.rs').read_text()
        worker=worker.replace('// @@WORKER@@',function(inputs['sle_workers.rs'].decode(),'process_host_events')).replace('// @@FAIL@@',function(inputs['sle_workers.rs'].decode(),'fail_host'))
        worker=worker.replace('// @@EXPIRE@@',function(inputs['sle_workers.rs'].decode(),'expire_command_deadlines')).replace('// @@FAIL_LOCKED@@',function(inputs['sle_workers.rs'].decode(),'fail_host_locked').replace('super::sle_host::CommandHost','CommandHost'))
        worker=worker.replace('// @@ENQUEUE@@',function(inputs['sle_ingress.rs'].decode(),'enqueue_rx').replace('kernel::sync::Arc','Arc').replace('super::ControllerRuntime','ControllerRuntime'))
        (tmp/'hardware_error_worker_fixture.rs').write_text(worker)
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(tmp/'fixture.rs'),'-o',str(tmp/'test')],check=True)
        process=subprocess.run([str(tmp/'test'),'--test-threads=1'],text=True,capture_output=True);result=process.stdout;print(result);print(process.stderr);process.check_returncode()
        for name in ['original_address_deadline_publishes_actual_host_fault_before_author_timeout', 'unselected_query_expiry_does_not_fabricate_host_fault_or_refund_credit', 'first_fault_and_cancelled_author_survive_shared_expiry_and_late_reply', 'address_set_complete_does_not_renew_original_readback_deadline', 'shared_expiry_never_advances_another_controller']:
            assert f'test actual_host::hardware_fault_worker::{name} ... ok' in result, 'required shared-expiry case missing: '+name
    with tempfile.TemporaryDirectory(prefix='sparklink-cleanup-prepare-') as tmp:
        tmp=Path(tmp)
        fixture=(here/'connection/cleanup_prepare_fixture.rs').read_text().replace('// @@ACTUAL_PREPARE@@',function(inputs['sle_workers.rs'].decode(),'progress_connection_cleanup'))
        pending=(net/'sle_mgmt.rs').read_text().split('// Command storage/progress is also compiled')[0].replace('kernel::','crate::actual_host::kernel::').replace('pin_init::','crate::hardware_fault_allocator::')
        (tmp/'hardware_fault_pending.rs').write_text(pending)
        worker=(here/'connection/hardware_error_worker_fixture.rs').read_text()
        worker=worker.replace('// @@WORKER@@',function(inputs['sle_workers.rs'].decode(),'process_host_events')).replace('// @@FAIL@@',function(inputs['sle_workers.rs'].decode(),'fail_host'))
        worker=worker.replace('// @@EXPIRE@@',function(inputs['sle_workers.rs'].decode(),'expire_command_deadlines')).replace('// @@FAIL_LOCKED@@',function(inputs['sle_workers.rs'].decode(),'fail_host_locked').replace('super::sle_host::CommandHost','CommandHost'))
        worker=worker.replace('// @@ENQUEUE@@',function(inputs['sle_ingress.rs'].decode(),'enqueue_rx').replace('kernel::sync::Arc','Arc').replace('super::ControllerRuntime','ControllerRuntime'))
        (tmp/'hardware_error_worker_fixture.rs').write_text(worker)
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(tmp/'fixture.rs'),'-o',str(tmp/'test')],check=True)
        subprocess.run([str(tmp/'test'),'--test-threads=1'],check=True)
    assert all((net/n).read_bytes()==b for n,b in inputs.items())
    count=re.search(r'test result: ok\. (\d+) passed; 0 failed;',result);assert count
    record={'status':'NATIVE_CONNECTION_ACTUAL_HOST_SOURCE_PASS','tests':int(count[1]),'cleanup_prepare_tests':2,'hardware_error_host_ticket_tests':5,'hardware_error_worker_ledger_ingress_tests':len(re.findall(r'(?m)^test actual_host::hardware_fault_worker::\S+ \.\.\. ok$',result)),'scope':'Actual Host/queue/operation/link, whole PendingEntry/PendingQueue prefix, RX enqueue, worker process_host_events/fail_host/fail_host_locked and Runtime expire_command_deadlines with one sampled instant plus Native atomic command callback source; std Mutex/Arc, global clock, full-ring rejection and nonexecuted initializer type are explicit dependencies. Pending namespace/type paths only adapted; queue-wrapper tail already compiled by Host is excluded. Not VFS, IRQ/workqueue concurrency, allocator/USB/firmware or RF refinement.','live_kernel_acceptance':False,'connection_rf_acceptance':False,'automatic_recovery_acceptance':False,'sources':{n:hashlib.sha256(b).hexdigest() for n,b in inputs.items()},'fixture_sources':{name:hashlib.sha256((here/name).read_bytes()).hexdigest() for name in ['connection/native_host_fixture.rs','connection/hardware_error_worker_fixture.rs','connection/cleanup_prepare_fixture.rs','native-ticket/command_commit.rs','native-ticket/command_outcome.rs','security_relay_fixture.py']}}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2));return record

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
