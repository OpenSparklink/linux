#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual retained command selector/provider submissions; dependency fixtures."""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from run_usb_discovery import block
from run_connection_tx import function

def run(output):
 here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink'
 sources={n:(net/n).read_text() for n in ['sle_backend.rs','sle_dli.rs','sle_native.rs','sle_usb.rs','sle_workers.rs']}
 s=(here/'backend_command_port_fixture.rs').read_text();trait=block(sources['sle_backend.rs'],sources['sle_backend.rs'].index('pub(crate) trait CommandPort'))
 selector=function(sources['sle_dli.rs'],'command_port').replace('use kernel::alloc::KBox;','use kernel::alloc::KBox; use crate::FallibleBox;').replace('KBox::new(','FallibleBox::new(')
 for marker,text in [('TRAIT',trait),('SELECTOR',selector),('NATIVE_PORT',block(sources['sle_native.rs'],sources['sle_native.rs'].index('impl super::sle_backend::CommandPort')))]:s=s.replace('// @@'+marker+'@@',text)
 s=s.replace('super::sle_backend','crate::sle_backend').replace('super::sle_command_plan','crate::sle_command_plan').replace('super::sle_uapi','crate::sle_uapi')
 with tempfile.TemporaryDirectory(prefix='sparklink-command-port-') as tmp:
  p=Path(tmp);(p/'actual.rs').write_text(s);subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p/'actual.rs'),'-o',str(p/'test')],check=True);log=subprocess.check_output([str(p/'test')],text=True);print(log)
 assert '2 passed; 0 failed' in log
 # Source-order contract complements actual provider tests, not a concurrency proof.
 worker=sources['sle_workers.rs'][sources['sle_workers.rs'].index('impl WorkItem<1>'):]
 a=worker.index('let transport = match runtime.controller.command_port()');b=worker.index('transport.submit(',a);assert worker.index('drop(guard);',a)<b
 assert 'if let sle_dli::ControllerBackend::Native' not in worker and 'runtime.controller.send_command_transport' not in worker
 assert all((net/n).read_text()==text for n,text in sources.items())
 record=dict(status='ACTUAL_RETAINED_COMMAND_PORT_PASS',tests=2,sources={n:hashlib.sha256(text.encode()).hexdigest() for n,text in sources.items()},scope='Actual selector and provider impls, allocator/std Arc/USB transport dependencies; KBox allocation adapted only to fallible Box fixture. Static worker release-before-submit order check, not actual workqueue/lockdep/IRQ/module/callback or USB proof.',physical_acceptance=False)
 if output:output.write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps(record,indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
