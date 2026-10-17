#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual standard event/ring functions and isolated historical witnesses;no kernel/RF."""
import argparse,hashlib,json,os,subprocess,tempfile
from pathlib import Path
from run_connection_tx import function
from run_usb_discovery import block

def run(output):
 here=Path(__file__).resolve().parent;net=here.parents[3]/'net/sparklink';dli=(net/'sle_dli.rs').read_text();codec=(net/'sle_standard_dli.rs').read_text();archive=here/'retired-standard-events'
 replacements={'OPCODE':block(dli,dli.index('pub(crate) enum SleOpcode {')),'STATUS':block(dli,dli.index('pub(crate) enum SleStatus {')),'OPCODE_PARSE':function(dli,'sle_opcode_from_u16'),'EVENT':block(dli,dli.index('pub(crate) enum SleEvent {')),'EVENT_STRUCT':block(codec,codec.index('struct DliUsbEvent {')),'PARSE':function(codec,'parse_event_packet'),'DECODE':function(codec,'event_to_sle'),'STATUS_PARSE':function(codec,'raw_to_status'),'RING_STRUCT':block(dli,dli.index('pub(crate) struct ControllerEventRing {')),'RING_PUSH':function(dli,'push_tagged'),'RING_POP':function(dli,'pop_tagged'),'OLD_EVENTS':(archive/'event_model.rs').read_text(),'OLD_DECODER':(archive/'decoder.rs').read_text(),'OLD_RING':(archive/'ring.rs').read_text()}
 # Enum attributes are part of production representation/semantics, not models.
 replacements['OPCODE']='#[repr(u16)]\n#[derive(Copy,Clone,Debug,PartialEq,Eq)]\n'+replacements['OPCODE'];replacements['STATUS']='#[repr(u8)]\n#[derive(Copy,Clone,Debug,PartialEq,Eq)]\n'+replacements['STATUS']
 fixture=(here/'standard_event_fixture.rs').read_text()
 for key,value in replacements.items():fixture=fixture.replace('// @@'+key+'@@',value.replace('super::','crate::') if key in ['PARSE','DECODE'] else value)
 assert '// @@' not in fixture
 with tempfile.TemporaryDirectory(prefix='sparklink-standard-events-') as tmp:
  p=Path(tmp);(p/'actual.rs').write_text(fixture);subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(p/'actual.rs'),'-o',str(p/'test')],check=True);s=subprocess.check_output([str(p/'test')],text=True);print(s);assert '7 passed; 0 failed' in s
 assert dli==(net/'sle_dli.rs').read_text() and codec==(net/'sle_standard_dli.rs').read_text()
 sources={str(p.relative_to(here.parents[3])):hashlib.sha256(p.read_bytes()).hexdigest() for p in [net/'sle_dli.rs',net/'sle_standard_dli.rs',here/'standard_event_fixture.rs',Path(__file__),*sorted(archive.iterdir())] if p.is_file()}
 result=dict(status='ACTUAL_STANDARD_EVENT_AND_TAGGED_RING_SUBSETS_PASS',current_tests=6,historical_test_groups=1,sources=sources,scope='Actual event/parser/status/opcode/tagged ring pure bodies;Vec allocator and errno dependencies explicit. Historical decoder/ring isolated,not current support or standard conformance. No ingress scheduling,IRQ/lock/USB callback,kernel or physical/RF proof.',physical_acceptance=False)
 if output:output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
