#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual SnoopLog methods/UAPI record; clock/allocation are dependencies, no RF."""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
from run_connection_tx import function

def run(output):
    root=Path(__file__).resolve().parents[4];net=root/'net/sparklink'
    original=(net/'sle_snoop.rs').read_text();uapi=(net/'sle_uapi.rs').read_text()
    source=original[original.index('const CAPACITY:'):].replace(function(original,'new_boxed'),'')
    record=re.search(r'pub\(crate\) struct SleSnoopRecord \{.*?\n\}',uapi,re.S)[0]
    constants='\n'.join(re.search(r'pub\(crate\) const '+name+r':[^;]+;',uapi)[0] for name in ['SNOOP_PAYLOAD_MAX','SNOOP_TRUNCATED','SNOOP_REDACTED'])
    fixture='''#[derive(Clone,Copy)] struct DeviceIdentity {id:u16,generation:u64}
mod kernel {pub mod bindings {pub unsafe fn ktime_get_boottime()->i64{17}}}
'''+constants+'\n#[derive(Clone,Copy)]\n'+record+'\n'+source+'''
#[test] fn actual_sensitive_payloads_are_explicitly_redacted_with_real_lengths(){
 let empty=unsafe{core::mem::zeroed::<SleSnoopRecord>()};
 let mut log=SnoopLog{records:[empty;CAPACITY],count:0,tail:0,seq:0};let id=DeviceIdentity{id:1,generation:2};
 for (opcode,length) in [(0x1c03,21),(0x1c05,20)]{
  let params=vec![0xa5;length];let before=log.current_seq();log.tx(id,1,opcode,&params,-13);
  let rec=log.next_after(before).unwrap();assert_eq!(rec.status,-13);assert_eq!(rec.flags,SNOOP_REDACTED);
  assert_eq!(rec.original_length,length as u32+5);assert_eq!(rec.captured_length,5);
  assert_eq!(&rec.payload[..5],&[0xa1,opcode as u8,0x1c,length as u8,0]);
  assert!(rec.payload[5..].iter().all(|b|*b==0));assert_eq!(params,vec![0xa5;length]);
 }
 log.tx(id,1,0x1812,&[1,2,3],0);let rec=log.next_after(2).unwrap();assert_eq!(rec.flags,0);assert_eq!(&rec.payload[5..8],&[1,2,3]);
 log.rx(id,1,&[0x14,2]);assert_eq!(log.next_after(3).unwrap().captured_length,2);
 for _ in 0..70{log.tx(id,1,0x1c03,&[0x5a;21],0);}
 let rec=log.next_after(0).unwrap();assert!(rec.lost>0);assert!(rec.payload[5..].iter().all(|b|*b==0));
}
'''
    with tempfile.TemporaryDirectory(prefix='sparklink-snoop-redaction-') as t:
        t=Path(t);(t/'test.rs').write_text(fixture)
        subprocess.run(['rustc','--edition=2024','--test','-Dwarnings',str(t/'test.rs'),'-o',str(t/'test')],check=True)
        p=subprocess.run([str(t/'test')],capture_output=True,text=True);print(p.stdout);print(p.stderr);p.check_returncode()
    result={'status':'ACTUAL_SNOOP_REDACTION_SOURCE_PASS','source_sha256':hashlib.sha256(original.encode()).hexdigest(),'record_uapi_sha256':hashlib.sha256(record.encode()).hexdigest(),'scope':'actual production trace methods/record; exact secret omission/length/header/ring replacement, no key installation, real concurrency or RF proof'}
    if output:output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
