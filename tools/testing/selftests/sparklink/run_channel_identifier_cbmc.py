#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Direct production CMTC codec proof; no kernel/firmware/lifetime refinement claim."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--timeout',type=int,default=120);a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parents[4];here=Path(__file__).resolve().parent
sources=[here/'channel/identifier_cbmc.c',root/'net/sparklink/sle_channel_wire.c',root/'net/sparklink/sle_channel_wire.h',Path(__file__).resolve()]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
before={str(p.relative_to(root)):sha(p) for p in sources}
command=['cbmc',str(sources[0]),str(sources[1]),'--function','main','--bounds-check','--pointer-check','--signed-overflow-check','--unwind','17','--unwinding-assertions','--json-ui']
r=dict(status='RUNNING_UNPROVED',source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),source_tree_clean=not bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)),sources=before,command=command,tool_version=subprocess.check_output(['cbmc','--version'],text=True).strip(),assumptions=['Valid C pointers/objects as required by codec interface; length bounded0..16 for arbitrary input','Sequential pure codec semantics,not real kernel locks/allocator/USB/firmware'],bounds=['All256identifier values,maximum2042 capability roundtrip','All byte values for arbitrary16-byte array;all valid lengths0..16;failure atomicity','Fixed16-iteration initialization,unwind17 with unwinding assertions enabled'],not_proved=['Dynamic channel creation/authorization/TCID lifecycle','Session worker synchronization,grant/epoch/revoke/late reply/physical lifetime','Firmware behavior,NOCP or actual peer delivery'],real_acceptance=False)
out=a.output/'report.json';out.write_text(json.dumps(r,indent=2)+'\n')
try:
 result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.timeout);(a.output/'raw.json').write_bytes(result.stdout);(a.output/'stderr.txt').write_bytes(result.stderr)
 rows=json.loads(result.stdout);properties=[p for row in rows for p in row.get('result',[])]
 success=(result.returncode==0 and not result.stderr and properties and all(p['status']=='SUCCESS' for p in properties) and any(row.get('cProverStatus')=='success' for row in rows) and {p['property'] for p in properties if p['property'].startswith('main.assertion.')}=={f'main.assertion.{n}' for n in range(1,9)} and not any(row.get('messageType','').upper() in ['ERROR','WARNING'] for row in rows) and before=={str(p.relative_to(root)):sha(p) for p in sources})
 r.update(status='PRODUCTION_CODEC_IDENTIFIER_BOUNDED_PASS' if success else 'UNPROVED',exit=result.returncode,property_count=len(properties),properties=properties,raw_sha256=sha(a.output/'raw.json'))
except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as error:r.update(status='UNPROVED',error=str(error))
out.write_text(json.dumps(r,indent=2)+'\n');print(r['status']);raise SystemExit(0 if r['status']=='PRODUCTION_CODEC_IDENTIFIER_BOUNDED_PASS' else 1)
