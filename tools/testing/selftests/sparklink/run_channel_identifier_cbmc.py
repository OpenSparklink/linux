#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Direct production CMTC codec proof; no kernel/firmware/lifetime refinement claim."""
import argparse,hashlib,json,subprocess,time
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--timeout',type=int,default=120);p.add_argument('--contract',choices=['identifier','limits','dynamic'],default='identifier');a=p.parse_args()
a.output.mkdir(parents=True,exist_ok=False)
root=Path(__file__).resolve().parents[4];here=Path(__file__).resolve().parent
sources=[here/({'identifier':'channel/identifier_cbmc.c','limits':'channel/mtu_mps_cbmc.c','dynamic':'channel/dynamic_cbmc.c'}[a.contract]),root/'net/sparklink/sle_channel_wire.c',root/'net/sparklink/sle_channel_wire.h',Path(__file__).resolve()]
if a.contract=='limits':sources.append(root/'net/sparklink/sle_channel_state.h')
if a.contract=='dynamic':sources.append(root/'net/sparklink/sle_dynamic_state.h')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
before={str(p.relative_to(root)):sha(p) for p in sources}
command=['cbmc',str(sources[0]),str(sources[1]),'--function','main','--bounds-check','--pointer-check','--signed-overflow-check','--unwind','65' if a.contract=='dynamic' else '17','--unwinding-assertions','--json-ui']
if a.contract=='limits':command+=['--unsigned-overflow-check']
r=dict(contract=a.contract,status='RUNNING_UNPROVED',source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),source_tree_clean=not bool(subprocess.check_output(['git','status','--porcelain'],cwd=root)),sources=before,command=command,tool_version=subprocess.check_output(['cbmc','--version'],text=True).strip(),assumptions=['Valid C pointers/objects as required by codec interface; length bounded0..16 for arbitrary input','Sequential pure codec semantics,not real kernel locks/allocator/USB/firmware'],bounds=['All256identifier values,maximum2042 capability roundtrip','All byte values for arbitrary16-byte array;all valid lengths0..16;failure atomicity','Fixed16-iteration initialization,unwind17 with unwinding assertions enabled'],not_proved=['Dynamic channel creation/authorization/TCID lifecycle','Session worker synchronization,grant/epoch/revoke/late reply/physical lifetime','Firmware behavior,NOCP or actual peer delivery'],real_acceptance=False)
if a.contract=='limits':
 r.update(bounds=['All unsigned32 MTU/MPS/TCID inputs to actual payload-limit function','Six transitions,all seven event choices with arbitrary unsigned inputs and expiry;original deadline cannot reopen terminal state','Independent capability MTU1..2042 and MPS20..2047;unwind17 with unwinding assertions'],not_proved=r['not_proved']+['Unbounded temporal liveness or implementation refinement','Concurrent kernel locks,wakeups,allocation or USB/firmware behavior'])
if a.contract=='dynamic':
 r.update(assumptions=['Valid C pointers/objects as required by the codec; arbitrary input length0..32','Sequential actual pure codec/state transitions; no kernel locks/allocator/USB/firmware refinement'],bounds=['All8bit identifiers,unicastTCID0x80..0xdf,MTU1..2042/MPS6..2047,8bit port/AID and SLQI inputs','Arbitrary32byte buffers,length0..32;failure atomicity;unwind65 with unwinding assertions,including full64byte decoded-struct memcmp','Six sequential events:submit,detach,expiry,arbitrary response;terminal/abandon/oldID invariants'],not_proved=r['not_proved']+['Whole dynamic socket/Grant/queue/lifecycle/close protocol refinement or temporal liveness'])
out=a.output/'report.json';out.write_text(json.dumps(r,indent=2)+'\n')
try:
 result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=a.timeout);(a.output/'raw.json').write_bytes(result.stdout);(a.output/'stderr.txt').write_bytes(result.stderr)
 rows=json.loads(result.stdout);properties=[p for row in rows for p in row.get('result',[])]
 success=(result.returncode==0 and not result.stderr and properties and all(p['status']=='SUCCESS' for p in properties) and any(row.get('cProverStatus')=='success' for row in rows) and {p['property'] for p in properties if p['property'].startswith('main.assertion.')}=={f'main.assertion.{n}' for n in range(1,14 if a.contract=='limits' else 9)} and not any(row.get('messageType','').upper() in ['ERROR','WARNING'] for row in rows) and before=={str(p.relative_to(root)):sha(p) for p in sources})
 passed={'identifier':'PRODUCTION_CODEC_IDENTIFIER_BOUNDED_PASS','limits':'PRODUCTION_MTU_MPS_BOUNDED_PASS','dynamic':'PRODUCTION_DYNAMIC_CMTC_BOUNDED_PASS'}[a.contract]
 r.update(status=passed if success else 'UNPROVED',exit=result.returncode,property_count=len(properties),properties=properties,raw_sha256=sha(a.output/'raw.json'))
except (OSError,ValueError,KeyError,subprocess.TimeoutExpired) as error:r.update(status='UNPROVED',error=str(error))
out.write_text(json.dumps(r,indent=2)+'\n');print(r['status']);raise SystemExit(0 if r['status'] in ['PRODUCTION_CODEC_IDENTIFIER_BOUNDED_PASS','PRODUCTION_MTU_MPS_BOUNDED_PASS','PRODUCTION_DYNAMIC_CMTC_BOUNDED_PASS'] else 1)
