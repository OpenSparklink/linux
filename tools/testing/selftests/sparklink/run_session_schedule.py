#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""CBMC of the production earliest-deadline helper, including modulo clock wrap.

No kernel locks, Linux scheduler, Runtime, USB or concurrency proof. Deliberate
unsigned jiffies wrap is well-defined modulo arithmetic; signed overflow checked.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def run(output):
    if not __debug__:
        raise RuntimeError('optimized verification is not a proof')
    here=Path(__file__).resolve().parent;root=here.parents[3];header=root/'net/sparklink/sle_session_schedule.h';harness=here/'session/schedule_cbmc.c'
    inputs={p:p.read_bytes() for p in [header,harness,Path(__file__).resolve()]}
    output.mkdir()
    report=dict(status='RUNNING_NOT_PROVEN',scope='Actual production pure deadline selection;Linux signed-difference clock dependency,4 deadlines/5000tick elapsed+offset;all base clock values including wrap,on32/64bit. Not scheduler/concurrency/Runtime/refinement/RF proof.',sources={str(p.relative_to(root)):hashlib.sha256(b).hexdigest() for p,b in inputs.items()},assumptions=['Linux two-complement signed-difference jiffies comparison','Offsets and elapsed at most5000ticks,well inside signed half-range;finite protocol deadlines','Unsigned addition/subtraction intentionally modulo;not enabled as erroneous overflow check'],runs=[])
    path=output/'report.json'
    try:
        report['tool']=subprocess.check_output(['cbmc','--version'],text=True).strip()
        original=inputs[header].decode();mutant=original.replace('delay < p->delay','delay > p->delay');assert mutant!=original
        for bits in [32,64]:
            for variant,text in [('production',original),('wrong-maximum-negative',mutant),('short-unwind-negative',original)]:
                kind=f'{bits}-'+variant;folder=output/kind;folder.mkdir();(folder/header.name).write_text(text);(folder/'harness.c').write_bytes(inputs[harness])
                command=['cbmc',str(folder/'harness.c'),'-I',str(folder),'-D','EXPECTED_CLOCK_BITS='+str(bits),'--'+str(bits),'--function','verify_original_deadlines','--unwind','2' if variant=='short-unwind-negative' else '5','--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check','--json-ui','--trace']
                raw=folder/'raw.json';start=time.time_ns()
                with raw.open('x') as f:done=subprocess.run(command,stdout=f,stderr=subprocess.STDOUT,timeout=120)
                rows=json.loads(raw.read_text());props=[p for row in rows for p in row.get('result',[])];statuses={p['status'] for p in props};terminal=[row['cProverStatus'] for row in rows if 'cProverStatus' in row];diagnostics=[row for row in rows if row.get('messageType') in ['ERROR','WARNING']]
                names={'idle has no timer','earliest original deadline including wrap and expiry','wakeup never refreshes original deadline','pending event not postponed by deadline'};assert names<={p.get('description') for p in props}
                report['runs'].append(dict(kind=kind,exit=done.returncode,property_count=len(props),statuses=sorted(statuses),terminal=terminal,diagnostics=diagnostics,command=command,elapsed_ns=time.time_ns()-start,raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest()))
                assert not diagnostics
                if variant!='production':
                    assert done.returncode==10 and terminal==['failure']
                    if variant=='short-unwind-negative':assert any(p['status']=='FAILURE' and 'unwind' in p['property'] for p in props)
                    else:assert any(p['status']=='FAILURE' and p['description']=='earliest original deadline including wrap and expiry' for p in props)
                else:assert done.returncode==0 and terminal==['success'] and statuses=={'SUCCESS'}
        assert all(p.read_bytes()==b for p,b in inputs.items())
        report['status']='BOUNDED_PRODUCTION_DEADLINE_SELECTION_PASS'
    except BaseException as error:
        report.update(status='UNPROVED',error=str(error),error_type=type(error).__name__);raise
    finally:path.write_text(json.dumps(report,indent=2)+'\n')
    print(report['status'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);run(p.parse_args().output)
