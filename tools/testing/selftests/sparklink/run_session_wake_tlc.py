#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Targeted finite timer/owner/work model; not a C refinement or Linux proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import time


def run(output):
    if not __debug__:
        raise RuntimeError('optimized Python cannot validate a proof report')
    output.mkdir(exist_ok=False)
    here=Path(__file__).resolve().parent;root=here.parents[3]
    paths=[here/'session'/n for n in ['SessionWakeTimer.tla','SessionWakeTimer.cfg','SessionWakeTimerNegative.cfg','SessionWakeTimer.md']]
    paths += [root/'net/sparklink'/n for n in ['sle_channel_socket.c','sle_sessions.rs']]
    paths.append(Path(__file__).resolve())
    originals={p:p.read_bytes()for p in paths}
    source=originals[paths[4]].decode();start=source.index('void sl_connection_session_stop(');stop=source[start:source.index('struct sl_bind_admission',start)]
    assert stop.index('sl_channel_close')<stop.index('hrtimer_cancel')<stop.index('cancel_delayed_work_sync')
    for p in paths[:3]:shutil.copy2(p,output/p.name)
    properties=['TypeOK','ReferenceLedger','NoFreeWhileLive','TimerJoinedQuiescent','WorkJoinedQuiescent','OwnerDropAfterJoins','CleanupConverges']
    report=dict(status='RUNNING_UNPROVED',sources={str(p.relative_to(root)):hashlib.sha256(b).hexdigest()for p,b in originals.items()},properties=properties,runs=[],
                scope='Finite two-Session model safety and conditional liveness under explicit fairness/Linux API contracts;manual object/lock/ref mapping,not implementation refinement,actual concurrent Linux/UAF/drain/USB or hardware proof.')
    target=output/'report.json'
    def save():target.write_text(json.dumps(report,indent=2)+'\n')
    save()
    try:
        cfg=originals[paths[1]].decode();assert all(name in cfg for name in properties)and 'SkipTimerJoin = FALSE'in cfg
        for name,config in [('production-model','SessionWakeTimer.cfg'),('skipped-timer-join-negative','SessionWakeTimerNegative.cfg')]:
            command=['tlc','-workers','1','-config',config,'-metadir','states-'+name,'SessionWakeTimer.tla'];step=dict(name=name,command=command,start_ns=time.time_ns());report['runs'].append(step);save()
            log=output/(name+'.log')
            with log.open('x')as f:r=subprocess.run(command,cwd=output,stdout=f,stderr=subprocess.STDOUT,timeout=180)
            text=log.read_text();step.update(exit=r.returncode,end_ns=time.time_ns(),log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),tool_banner=text.splitlines()[0]);save()
            assert not re.search(r'^Warning:|unsupported|out of memory|incomplete|Error:.*(?:parse|syntax)',text,re.M|re.I),text[-3000:]
            if name=='production-model':
                assert r.returncode==0 and 'Model checking completed. No error has been found.'in text and 'Error:'not in text
                assert 'temporal properties for the complete state space'in text
                counts=re.findall(r'(\d+) states generated, (\d+) distinct states found, 0 states left on queue\.',text);assert counts
                step['states_generated'],step['distinct_states']=map(int,counts[-1]);step['depth']=int(re.search(r'depth of the complete state graph search is (\d+)',text)[1])
            else:
                assert r.returncode!=0 and 'Invariant NoFreeWhileLive is violated.'in text and 'The behavior up to this point is:'in text
                step['expected_counterexample']='NoFreeWhileLive after parent drop while unjoined callback remains'
            save()
        assert all(p.read_bytes()==b for p,b in originals.items())
        report['status']='FINITE_TWO_SESSION_MODEL_SAFETY_AND_CONDITIONAL_LIVENESS_PASS'
    except BaseException as error:
        report.update(status='UNPROVED',error_type=type(error).__name__,error=str(error));raise
    finally:save()
    print(report['status'],report['runs'][0]['distinct_states'],'states;unsafe timer-join counterexample retained')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);run(p.parse_args().output)
