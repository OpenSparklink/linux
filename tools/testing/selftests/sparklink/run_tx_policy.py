#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded CBMC checks of the actual PDU class selector and negative controls.

Constant eligibility and completed-PDU steps are assumptions. No USB, locks,
credit truth, scheduling fairness, original deadlines or refinement proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def run(output):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    net = root / 'net/sparklink'
    header = net / 'sle_tx_policy.h'
    table = net / 'sle_channel_table.h'
    harness = here / 'session/tx_policy_cbmc.c'
    inputs = {p: p.read_bytes() for p in (header, table, harness, Path(__file__))}
    output.mkdir(parents=True, exist_ok=False)
    path = output / 'report.json'
    report = dict(status='RUNNING_UNPROVED', tool=subprocess.check_output(['cbmc','--version'],text=True).strip(),
        kernel_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        dirty_diff_sha256=hashlib.sha256(subprocess.check_output(['git','diff','--binary'],cwd=root)).hexdigest(),
        sources={str(p.relative_to(root)):hashlib.sha256(raw).hexdigest() for p,raw in inputs.items()},
        bounds=dict(slots=6,fixed_slots=2,fixed_burst=2,completed_PDUs=18,unwind=19),
        assumptions=['Initial zero state checked separately; induction starts with in-range cursors and fixed_run<=2.',
                     'One arbitrary six-bit eligibility mask remains eligible for18 completed-PDU steps.',
                     'Caller invokes complete only after actual last-fragment acceptance; actual batch regression checks mapping.',
                     'No real locks, USB, callback drain, NOCP accuracy, time bound or unbounded/refinement proof.'],runs=[])
    try:
        original=inputs[header].decode()
        condition='p->fixed_run < SL_TX_FIXED_BURST || !normal'
        cursor='cursor = &p->normal_next;'
        assert original.count(condition)==original.count(cursor)==1
        variants={'production':original,
                  'unbounded-fixed-negative':original.replace(condition,'true'),
                  'shared-cursor-negative':original.replace(cursor,'cursor = &p->fixed_next;'),
                  'short-unwind-negative':original}
        required={'zero initialized policy','choose only eligible bounded slot','selection spends no completed quota',
                  'credit wait retains selected turn','bounded fixed priority and owed normal turn',
                  'retry yield earns no completion','completion preserves finite policy state',
                  'independent class cursors','all continuously ready slots progress in bounded completions'}
        for name,source in variants.items():
            folder=output/name;folder.mkdir()
            (folder/header.name).write_text(source)
            (folder/table.name).write_bytes(inputs[table])
            (folder/'harness.c').write_bytes(inputs[harness])
            command=['cbmc',str(folder/'harness.c'),'-I',str(folder),'--function','verify_tx_policy',
                     '--unwind','2' if name=='short-unwind-negative'else'19','--unwinding-assertions',
                     '--bounds-check','--pointer-check','--signed-overflow-check','--unsigned-overflow-check','--json-ui','--trace']
            raw=folder/'raw.json';started=time.time_ns()
            row=dict(kind=name,command=command,start_ns=started);report['runs'].append(row)
            path.write_text(json.dumps(report,indent=2)+'\n')
            with raw.open('x') as stream:
                done=subprocess.run(command,stdout=stream,stderr=subprocess.STDOUT,timeout=120)
            rows=json.loads(raw.read_text())
            properties=[p for r in rows for p in r.get('result',[])]
            terminal=[r['cProverStatus']for r in rows if 'cProverStatus'in r]
            diagnostics=[r for r in rows if r.get('messageType')in('ERROR','WARNING')]
            row.update(exit=done.returncode,elapsed_ns=time.time_ns()-started,terminal=terminal,
                       property_count=len(properties),statuses=sorted({p['status']for p in properties}),
                       diagnostics=diagnostics,raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest())
            assert not diagnostics,diagnostics
            assert required<={p.get('description')for p in properties}
            if name=='production':
                assert done.returncode==0 and terminal==['success']
                assert properties and all(p['status']=='SUCCESS'for p in properties)
            else:
                assert done.returncode==10 and terminal==['failure']
                assert any(p['status']=='FAILURE'and ('unwind'in p['property']if name=='short-unwind-negative'else p.get('description')in required)for p in properties)
            path.write_text(json.dumps(report,indent=2)+'\n')
        assert all(p.read_bytes()==raw for p,raw in inputs.items())
        report['status']='BOUNDED_ACTUAL_TX_POLICY_AND_NEGATIVE_CONTROLS_PASS'
    except BaseException as error:
        report.update(status='UNPROVED',error_type=type(error).__name__,error=str(error));raise
    finally:
        path.write_text(json.dumps(report,indent=2)+'\n')
    print(report['status'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
