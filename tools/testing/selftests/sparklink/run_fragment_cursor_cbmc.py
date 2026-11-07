#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""All scalar inputs of the actual production cursor; no worker/USB proof."""
import argparse, hashlib, json, re, subprocess
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--output',type=Path,required=True)
p.add_argument('--timeout',type=int,default=120)
a=p.parse_args();here=Path(__file__).resolve().parent;root=here.parents[3]
paths=[root/'net/sparklink/sle_fragment_cursor.h',here/'fragment_cursor_cbmc.c']
inputs={s:s.read_bytes() for s in paths}
command=['cbmc',str(paths[1]),'--bounds-check','--pointer-check','--signed-overflow-check',
         '--unsigned-overflow-check','--conversion-check','--unwinding-assertions','--trace']
try:
 r=subprocess.run(command,capture_output=True,text=True,timeout=a.timeout)
 log=r.stdout+r.stderr;status='NOT_PROVEN'
 if r.returncode==0 and 'VERIFICATION SUCCESSFUL' in log and not re.search(r'unsupported|warning:|: FAILURE|: UNKNOWN',log,re.I):status='SCALAR_TRANSITIONS_PASS'
except subprocess.TimeoutExpired as e:
 log=(e.stdout or b'').decode()+(e.stderr or b'').decode();status='NOT_PROVEN_TIMEOUT';r=None
assert all(s.read_bytes()==b for s,b in inputs.items())
a.output.with_suffix('.cbmc.log').write_text(log)
record=dict(status=status,exit=r.returncode if r else None,source_head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),source_tree_clean=not subprocess.check_output(['git','status','--porcelain'],cwd=root),sources={str(s.relative_to(root)):hashlib.sha256(b).hexdigest() for s,b in inputs.items()},command=command,tool_version=subprocess.check_output(['cbmc','--version'],text=True).strip(),checks=re.findall(r'(\d+) of (\d+) failed',log),log_sha256=hashlib.sha256(log.encode()).hexdigest(),timeout_seconds=a.timeout,scope='Actual sl_fragment_next/advance, arbitrary unsigned scalar inputs; bounds, exact PB, strictly increasing bounded offset, invalid input atomicity, original deadline preserved; no loops or sequence unwind limit',assumptions=['Valid writable C output objects and cursor; serialized worker access outside this proof'],trusted_base=['CBMC C frontend, solver, C integer semantics'],not_proved=['Worker locking/references/Grant cancellation/USB callbacks','NOCP accuracy/late duplicates/handle reuse','Firmware PB support and real peer delivery'],real_acceptance=False)
a.output.write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record))
raise SystemExit(0 if status=='SCALAR_TRANSITIONS_PASS' else 1)
