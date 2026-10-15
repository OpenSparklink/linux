#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test actual staged per-connection relay transitions; no devices or RF."""
import argparse
import hashlib
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path)
parser.add_argument('--kani', action='store_true', help='verify the same staged source in a private mirrored tree')
parser.add_argument('--timeout', type=int, default=300, help='formal tool seconds; timeout is NOT_PROVEN')
args = parser.parse_args()
paths = [root / 'net/sparklink/sle_security_relay_state.rs', here / 'security/relay_session.rs']
if args.kani:
    paths.append(here / 'security/relay_session_kani.rs')
originals = {p: p.read_bytes() for p in paths}
with tempfile.TemporaryDirectory(prefix='sparklink-relay-session-') as directory:
    binary = str(Path(directory) / 'regression')
    subprocess.run(['rustc', '--edition=2024', '--test', '-Dwarnings', str(paths[1]), '-o', binary], check=True)
    regression=subprocess.run([binary],check=True,text=True,capture_output=True)
    print(regression.stdout,end="")
    counts=re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",regression.stdout)
    if len(counts)!=1 or int(counts[0])==0:raise ValueError("complete nonempty regression verdict required")
    test_count=int(counts[0])
    formal = None
    if args.kani:
        mirror = Path(directory) / 'linux'
        for path, contents in originals.items():
            target = mirror / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
        model = mirror / paths[-1].relative_to(root)
        command = ['kani', str(model)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
            log = stdout + stderr
            status = 'BOUNDED_PASS' if process.returncode == 0 else 'NOT_PROVEN'
            if 'unsupported' in log.lower():
                status = 'NOT_PROVEN_UNSUPPORTED'
            formal = dict(status=status, exit=process.returncode,
                          generated_checks=[int(n) for n in re.findall(r'0 of (\d+) failed', log)],
                          command=['kani', str(paths[-1].relative_to(root))],
                          log_sha256=hashlib.sha256(log.encode()).hexdigest(),
                          version=subprocess.check_output(['kani', '--version'], text=True).strip())
        except subprocess.TimeoutExpired:
            # Stop the verifier's whole process group, including solver/compiler.
            # A timed-out parent must not leave an untracked verification run.
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            log = stdout + stderr
            formal = dict(status='NOT_PROVEN_TIMEOUT', timeout=args.timeout,
                          log_sha256=hashlib.sha256(log.encode()).hexdigest())
        if args.output:
            args.output.with_suffix('.kani.log').write_text(log)
assert all(p.read_bytes() == data for p, data in originals.items())
record = dict(status='PRODUCTION_RELAY_SESSION_REGRESSION_PASS', tests=test_count,
              default_kernel_implementation=True, rf_acceptance=False,
              rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
              sources={str(p.relative_to(root)): hashlib.sha256(data).hexdigest() for p, data in originals.items()})
if formal is not None:
    record['formal'] = formal
    record['regression_status'] = 'PASS'
    if formal['status'] != 'BOUNDED_PASS':
        record['status'] = 'PRODUCTION_RELAY_SESSION_FORMAL_NOT_PROVEN'
if args.output:
    args.output.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
if formal is not None and formal['status'] != 'BOUNDED_PASS':
    raise SystemExit(1)
