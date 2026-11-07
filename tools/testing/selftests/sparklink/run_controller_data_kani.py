#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify the exact production ControllerData envelope predicate, not RF/Host."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
from run_connection_tx import function


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    args = parser.parse_args()
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    source = root / 'net/sparklink/sle_native.rs'
    harness = here / 'security/controller_data_kani.rs'
    originals = {p: p.read_bytes() for p in [source, harness]}
    body = function(originals[source].decode(), 'native_controller_data_valid')
    model = originals[harness].decode().replace('// @@CONTROLLER_DATA@@', body)
    command = ['kani', 'controller_data_kani.rs']
    version = subprocess.check_output(['kani', '--version'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='sparklink-controller-data-kani-') as directory:
        Path(directory, command[1]).write_text(model)
        process = subprocess.Popen(command, cwd=directory, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
            log = stdout + stderr
            status = 'BOUNDED_PASS' if process.returncode == 0 else 'NOT_PROVEN'
            if 'unsupported' in log.lower():
                status = 'NOT_PROVEN_UNSUPPORTED'
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            log = stdout + stderr
            status = 'NOT_PROVEN_TIMEOUT'
    assert all(p.read_bytes() == content for p, content in originals.items())
    args.output.with_suffix('.kani.log').write_text(log)
    record = dict(status=status, exit=process.returncode, timeout=args.timeout,
                  source_head=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                  source_tree_clean=not subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True).strip(),
                  sources={str(p.relative_to(root)): hashlib.sha256(v).hexdigest() for p, v in originals.items()},
                  body_sha256=hashlib.sha256(body.encode()).hexdigest(),
                  model_sha256=hashlib.sha256(model.encode()).hexdigest(),
                  log_sha256=hashlib.sha256(log.encode()).hexdigest(), version=version, command=command,
                  generated_checks=[int(n) for n in re.findall(r'0 of (\d+) failed', log)],
                  scope='Exact production predicate, arbitrary bytes[265], slice length 0..265, unwind270; length/12bit handle/u8 payload consistency and memory safety',
                  assumptions=['Rust valid borrowed slice; firmware input modeled as arbitrary bytes, not trusted',
                               'Lengths >265 rejected by predicate before reads but outside this bounded model'],
                  rf_acceptance=False, whole_security_proof=False, whole_receive_callback_proof=False)
    args.output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))
    if status != 'BOUNDED_PASS':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
