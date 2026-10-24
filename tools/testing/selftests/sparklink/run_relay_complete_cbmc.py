#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded proof of the actual SDK111 Complete validator, with old-source counterexample."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile


def run(output, timeout, baseline, kind='complete'):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    driver = root / 'drivers/sparklink/ws73'
    harness = here / ('security/relay_' + kind + '_cbmc.c')
    paths = [driver / 'dli.c', *sorted(driver.glob('*.h')), harness]
    originals = {p: p.read_bytes() for p in paths}
    source = originals[driver / 'dli.c']
    if baseline:
        source = subprocess.check_output(['git', '-C', str(root), 'show',
                                          baseline + ':drivers/sparklink/ws73/dli.c'])
    with tempfile.TemporaryDirectory(prefix='sparklink-relay-complete-') as directory:
        tmp = Path(directory)
        for p in paths[:-1]:
            (tmp / p.name).write_bytes(source if p.name == 'dli.c' else originals[p])
        (tmp / 'probe.c').write_text(originals[harness].decode().replace(
            '../../../../../drivers/sparklink/ws73/dli.c', 'dli.c'))
        command = ['cbmc', 'probe.c', '--function', 'main', '--unwind', '266',
                   '--unwinding-assertions', '--bounds-check', '--pointer-check',
                   '--signed-overflow-check', '--unsigned-overflow-check', '--conversion-check', '--trace']
        process = subprocess.Popen(command, cwd=tmp, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, start_new_session=True)
        timed_out = False
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process_group = process.pid
            os.killpg(process_group, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process_group, signal.SIGKILL)
                stdout, stderr = process.communicate()
        log = stdout + stderr
    limited = bool(re.search(r'unsupported|not supported|warning:|: UNKNOWN\b', log, re.I))
    if timed_out:
        status = 'NOT_PROVEN_TIMEOUT'
    elif limited:
        status = 'NOT_PROVEN_TOOL_LIMITATION'
    elif baseline and process.returncode == 10 and 'VERIFICATION FAILED' in log:
        status = 'EXPECTED_OLD_SOURCE_COUNTEREXAMPLE'
    elif not baseline and process.returncode == 0 and 'VERIFICATION SUCCESSFUL' in log and ': FAILURE' not in log:
        status = 'BOUNDED_PASS'
    else:
        status = 'NOT_PROVEN'
    assert all(p.read_bytes() == data for p, data in originals.items())
    output.with_suffix('.cbmc.log').write_text(log)
    record = {'status': status, 'exit': process.returncode, 'timeout_seconds': timeout,
              'source_head': subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
              'baseline': baseline, 'validator_sha256': hashlib.sha256(source).hexdigest(),
              'sources': {str(p.relative_to(root)): hashlib.sha256(data).hexdigest() for p, data in originals.items()},
              'tool_version': subprocess.check_output(['cbmc', '--version'], text=True).strip(),
              'command': command, 'log_sha256': hashlib.sha256(log.encode()).hexdigest(),
              'generated_checks': re.findall(r'(\d+) of (\d+) failed', log),
              'scope': ('Actual production ws73_dli_validate_reply: memory safety for arbitrary allocated bytes[265]/length0..265, successful1812 exact13-byte frame/handle12bit; no second parser' if kind == 'complete' else
                        'Actual production relay prepare/RX normalization: bytes265/length0..265, handle/index0..65535, payload/capacity0..255; mapping, frozen wire echo, byte preservation and failure atomicity; no second codec'),
              'assumptions': ['Valid allocated C packet object; actual lifetime/generation/locks/USB/firmware outside this harness',
                              'Lengths beyond265 outside this bounded model; packet contents are not trusted'],
              'trusted_base': ['CBMC C front-end/solver and C semantics; not a proof of Linux, firmware or hardware'],
              'implementation_regression': 'Real K9806 VM counterexample plus ws73_dli_test and actual Host echo mismatch tests',
              'rf_acceptance': False, 'whole_security_proof': False}
    output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return status in ['BOUNDED_PASS', 'EXPECTED_OLD_SOURCE_COUNTEREXAMPLE']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=300)
    parser.add_argument('--baseline', help='Replay an actual old committed validator; require a counterexample')
    parser.add_argument('--kind', choices=['complete', 'index'], default='complete')
    args = parser.parse_args()
    if args.baseline and args.kind != 'complete':
        parser.error('Old-source counterexample replay applies only to the Complete harness')
    raise SystemExit(0 if run(args.output, args.timeout, args.baseline, args.kind) else 1)
