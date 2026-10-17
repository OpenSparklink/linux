#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded CBMC checks of the actual software TX service budget and negatives.

Not a protocol-credit, concurrency, scheduler, firmware or WCET proof. Monotonic
elapsed <=48ms; absolute uint64 clock wraps modulo by design. Accepted byte sums
are checked explicitly for nonwrap instead of banning deliberate clock wrap.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time


def run(output):
    if not __debug__:
        raise RuntimeError('optimized verification forbidden')
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    header = root / 'net/sparklink/sle_tx_budget.h'
    harness = here / 'session/tx_budget_cbmc.c'
    inputs = {p: p.read_bytes() for p in [header, harness, Path(__file__).resolve()]}
    output.mkdir()
    path = output / 'report.json'
    report = dict(status='RUNNING_NOT_PROVEN', runs=[],
                  scope=__doc__, bounds=dict(transitions=12, maximum_elapsed_ns=48000000),
                  assumptions=['Sequential pure helper; no concurrent mutation',
                               'uint64 monotonic clock modulo; elapsed advances 0..4ms per call',
                               'No claim about synchronous USB call duration or real scheduler fairness'],
                  sources={str(p.relative_to(root)): hashlib.sha256(b).hexdigest()
                           for p, b in inputs.items()})
    path.write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['tool_version'] = subprocess.check_output(['cbmc', '--version'], text=True).strip()
        original = inputs[header].decode()
        variants = {
            'production': original,
            'packet-negative': original.replace('b->packets >= SL_TX_QUANTUM_PACKETS',
                                                 'b->packets > SL_TX_QUANTUM_PACKETS'),
            'byte-negative': original.replace('length > SL_TX_QUANTUM_BYTES - b->bytes', 'false'),
            'latch-negative': original.replace('if (b->stop != SL_TX_BUDGET_NONE)', 'if (false)'),
            'elapsed-negative': original.replace('now - b->start_ns >= SL_TX_QUANTUM_NS',
                                                  'now - b->start_ns > SL_TX_QUANTUM_NS'),
            'short-unwind-negative': original,
        }
        required = {'initial empty budget', 'origin never refreshed', 'finite counters',
                    'accepted only inside original service limits', 'exact accepted accounting',
                    'rejection preserves accounting', 'stop is latched',
                    'new quantum starts empty', 'exact deadline denies next operation'}
        for name, source in variants.items():
            folder = output / name
            folder.mkdir()
            (folder / header.name).write_text(source)
            (folder / 'harness.c').write_bytes(inputs[harness])
            command = ['cbmc', str(folder / 'harness.c'), '-I', str(folder),
                       '--function', 'verify_tx_budget', '--unwind',
                       '2' if name == 'short-unwind-negative' else '13',
                       '--unwinding-assertions', '--bounds-check', '--pointer-check',
                       '--signed-overflow-check', '--json-ui', '--trace']
            raw = folder / 'raw.json'
            started = time.time_ns()
            with raw.open('x') as stream:
                done = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
            rows = json.loads(raw.read_text())
            props = [p for row in rows for p in row.get('result', [])]
            terminal = [row['cProverStatus'] for row in rows if 'cProverStatus' in row]
            diagnostics = [row for row in rows if row.get('messageType') in ['ERROR', 'WARNING']]
            report['runs'].append(dict(kind=name, exit=done.returncode, property_count=len(props),
                                      terminal=terminal, command=command, diagnostics=diagnostics,
                                      statuses=sorted({p['status'] for p in props}),
                                      elapsed_ns=time.time_ns() - started,
                                      raw_sha256=hashlib.sha256(raw.read_bytes()).hexdigest()))
            assert not diagnostics, diagnostics
            assert required <= {p.get('description') for p in props}
            if name == 'production':
                assert done.returncode == 0 and terminal == ['success']
                assert props and all(p['status'] == 'SUCCESS' for p in props)
            else:
                assert done.returncode == 10 and terminal == ['failure']
                assert any(p['status'] == 'FAILURE' and
                           ('unwind' in p['property'] if name == 'short-unwind-negative'
                            else p['description'] in required) for p in props)
            path.write_text(json.dumps(report, indent=2) + '\n')
        assert all(p.read_bytes() == b for p, b in inputs.items())
        report['status'] = 'BOUNDED_PRODUCTION_TX_BUDGET_AND_NEGATIVES_PASS'
    except BaseException as error:
        report.update(status='UNPROVED', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        path.write_text(json.dumps(report, indent=2) + '\n')
    print(report['status'])


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    run(p.parse_args().output)
