#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual Session immediate/fallback enqueue functions with visible API fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


def check_cbmc(directory, fixture, bodies, harness):
    directory.mkdir()
    report = dict(status='RUNNING_NOT_PROVEN', bound=20, runs=[],
                  scope='Actual C enqueue bodies with explicit sequential Linux API dependencies;not kernel implementation,concurrency,drain,unbounded or RF proof.')
    path = directory / 'report.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    try:
        report['tool'] = subprocess.check_output(['cbmc', '--version'], text=True).strip()
        variants = [('production', bodies),
                    ('inverted-queue-reference-negative', bodies.replace('if (mod_delayed_work(', 'if (!mod_delayed_work(')),
                    ('short-unwind-negative', bodies)]
        assert variants[0][1] != variants[1][1]
        for kind, body in variants:
            source = directory / (kind + '.c')
            source.write_text(fixture.replace('/* @@FUNCTIONS@@ */', body) + harness)
            command = ['cbmc', str(source), '--function', 'verify_wake_sequences', '--unwind',
                       '5' if kind == 'short-unwind-negative' else '21',
                       '--unwinding-assertions', '--bounds-check', '--pointer-check', '--pointer-overflow-check',
                       '--signed-overflow-check', '--unsigned-overflow-check', '--json-ui', '--trace']
            start = time.time_ns()
            raw_path = directory / (kind + '.json')
            with raw_path.open('x') as stream:
                process = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            raw = json.loads(raw_path.read_text())
            properties = [p for item in raw for p in item.get('result', [])]
            statuses = {p.get('status') for p in properties}
            terminal = [item['cProverStatus'] for item in raw if 'cProverStatus' in item]
            diagnostics = [item for item in raw if item.get('messageType') in ('WARNING', 'ERROR')]
            expected = {'one reference per queued/running invocation', 'closed rejects new queue',
                        'event never postponed beyond fallback', 'close/cancel/finish settle queue refs'}
            assert expected <= {p.get('description') for p in properties}
            row = dict(kind=kind, exit=process.returncode, property_count=len(properties),
                       statuses=sorted(statuses), terminal=terminal, diagnostics=diagnostics,
                       source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                       raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(),
                       elapsed_ns=time.time_ns() - start, command=command)
            report['runs'].append(row)
            assert not diagnostics, diagnostics
            if kind == 'production':
                assert process.returncode == 0 and terminal == ['success'] and statuses == {'SUCCESS'}
            else:
                failed = [p for p in properties if p['status'] == 'FAILURE']
                assert process.returncode == 10 and terminal == ['failure']
                if kind == 'short-unwind-negative':
                    # A statically completed loop need not emit an unwind
                    # property. Deliberately insufficient expansion MUST fail.
                    assert any('unwind' in p['property'] for p in failed)
                else:
                    assert any(p['description'] == 'one reference per queued/running invocation' for p in failed)
        report['status'] = 'BOUNDED_PRODUCTION_ENQUEUE_DEPENDENCY_CONTRACT_PASS'
    except BaseException as error:
        report.update(status='UNPROVED', error=str(error), error_type=type(error).__name__)
        raise
    finally:
        path.write_text(json.dumps(report, indent=2) + '\n')
    return report


def function(source, name):
    match = re.search(r'^(?:static )?void ' + name + r'\([^;{]*\)\s*\{', source, re.M)
    if not match:
        raise ValueError('missing production function: ' + name)
    i, depth = match.end(), 1
    while depth:
        depth += (source[i] == '{') - (source[i] == '}')
        i += 1
    return source[match.start():i]


def run(output, cbmc_output=None):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    paths = [root / 'net/sparklink/sle_channel_socket.c', here / 'session/wake_fixture.c']
    if cbmc_output:
        paths.append(here / 'session/wake_cbmc.c')
    originals = {p: p.read_bytes() for p in paths}
    source = originals[paths[0]].decode()
    bodies = '\n'.join(function(source, name) for name in ['sl_schedule', 'sl_connection_session_kick'])
    fixture = originals[paths[1]].decode().replace('/* @@FUNCTIONS@@ */', bodies)
    if output and output.exists():
        raise ValueError('do not overwrite evidence')
    with tempfile.TemporaryDirectory(prefix='sparklink-session-wake-') as directory:
        tmp = Path(directory)
        (tmp / 'test.c').write_text(fixture)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-g', str(tmp / 'test.c'), '-o', str(tmp / 'test')], check=True)
        subprocess.run([str(tmp / 'test')], check=True,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
    formal = check_cbmc(cbmc_output, originals[paths[1]].decode(), bodies,
                        originals[paths[2]].decode()) if cbmc_output else None
    assert all(p.read_bytes() == data for p, data in originals.items())
    report = dict(status='ACTUAL_SESSION_WAKE_SEQUENTIAL_DEPENDENCIES_PASS',
                  scope='Actual C enqueue bodies;explicit single-thread workqueue/spinlock/kref API dependencies. Pending coalescence,running requeue,earlier event not postponed,closed admission,queue ref settlement. Not Linux workqueue correctness,concurrent callback UAF,formal or real-device qualification.',
                  production_bodies_sha256=hashlib.sha256(bodies.encode()).hexdigest(),
                  sources={str(p.relative_to(root)): hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  compiler=subprocess.check_output([os.environ.get('CC', 'clang'), '--version'], text=True).splitlines()[0],
                  remaining=['Separate original-deadline scheduling and remove periodic fallback.',
                             'Runtime event/Session notification interleavings,actual VM drain/close/credit recovery.',
                             'Production-mapped LKMM/TLC and unchanged-config real WS73 comparison.'])
    if formal:
        report['cbmc'] = formal
    if output:
        output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cbmc-output', type=Path, help='new private directory;20-step actual-body dependency proof plus negative;unsupported/timeout remain UNPROVED')
    args = parser.parse_args()
    run(args.output, args.cbmc_output)
