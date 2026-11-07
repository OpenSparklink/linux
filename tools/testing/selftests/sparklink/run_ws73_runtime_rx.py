#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual WS73 RX/open/close functions; explicit dependencies, not USB proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

from run_connection_tx import function


def run(output, artifacts=None):
    if output:
        # A prior PASS must not survive a failed compiler, detector or child.
        output.write_text(json.dumps(dict(status='RUNNING_NOT_QUALIFIED',
                                         completed=False,
                                         started_ns=time.time_ns())) + '\n')
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    driver = root / 'drivers/sparklink/ws73'
    paths = [driver / 'usb.c', driver / 'wire.c', driver / 'wire.h',
             here / 'ws73-runtime-rx/fixture.c', Path(__file__).resolve(),
             here / 'run_connection_tx.py']
    originals = {p: p.read_bytes() for p in paths}
    source = originals[driver / 'usb.c'].decode()
    names = ['ws73_native_close', 'ws73_native_rx_complete', 'ws73_native_open']
    # Normalize only the declaration for the existing extractor. The original
    # body is inserted verbatim, including all error/stop/rearm decisions.
    bodies = []
    for name in names:
        result_type = 'int' if name.endswith('_open') else 'void'
        text = source.replace('static ' + result_type + ' ' + name + '(',
                              'int ' + name + '(', 1)
        body = function(text, name)
        body = body.replace('int ' + name + '(',
                            'static ' + result_type + ' ' + name + '(', 1)
        assert body in source, 'extracted body differs from production: ' + name
        bodies.append(body)
    fixture = originals[here / 'ws73-runtime-rx/fixture.c'].decode()
    assert fixture.count('/* @@PRODUCTION@@ */') == 1
    actual = fixture.replace('/* @@PRODUCTION@@ */', '\n\n'.join(bodies))
    compiler = os.environ.get('CC', 'clang')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g']
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
    negative = []
    retained = {}
    if artifacts:
        artifacts.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='ws73-runtime-rx-') as directory:
        temp = Path(directory)
        code, binary = temp / 'actual.c', temp / 'test'
        code.write_text(actual)
        command = [compiler, *flags, '-I', str(driver), str(code),
                   str(driver / 'wire.c'), '-o', str(binary)]
        subprocess.run(command, check=True)
        text = subprocess.check_output([str(binary)], text=True,
                                       env=environment, timeout=10)
        generated_sha256 = hashlib.sha256(code.read_bytes()).hexdigest()
        binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
        if artifacts:
            for path, name in [(code, 'actual.c'), (binary, 'test')]:
                shutil.copyfile(path, artifacts / name)
                retained[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        guard = '\tif (!READ_ONCE(ws->streaming) || READ_ONCE(ws->stopping))\n\t\treturn;'
        assert actual.count(guard) == 2
        mutations = {
            'panic-ignored': actual.replace(
                'get_unaligned_le32(ws->notification) & BIT(6)',
                'get_unaligned_le32(ws->notification) & 0', 1),
            'short-notification-accepted': actual.replace(
                'urb->actual_length != sizeof(ws->notification))\n\t\t\tret = -EPROTO;',
                'urb->actual_length != sizeof(ws->notification))\n\t\t\tret = 0;', 1),
            'retired-consumer-treated-as-fault': actual.replace(
                'if (ret == -ENODEV)', 'if (ret == -EOPNOTSUPP)', 1),
            'stop-before-rearm-ignored': ''.join(actual.rsplit(guard, 1)),
            'partial-open-drain-skipped': actual.replace(
                '\tusb_kill_urb(ws->notification_urb);',
                '', 1),
        }
        for name, mutation in mutations.items():
            assert mutation != actual, name
            code.write_text(mutation)
            subprocess.run(command, check=True)
            failed = subprocess.run([str(binary)], text=True, env=environment,
                                    capture_output=True, timeout=10)
            # Compiler failure, sanitizer startup failure, timeout or any
            # arbitrary nonzero exit is not a successful negative control.
            assert failed.returncode == -6 and 'Assertion' in failed.stderr, (
                name, failed.returncode, failed.stderr)
            if artifacts:
                for path, suffix in [(code, '.c'), (binary, '.bin')]:
                    shutil.copyfile(path, artifacts / (name + suffix))
                    retained[name + suffix] = hashlib.sha256(path.read_bytes()).hexdigest()
                (artifacts / (name + '.stderr')).write_text(failed.stderr)
                retained[name + '.stderr'] = hashlib.sha256(failed.stderr.encode()).hexdigest()
            negative.append(dict(case=name, rejected=True,
                                 method='COMPILED_MUTATION_ASSERTION_ABORT',
                                 stderr_sha256=hashlib.sha256(
                                     failed.stderr.encode()).hexdigest()))
    result = json.loads(text)
    assert result == dict(status='WS73_RUNTIME_RX_FUNCTIONS_PASS', cases=33)
    assert all(p.read_bytes() == content for p, content in originals.items())
    result.update(
        completed=True, functions=names, negative_controls=negative,
        generated_source_sha256=generated_sha256,
        compiled_test_sha256=binary_sha256,
        retained_artifacts=retained,
        artifact_access='EXPLICIT_ARTIFACT_DIRECTORY' if artifacts else
                        'NOT_RETAINED_REBUILD_REQUIRED',
        compiled_wire='drivers/sparklink/ws73/wire.c',
        sources={str(p.relative_to(root)): hashlib.sha256(content).hexdigest()
                 for p, content in originals.items()},
        function_body_sha256={name: hashlib.sha256(body.encode()).hexdigest()
                              for name, body in zip(names, bodies)},
        compiler=subprocess.check_output([compiler, '--version'], text=True),
        command=[compiler, *flags, '-I', 'drivers/sparklink/ws73',
                 '<temporary actual.c>', 'drivers/sparklink/ws73/wire.c',
                 '-o', '<temporary test>'],
        fixtures=['single-thread READ_ONCE/WRITE_ONCE', 'allocation and failure',
                  'USB fill/submit/error/kill call recording',
                  'programmable Native consumer/error/stop',
                  'per-object asynchronous-failure observation'],
        scope='Actual unchanged production callback/open/close plus actual HCC '
              'parser. Finite single-thread scenarios and injected dependency '
              'errors only; no USB core execution, worker, scheduler, kernel '
              'memory ordering, reference drain, hardware, firmware/RF, credit '
              'accounting, natural recovery or formal/refinement qualification.',
        physical_acceptance=False, concurrency_acceptance=False,
        formal_proof=False)
    if output:
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--artifacts', type=Path,
                        help='new directory for exact test and mutation artifacts')
    args = parser.parse_args()
    run(args.output, args.artifacts)
