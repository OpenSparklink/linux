#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual WS73 query and USB exact-reply helper; explicit dependencies, no USB."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from run_connection_tx import function


def run(output, artifacts):
    if output:
        output.write_text(json.dumps(dict(status='RUNNING_NOT_QUALIFIED',
                                         completed=False)) + '\n')
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    source = root / 'drivers/sparklink/ws73/usb.c'
    usb_core = root / 'drivers/usb/core/message.c'
    fixture = here / 'ws73-runtime-rx/hcc_memory_fixture.c'
    paths = [source, usb_core, fixture, Path(__file__).resolve(),
             here / 'run_connection_tx.py', here / 'usb_source_paths.py']
    originals = {p: p.read_bytes() for p in paths}
    text = originals[source].decode()
    start = text.index('struct ws73_hcc_memory_observation {')
    definition = text[start:text.index('};', start) + 2]
    query = function(text.replace('static int ws73_hcc_memory_query(',
                                  'int ws73_hcc_memory_query(', 1),
                     'ws73_hcc_memory_query').replace(
                         'int ws73_hcc_memory_query(',
                         'static int ws73_hcc_memory_query(', 1)
    assert query in text
    helper = function(originals[usb_core].decode(), 'usb_control_msg_recv')
    code = originals[fixture].decode().replace('/* @@OBSERVATION@@ */', definition)
    code = code.replace('/* @@USB_HELPER@@ */', helper).replace('/* @@QUERY@@ */', query)
    assert 'static DEVICE_ATTR(hcc_memory_observation, 0400,' in text
    compiler = os.environ.get('CC', 'clang')
    if artifacts:
        artifacts.mkdir(parents=True, exist_ok=False)
    negative = []
    with tempfile.TemporaryDirectory(prefix='ws73-hcc-memory-') as directory:
        temp = Path(directory)
        actual, binary = temp / 'actual.c', temp / 'test'
        actual.write_text(code)
        command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                   str(actual), '-o', str(binary)]
        subprocess.run(command, check=True)
        reply = subprocess.check_output([str(binary)], text=True, timeout=10,
                                        env=dict(os.environ,
                                                 ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                                 UBSAN_OPTIONS='halt_on_error=1'))
        result = json.loads(reply)
        assert result == dict(status='WS73_HCC_MEMORY_QUERY_FUNCTIONS_PASS', cases=28)
        binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        if artifacts:
            shutil.copy2(actual, artifacts / 'actual.c')
            shutil.copy2(binary, artifacts / 'test')
        stale_guard = ('\tif (READ_ONCE(ws->stopping) || READ_ONCE(ws->broken) ||\n'
                       '\t    !READ_ONCE(ws->streaming) || !smp_load_acquire(&ws->metadata_valid) ||\n'
                       '\t    ws->native_id != candidate.id ||\n'
                       '\t    ws->native_generation != candidate.generation)')
        assert code.count(stale_guard) == 1
        mutations = {
            'stale-reply-published': code.replace(stale_guard, '\tif (false)', 1),
            'short-response-accepted': code.replace('if (ret == size)', 'if (ret >= 0)', 1),
            'known-word-replaced-with-zero': code.replace(
                '\t*out = candidate;', '\tcandidate.raw_le32 = 0;\n\t*out = candidate;', 1),
            'wrong-class-request': code.replace('ws->udev, 0, 5,', 'ws->udev, 0, 6,', 1),
            'successful-query-lock-not-released': code.replace(
                '\tmutex_unlock(&ws->phase_lock);',
                '\tif (ret)\n\t\tmutex_unlock(&ws->phase_lock);', 1),
        }
        for name, changed in mutations.items():
            assert changed != code
            actual.write_text(changed)
            subprocess.run(command, check=True)
            child = subprocess.run([str(binary)], text=True, timeout=10, capture_output=True,
                                   env=dict(os.environ,
                                            ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                            UBSAN_OPTIONS='halt_on_error=1'))
            assert child.returncode == -6 and 'Assertion' in child.stderr, (
                name, child.returncode, child.stderr)
            if artifacts:
                shutil.copy2(actual, artifacts / (name + '.c'))
                shutil.copy2(binary, artifacts / (name + '.bin'))
                (artifacts / (name + '.stderr')).write_text(child.stderr)
            negative.append(dict(case=name, rejected=True,
                                 method='COMPILED_MUTATION_ASSERTION_ABORT',
                                 stderr_sha256=hashlib.sha256(child.stderr.encode()).hexdigest()))
    assert all(p.read_bytes() == content for p, content in originals.items())
    result.update(completed=True, negative_controls=negative,
                  sources={str(p.relative_to(root)): hashlib.sha256(content).hexdigest()
                           for p, content in originals.items()},
                  generated_source_sha256=hashlib.sha256(code.encode()).hexdigest(),
                  test_binary_sha256=binary_sha,
                  compiler=subprocess.check_output([compiler, '--version'], text=True),
                  scope='Actual WS73 query and USB core exact-response helper. '
                        'Raw USB, allocation, clock, mutex/access-order and state '
                        'changes are explicit programmable single-thread fixtures. '
                        'Not real USB, firmware support/counter semantics, kernel '
                        'concurrency, attribute/ref drain, protocol credit, '
                        'Ready, peer delivery, recovery or formal proof.',
                  physical_acceptance=False, formal_proof=False)
    if output:
        output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    run(args.output, args.artifacts)
