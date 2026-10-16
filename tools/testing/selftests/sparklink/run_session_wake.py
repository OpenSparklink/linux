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


def function(source, name):
    match = re.search(r'^(?:static )?void ' + name + r'\([^;{]*\)\s*\{', source, re.M)
    if not match:
        raise ValueError('missing production function: ' + name)
    i, depth = match.end(), 1
    while depth:
        depth += (source[i] == '{') - (source[i] == '}')
        i += 1
    return source[match.start():i]


def run(output):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    paths = [root / 'net/sparklink/sle_channel_socket.c', here / 'session/wake_fixture.c']
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
    assert all(p.read_bytes() == data for p, data in originals.items())
    report = dict(status='ACTUAL_SESSION_WAKE_SEQUENTIAL_DEPENDENCIES_PASS',
                  scope='Actual C enqueue bodies;explicit single-thread workqueue/spinlock/kref API dependencies. Pending coalescence,running requeue,earlier event not postponed,closed admission,queue ref settlement. Not Linux workqueue correctness,concurrent callback UAF,formal or real-device qualification.',
                  production_bodies_sha256=hashlib.sha256(bodies.encode()).hexdigest(),
                  sources={str(p.relative_to(root)): hashlib.sha256(b).hexdigest() for p, b in originals.items()},
                  compiler=subprocess.check_output([os.environ.get('CC', 'clang'), '--version'], text=True).splitlines()[0],
                  remaining=['Separate original-deadline scheduling and remove periodic fallback.',
                             'Runtime event/Session notification interleavings,actual VM drain/close/credit recovery.',
                             'Production-mapped LKMM/TLC and unchanged-config real WS73 comparison.'])
    if output:
        output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
