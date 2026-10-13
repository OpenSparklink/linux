#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual Runtime ingress route and queue bodies; no kernel or hardware proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_connection_tx import function


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    paths = [net / 'sle_ingress.rs', net / 'sle_dev.rs', here / 'ingress/fixture.rs']
    inputs = {path: path.read_text() for path in paths}
    source = inputs[paths[0]]
    names = ['publish_runtime', 'unpublish_runtime', 'ingress_owner', 'drain_runtime_events',
             'drain_events_for', 'take_dropped_stats', 'enqueue_rx', 'enqueue_command']
    bodies = '\n'.join(function(source, name) for name in names)
    identity = re.search(r'pub\(crate\) struct DeviceIdentity \{[^}]+\}', inputs[paths[1]]).group()
    stats = re.search(r'pub\(crate\) struct RxDropStats \{[^}]+\}', source).group()
    fixture = inputs[paths[2]].replace('// @@FUNCTIONS@@', bodies).replace('// @@IDENTITY@@', identity).replace('// @@STATS@@', stats)
    with tempfile.TemporaryDirectory(prefix='sparklink-runtime-ingress-') as directory:
        root = Path(directory)
        rust = root / 'actual.rs'
        rust.write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings', str(rust), '-o', str(root / 'actual')], check=True)
        text = subprocess.check_output([str(root / 'actual'), '--test-threads=1'], text=True)
    assert all(path.read_text() == text for path, text in inputs.items())
    assert 'test result: ok. 8 passed; 0 failed' in text
    record = {'status': 'ACTUAL_RUNTIME_INGRESS_PASS', 'tests': 8,
              'scope': 'production route/queue functions and identity; std Mutex/Arc with ranked guard checks, Host admission/receive and event/queue dependency fixtures; not kernel IRQ/workqueue/module/Host or hardware refinement',
              'sources': {str(p.relative_to(here.parents[3])): hashlib.sha256(s.encode()).hexdigest() for p, s in inputs.items()},
              'actual_function_sha256': hashlib.sha256(bodies.encode()).hexdigest(), 'hardware_acceptance': False}
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
