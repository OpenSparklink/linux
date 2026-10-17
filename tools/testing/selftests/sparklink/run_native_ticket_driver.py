#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual WS73 ACB ticket/URB functions and wire codec with explicit fault dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name):
    match = re.search(r'^static (?:int|void) '+name+r'\([^;{]*\)\s*\{', text, re.M)
    assert match, name
    i = match.end()
    depth = 1
    while depth:
        depth += (text[i] == '{') - (text[i] == '}')
        i += 1
    return text[match.start():i]


def run(output, command=False):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    driver = root / 'drivers/sparklink/ws73'
    files = [driver / 'usb.c', driver / 'wire.c', driver / 'wire.h', here / ('native-ticket/command_driver_fixture.c' if command else 'native-ticket/driver_fixture.c')]
    if command:files += [driver/'dli.c',driver/'dli.h']
    fixture_file=here / ('native-ticket/command_driver_fixture.c' if command else 'native-ticket/driver_fixture.c')
    inputs = {p: p.read_bytes() for p in files}
    source = inputs[files[0]].decode()
    start = source.index('struct ws73_acb_transfer {')
    end = source.index('\n};', start) + 3
    code = source[start:end] + '\n' + '\n'.join(function(source, name) for name in
        (['ws73_acb_complete', 'ws73_acb_submit', 'ws73_native_command'] if command else
         ['ws73_acb_complete', 'ws73_acb_submit', 'ws73_native_acb_fragment', 'ws73_native_acb']))
    defines = '\n'.join(re.search(r'^#define '+name+r'\s+.*$', source, re.M)[0]
                        for name in ['WS73_FW_CHUNK', 'WS73_TX_TIMEOUT'])
    fixture = inputs[fixture_file].decode().replace('/* @@DEFINES@@ */', defines).replace('/* @@DRIVER@@ */', code)
    with tempfile.TemporaryDirectory(prefix='sparklink-ticket-driver-') as directory:
        tmp = Path(directory)
        (tmp / 'test.c').write_text(fixture)
        compile_command = [os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                   '-I'+str(driver), str(tmp/'test.c'), str(driver/'wire.c'), *([str(driver/'dli.c')] if command else []), '-o', str(tmp/'test')]
        subprocess.run(compile_command, check=True)
        subprocess.run([str(tmp/'test')], check=True,
                       env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
    assert all(p.read_bytes() == b for p, b in inputs.items())
    result = {'status': 'WS73_ACTUAL_COMMAND_TICKET_DRIVER_FAULTS_PASS' if command else 'WS73_ACTUAL_TICKET_DRIVER_FAULTS_PASS', 'cases': 21 if command else 11,
              'scope': 'actual C preparation/atomic submit/completion/finite wait/kill/join bodies + wire codec; USB/lock/time are explicit dependencies',
              'physical_acceptance': False, 'whole_ticket_proof': False,
              'production_bodies_sha256': hashlib.sha256(code.encode()).hexdigest(),
              'sources': {str(p.relative_to(root)): hashlib.sha256(b).hexdigest() for p,b in inputs.items()}}
    if output: output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--command', action='store_true', help='exercise actual command ticket bodies instead of ACB')
    args = parser.parse_args()
    run(args.output, args.command)
