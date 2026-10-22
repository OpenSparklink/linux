#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production WS73 file selection/validation/boot with explicit fault fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from run_native_ticket_driver import function


def table(source, name):
    end = source.index('\n};', source.index(name + '[')) + 3
    start = source.rfind('\nstatic ', 0, source.index(name + '[')) + 1
    return source[start:end]


def run(output):
    here = Path(__file__).resolve().parent
    driver = here.parents[3] / 'drivers/sparklink/ws73'
    paths = [driver / n for n in ['usb.c', 'fw_profile.c', 'fw_profile.h', 'recovery.h']]
    paths += [here / 'firmware/profile_driver_fixture.c', Path(__file__).resolve()]
    inputs = {p: p.read_bytes() for p in paths}
    source = inputs[paths[0]].decode()
    bodies = '\n'.join(function(source, n) for n in
                       ['ws73_validate_image', 'ws73_profile_load', 'ws73_profile_file', 'ws73_boot_work'])
    defines = '\n'.join(re.search(r'^#define ' + n + r'\s+.*$', source, re.M)[0]
                        for n in ['WS73_FW_HEADER', 'WS73_FW_MAX'])
    tables = '\n'.join(table(source, n) for n in ['ws73_images', 'ws73_profile_names', 'ws73_cali_banks'])
    fixture = inputs[here / 'firmware/profile_driver_fixture.c'].decode()
    fixture = fixture.replace('/* @@DEFINES@@ */', defines).replace('/* @@TABLES@@ */', tables)
    fixture = fixture.replace('/* @@ACTUAL@@ */', bodies)
    start = source.index('enum ws73_stage {')
    fixture = fixture.replace('/* @@STAGES@@ */', source[start:source.index('\n};', start)+3])
    with tempfile.TemporaryDirectory(prefix='ws73-input-profile-') as directory:
        root = Path(directory)
        (root / 'actual.c').write_text(fixture)
        command = [os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g', '-I'+str(driver),
                   str(root / 'actual.c'), str(driver / 'fw_profile.c'), '-lcrypto', '-o', str(root / 'test')]
        subprocess.run(command, check=True)
        result = subprocess.run([str(root / 'test')], capture_output=True, text=True,
                                env=os.environ | {'ASAN_OPTIONS': 'detect_leaks=1:abort_on_error=1',
                                                  'UBSAN_OPTIONS': 'halt_on_error=1'})
        print(result.stdout, end='')
        if result.returncode:
            raise RuntimeError('actual fixture failed: ' + result.stderr)
        match = re.fullmatch(r'WS73 actual profile/boot fault fixture: ([1-9][0-9]*) cases passed;all references released\n', result.stdout)
        if not match or result.stderr:
            raise ValueError('complete clean fixture receipt required')
    assert all(p.read_bytes() == raw for p, raw in inputs.items())
    record = dict(status='ACTUAL_WS73_PROFILE_BOOT_FAILURE_FIXTURE_PASS', cases=int(match[1]),
                  sources={str(p.relative_to(here.parents[3])): hashlib.sha256(raw).hexdigest() for p, raw in inputs.items()},
                  production_bodies_sha256=hashlib.sha256(bodies.encode()).hexdigest(),
                  scope='Actual profile/file/boot bodies and production pure decoder;filesystem/alloc/mutex/clock/USB dependencies visible in fixture. Inject missing/malformed/changed inputs, allocation, every boot command/download failure, short read and upload budget. No real kernel concurrency,callback/drain,HCC publication,upload or hardware qualification.',
                  physical_acceptance=False, natural_recovery=False)
    if output:
        output.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
