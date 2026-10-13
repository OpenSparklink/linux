#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual common standard provider adapter with controlled registration and USB calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(output):
    here = Path(__file__).resolve().parent
    source = here.parents[3]/'drivers/sparklink/standard_usb.c'
    header = here.parents[3]/'include/linux/sparklink_usb.h'
    original = source.read_text()
    definitions = header.read_text()
    fixture = (here/'standard_provider_fixture.c').read_text()
    start = definitions.index('struct sle_usb_capabilities {')
    end = definitions.index('int sle_usb_dev_register(', start)
    fixture = fixture.replace('/* @@METADATA@@ */', definitions[start:end])
    fixture = fixture.replace('/* @@ADAPTER@@ */', original[original.index('static void sle_usb_provider_get'):original.index('/* Hardware binding is driver-owned.')])
    with tempfile.TemporaryDirectory(prefix='sparklink-common-standard-provider-', dir=here) as temporary:
        path = Path(temporary)
        (path/'actual.c').write_text(fixture)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11','-I'+str(here.parents[3]/'include'), '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(path/'actual.c'), '-o', str(path/'test')], check=True)
        data = json.loads(subprocess.check_output([str(path/'test')], text=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')))
    assert data['cases'] == 14 and source.read_text() == original and header.read_text() == definitions
    record = dict(status=data['status'], cases=data['cases'], source_sha256=hashlib.sha256(original.encode()).hexdigest(), header_sha256=hashlib.sha256(definitions.encode()).hexdigest(), scope='Actual standard provider adapter including ops table, metadata descriptor/borrowed identity, query validation, retained get/put and exact open/partial-failure close. Primitive locks/getter/USB/register dependencies controlled; no real Core/URB/module/refcount/IRQ/lifetime or physical standard qualification.', physical_acceptance=False)
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
