#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual legacy USB firmware/prepare/probe source; dependency fixtures, no USB I/O."""
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
    inputs = {n: (net/n).read_text() for n in ['sle_usb_ffi.c', 'sle_fw.rs', 'sle_usb.rs']}
    c = inputs['sle_usb_ffi.c'].replace('static int sle_usb_send_cmd_sync', 'int sle_usb_send_cmd_sync').replace('static int sle_usb_validate_init_reply', 'int sle_usb_validate_init_reply')
    defines = '\n'.join(re.search(r'(?m)^#define '+n+r' .+$', c).group() for n in
                        ['SLE_USB_MAX_DEVS', 'DLI_PKT_COMMAND', 'SLE_EVT_CMD_COMPLETE',
                         'SLE_INIT_TIMEOUT_MS', 'SLE_FW_DATA_MARKER', 'SLE_FW_CHUNK_HDR',
                         'SLE_OP_FW_DL_START', 'SLE_OP_FW_DL_DONE', 'SLE_FW_DEFAULT_CHUNK',
                         'SLE_FW_MAX_SIZE', 'SLE_FW_DL_TIMEOUT_MS'])
    fixture = (here/'firmware/usb_fw_fixture.c').read_text().replace('/* @@DEFINES@@ */', defines)
    for marker, name in [('SYNC', 'sle_usb_send_cmd_sync'), ('VALIDATOR', 'sle_usb_validate_init_reply'),
                         ('DOWNLOAD', 'sle_usb_dev_download_fw')]:
        fixture = fixture.replace('/* @@'+marker+'@@ */', function(c, name))
    rust = (here/'firmware/usb_fw_fixture.rs').read_text()
    loader = function(inputs['sle_fw.rs'], 'load_usb_firmware')
    constants = '\n'.join(re.search(r'(?m)^const '+n+r'.+$', inputs['sle_fw.rs']).group() for n in
                          ['FW_DEFAULT_CHUNK_SIZE', 'FW_MAX_SIZE'])
    rust = rust.replace('// @@LOADER@@', constants+'\n'+loader)
    rust = rust.replace('// @@PREPARE@@', '\n'.join(function(inputs['sle_usb.rs'], n) for n in
                        ['initialize_usb_controller', 'prepare_usb_controller', 'probe_usb_device']))
    with tempfile.TemporaryDirectory(prefix='sparklink-usb-fw-') as tmp:
        tmp = Path(tmp)
        (tmp/'c.c').write_text(fixture)
        (tmp/'rust.rs').write_text(rust)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(tmp/'c.c'),
                        '-o', str(tmp/'c-test')], check=True)
        result = subprocess.run([str(tmp/'c-test')], check=True, text=True, stdout=subprocess.PIPE,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                         UBSAN_OPTIONS='halt_on_error=1'))
        c_record = json.loads(result.stdout)
        print(result.stdout, end='')
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings',
                        str(tmp/'rust.rs'), '-o', str(tmp/'rust-test')], check=True)
        subprocess.run([str(tmp/'rust-test'), '--test-threads=1'], check=True)
    assert all((net/n).read_text() == s for n, s in inputs.items())
    record = {'status': 'GENERIC_USB_FIRMWARE_SOURCE_BOUNDARIES_PASS', 'c_cases': c_record['c_cases'],
              'rust_tests': 12, 'scope': 'actual C download/sync/validator and Rust loader/prepare/probe bodies; fixture USB, allocation, request_firmware and registry dependencies; C static linkage only lifted for extraction',
              'generic_firmware_wire_acceptance': False, 'native_ws73_firmware_acceptance': False,
              'natural_fault_root_cause_closed': False,
              'sources': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in inputs.items()}}
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
