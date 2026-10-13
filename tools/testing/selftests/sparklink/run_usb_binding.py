#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual standard USB EP0 writer and interrupt query with controlled dependencies."""
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
    source = here.parents[3]/'drivers/sparklink/standard_usb.c'
    original = source.read_text()
    rust_source=here.parents[3]/'net/sparklink/sle_standard_dli.rs';rust_original=rust_source.read_text()
    rust=(here/'usb_binding_prepare_fixture.rs').read_text()
    archived=(here/'retired-usb-registration/core_driver.rs').read_text()
    for marker,name in [('INIT','initialize_usb_controller'),('PREPARE','prepare_usb_controller')]:rust=rust.replace('// @@'+marker+'@@',function(archived,name))
    rust=rust.replace('// @@RX@@',function(rust_original.replace('pub(crate) extern "C" fn sparklink_standard_receive_rust','fn sparklink_standard_receive_rust'),'sparklink_standard_receive_rust').replace('super::sle_dev::','crate::sle_dev::'))
    assert 'load_usb_firmware' not in rust_original and not (here.parents[3]/'net/sparklink/sle_fw.rs').exists()
    assert 'mod sle_fw;' not in (here.parents[3]/'net/sparklink/sparklink_core.rs').read_text()
    fixture = (here/'usb_binding_fixture.c').read_text()
    defines = '\n'.join(re.search(r'(?m)^#define '+name+r' .+$', original).group() for name in ['SLE_CMD_TIMEOUT_MS', 'SLE_INIT_TIMEOUT_MS'])
    fixture = fixture.replace('/* @@DEFINES@@ */', defines)
    for marker, name in [('WRITE', 'sle_usb_write_command_locked'), ('SEND', 'sle_usb_dev_send_cmd_locked'), ('SYNC', 'sle_usb_send_cmd_sync'), ('DATA', 'sle_usb_dev_send_data_locked')]:
        fixture = fixture.replace('/* @@'+marker+'@@ */', function(original.replace('static int '+name, 'int '+name), name))
    with tempfile.TemporaryDirectory(prefix='sparklink-standard-binding-') as temporary:
        path = Path(temporary)
        (path/'actual.c').write_text(fixture)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', str(path/'actual.c'), '-o', str(path/'test')], check=True)
        result = subprocess.check_output([str(path/'test')], text=True, env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1'))
        (path/'actual.rs').write_text(rust)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(path/'actual.rs'),'-o',str(path/'rust-test')],check=True)
        log=subprocess.check_output([str(path/'rust-test'),'--test-threads=1'],text=True)
    assert '8 passed; 0 failed' in log and rust_source.read_text()==rust_original
    data = json.loads(result)
    assert data['cases'] == 25 and source.read_text() == original
    record = dict(status=data['status'], cases=data['cases'],rust_tests=8,rust_sha256=hashlib.sha256(rust_original.encode()).hexdigest(), source_sha256=hashlib.sha256(original.encode()).hexdigest(), scope='Actual EP0 writer/control setup/four-byte framing/interrupt bootstrap read/unsupported data stub, and current attributed DLI lane callback with retired prepare history; decoder/ingress ownership are controlled fixture dependencies, not protocol/lifetime proof; USB, allocation and retained active context dependencies controlled. Includes u16 wLength boundary and uncertain/short transfers. No hardware, class discovery, async listener, lifetime, Ready or firmware proof.', physical_acceptance=False)
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
