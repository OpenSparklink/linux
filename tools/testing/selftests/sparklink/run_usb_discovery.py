#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual generic USB registration and unqueried info/default/attach boundaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from run_connection_tx import function
from usb_source_paths import source_path


def block(text, start):
    brace = text.index('{', start)
    end, depth = brace+1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3]/'net/sparklink'
    inputs = {n: source_path(net,n).read_text() for n in
              ['sle_usb_ffi.c', 'sle_usb.rs', 'sle_dli.rs', 'sparklink_core.rs']}
    archived=here/'retired-serdev/sle_serdev.rs'
    serdev_source=archived.read_text()
    c = inputs['sle_usb_ffi.c']
    fixture = (here/'usb-discovery/register_fixture.c').read_text()
    header=(here.parents[3]/'include/linux/sparklink_usb.h').read_text()
    fixture = fixture.replace('/* @@STRUCT@@ */', block(header, header.index('struct sle_usb_capabilities {'))+';\n'+block(c, c.index('struct sle_usb_dev {'))+';')
    fixture = fixture.replace('/* @@DEFINES@@ */', '\n'.join(re.search(r'(?m)^#define '+n+r' .+$',c).group() for n in ('SLE_USB_MAX_DEVS','SLE_USB_EVENT_MAX')))
    for marker, name in [('REGISTER', 'sle_usb_dev_register'), ('UNREGISTER', 'sle_usb_dev_unregister'), ('RELEASE','sle_usb_dev_release'), ('GET','sle_usb_dev_get'), ('PUT','sle_usb_dev_put'), ('GET_VERSION','sle_usb_dev_get_fw_version')]:
        body = block(c, re.search(r'(?m)^(?:static )?(?:void|int|u8|u32) '+name+r'\([^;{]*\)\s*\{', c).start())
        fixture = fixture.replace('/* @@'+marker+'@@ */', body)
    dli = (here/'retired-dli-metadata/legacy_metadata.rs').read_text()
    rust = (here/'usb-discovery/info_fixture.rs').read_text()
    usb=(here/'retired-usb-registration/static_controller.rs').read_text()
    declarations='\n'.join('#[repr(C)]\n#[derive(Clone,Copy,Default)]\n'+block(usb,usb.index('struct '+name+' {')) for name in ('UsbCapabilities','UsbMetadata'))
    rust=rust.replace('// @@USB_METADATA_TYPES@@',declarations)
    rust=rust.replace('// @@USB_NEW@@',function(usb[usb.index('impl UsbController {'):], 'new').replace('super::sle_dev::','crate::sle_dev::'))
    rust=rust.replace('// @@USB_SNAPSHOT@@',function(usb,'fill_snapshot').replace('super::sle_uapi::','crate::sle_uapi::'))
    uapi=(net/'sle_uapi.rs').read_text()
    rust=rust.replace('// @@SNAPSHOT_TYPE@@','#[derive(Default)]\n'+block(uapi,uapi.index('pub(crate) struct SleControllerSnapshot {')))

    rust = rust.replace('// @@INFO_STRUCT@@', block(dli, dli.index('pub struct SleControllerInfo {')))
    rust = rust.replace('// @@DEFAULT@@', function(dli[dli.index('impl Default for SleControllerInfo'):], 'default'))
    for marker, source in [('USB_INFO', 'sle_usb.rs'), ('SERDEV_INFO', 'sle_serdev.rs')]:
        rust = rust.replace('// @@'+marker+'@@', function(serdev_source if source=='sle_serdev.rs' else usb, 'info'))
    historic_attach = here/'retired-usb-registration/attach_metadata.rs'
    assembly = historic_attach.read_text()
    rust = rust.replace('// @@ATTACH_METADATA@@', assembly)
    reserve = function((here/'retired-usb-registration/core_wrappers.rs').read_text(), 'reserve_usb_identity')
    metadata = reserve[reserve.index('    let mut info ='):reserve.index('    reserve_backend_identity(')]
    rust = rust.replace('// @@RESERVE_METADATA@@', metadata)
    with tempfile.TemporaryDirectory(prefix='sparklink-usb-discovery-') as tmp:
        tmp = Path(tmp)
        (tmp/'fixture.c').write_text(fixture)
        (tmp/'fixture.rs').write_text(rust)
        subprocess.run([os.environ.get('CC', 'clang'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', str(tmp/'fixture.c'),
                        '-pthread', '-o', str(tmp/'c-test')], check=True)
        result = subprocess.run([str(tmp/'c-test')], check=True, text=True, stdout=subprocess.PIPE,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                         UBSAN_OPTIONS='halt_on_error=1'))
        c_record = json.loads(result.stdout)
        print(result.stdout, end='')
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings',
                        str(tmp/'fixture.rs'), '-o', str(tmp/'rust-test')], check=True)
        subprocess.run([str(tmp/'rust-test'), '--test-threads=1'], check=True)
    assert all(source_path(net,n).read_text() == s for n, s in inputs.items())
    assert archived.read_text()==serdev_source
    record = {'status': 'GENERIC_USB_DESCRIPTOR_CAPABILITY_SOURCE_BOUNDARIES_PASS',
              'c_cases': c_record['c_cases'], 'rust_tests': 11,
              'scope': 'actual C register/unregister and pending reservation/default types; retired static USB constructor/info/snapshot and archived attach/serdev history; current registered projection tested by run_backend_bus;  descriptor lookup/allocation/URB/types/firmware getters are dependency fixtures',
              'physical_acceptance': False, 'generic_dialect_acceptance': False,
              'full_capability_provenance_contract': False, 'natural_fault_root_cause_closed': False,
              'sources': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in inputs.items()},
              'archived_metadata_sha256': hashlib.sha256(dli.encode()).hexdigest(),
              'archived_attach_sha256': hashlib.sha256(assembly.encode()).hexdigest(),
              'archived_serdev_info_sha256': hashlib.sha256(serdev_source.encode()).hexdigest()}
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
