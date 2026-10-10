#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual connection sender/ioctl/USB bodies; fixtures are not socket or RF proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def function(text, name):
    match = re.search(r'(?m)^(?:    )?(?:pub(?:\(crate\))? )?fn '+name+r'\(', text)
    if match is None:
        match = re.search(r'(?m)^int '+name+r'\([^;{]*\)\s*\{', text)
    if match is None:
        raise ValueError('missing actual function '+name)
    start = match.start()
    brace = text.index('{', match.start())
    end, depth = brace+1, 1
    while depth:
        depth += (text[end]=='{')-(text[end]=='}')
        end += 1
    return text[start:end]


def run(output):
    here=Path(__file__).resolve().parent
    net=here.parents[3]/'net/sparklink'
    inputs={name:(net/name).read_text() for name in ['sle_conn.rs','sparklink_core.rs','sle_usb_ffi.c']}
    conn=inputs['sle_conn.rs']
    methods='\n'.join(function(conn,n) for n in ['find_mut','find','find_first_connected_mut','resolve_handle','send'])
    rust=(here/'connection/tx_fixture.rs').read_text().replace('// @@CONN_METHODS@@',methods).replace('// @@SEQ_METHOD@@',function(conn,'advance_tx')).replace('// @@IOCTL@@',function(inputs['sparklink_core.rs'],'ioctl_conn_send'))
    usb=inputs['sle_usb_ffi.c']
    defines='\n'.join(re.search(r'(?m)^#define '+n+r' .+$',usb).group() for n in ['SLE_USB_MAX_DEVS','DLI_PKT_ASYNC_DATA','SLE_CMD_TIMEOUT_MS'])
    c=(here/'connection/usb_tx_fixture.c').read_text().replace('/* @@DEFINES@@ */',defines).replace('/* @@USB_FUNCTION@@ */',function(usb,'sle_usb_dev_send_data'))
    with tempfile.TemporaryDirectory(prefix='sparklink-connection-tx-') as tmp:
        path=Path(tmp)
        (path/'tx.rs').write_text(rust);(path/'tx.c').write_text(c)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(path/'tx.rs'),'-o',str(path/'rust-test')],check=True)
        subprocess.run([str(path/'rust-test')],check=True)
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(path/'tx.c'),'-o',str(path/'c-test')],check=True)
        subprocess.run([str(path/'c-test')],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
    assert all((net/n).read_text()==v for n,v in inputs.items()), 'production inputs changed during tests'
    result={'status':'CONNECTION_TX_SUBMISSION_BOUNDARY_PASS','scope':'actual sender/ioctl/legacy USB bodies with dependency fixtures; not socket/protocol/RF qualification','physical_acceptance':False,'socket_acceptance':False,'rust_tests':11,'usb_boundaries':['range','allocation','errno','all short completions','exact completion','max length'],'sources':{n:hashlib.sha256(v.encode()).hexdigest() for n,v in inputs.items()}}
    if output:output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
