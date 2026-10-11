#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Staging connection session/codec contracts; no production or RF claim."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(output):
    here=Path(__file__).resolve().parent;directory=here/'connection'
    names=['session.rs','ws73_connection_codec.c','ws73_connection_codec.h','ws73_connection_codec_test.c']
    inputs={name:(directory/name).read_bytes() for name in names}
    with tempfile.TemporaryDirectory(prefix='sparklink-connection-contract-') as tmp:
        tmp=Path(tmp)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(directory/'session.rs'),'-o',str(tmp/'session')],check=True)
        tests=subprocess.check_output([str(tmp/'session')],text=True);print(tests)
        count=re.search(r'test result: ok\. (\d+) passed; 0 failed;',tests);assert count
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer',str(directory/'ws73_connection_codec.c'),str(directory/'ws73_connection_codec_test.c'),'-o',str(tmp/'codec')],check=True)
        subprocess.run([str(tmp/'codec')],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
    assert all((directory/name).read_bytes()==data for name,data in inputs.items())
    record={'status':'NATIVE_CONNECTION_STAGING_CONTRACT_PASS','scope':'staging session model and independent WS7327/3-byte codec; excluded from production; not actual Host callers, running kernel or RF',
        'rust_tests':int(count[1]),'codec_sanitizers':['address','undefined','leak'],
        'production_connection_admission':False,'connection_rf_acceptance':False,'ssap_acceptance':False,'automatic_recovery_acceptance':False,
        'sources':{name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
