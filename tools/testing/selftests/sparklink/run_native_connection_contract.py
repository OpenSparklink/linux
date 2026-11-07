#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual native operation storage and driver codec; not running-kernel or RF proof."""
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
    net=here.parents[3]/'net/sparklink';driver=here.parents[3]/'drivers/sparklink/ws73';include=here.parents[3]/'include'
    paths={'sle_connection_operation.rs':net/'sle_connection_operation.rs','connection.c':driver/'connection.c','connection.h':driver/'connection.h','sparklink_connection.h':include/'linux/sparklink_connection.h','ws73_connection_codec_test.c':directory/'ws73_connection_codec_test.c'}
    inputs={name:path.read_bytes() for name,path in paths.items()}
    with tempfile.TemporaryDirectory(prefix='sparklink-connection-contract-') as tmp:
        tmp=Path(tmp)
        subprocess.run([os.environ.get('RUSTC','rustc'),'--edition=2021','--test','-D','warnings',str(net/'sle_connection_operation.rs'),'-o',str(tmp/'session')],check=True)
        tests=subprocess.check_output([str(tmp/'session')],text=True);print(tests)
        count=re.search(r'test result: ok\. (\d+) passed; 0 failed;',tests);assert count
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I'+str(driver),'-I'+str(include),str(driver/'connection.c'),str(directory/'ws73_connection_codec_test.c'),'-o',str(tmp/'codec')],check=True)
        subprocess.run([str(tmp/'codec')],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
    from run_native_connection_host import run as run_host
    host_result=run_host()
    assert all(paths[name].read_bytes()==data for name,data in inputs.items())
    record={'status':'NATIVE_CONNECTION_PRODUCTION_SOURCE_CONTRACT_PASS','scope':'actual production operation storage and WS7327/3-byte driver codec; actual Host caller dependency tests; not running kernel or RF proof',
        'rust_tests':int(count[1]),'actual_host_tests':host_result['tests'],'actual_host_sources':host_result['sources'],'codec_sanitizers':['address','undefined','leak'],
        'production_connection_admission':False,'connection_rf_acceptance':False,'ssap_acceptance':False,'automatic_recovery_acceptance':False,
        'sources':{name:hashlib.sha256(data).hexdigest() for name,data in inputs.items()}}
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
