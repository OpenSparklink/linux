#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual connection route and channel submit-consent bodies with kernel dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def function(source, name):
    m = re.search(r'^static [^{;\n]+?\b'+name+r'\([^;{]*\)\s*\{', source, re.M)
    assert m
    i=m.end();depth=1
    while depth:
        depth+=(source[i]=='{')-(source[i]=='}');i+=1
    return source[m.start():i]


def run(output):
    here=Path(__file__).resolve().parent;root=here.parents[3];net=root/'net/sparklink'
    paths=[net/'sle_channel_socket.c',net/'sle_channel_state.h',net/'sle_channel_grant.h',net/'sle_channel_wire.c',net/'sle_channel_wire.h',root/'include/linux/sparklink_channel.h',net/'sle_channel_table.h',net/'sle_fragment_cursor.h',root/'include/uapi/linux/sparklink_socket.h',here/'session/dispatch_fixture.c']
    inputs={p:p.read_bytes() for p in paths};source=inputs[paths[0]].decode()
    structs=source[source.index('struct sl_basic_channel {'):source.index('static struct proto sl_channel_proto;')]
    # Include actual SocketBinding/grant layout; allocation/mapping remain dependencies.
    structs+=re.search(r'struct sl_bind_admission \{[^}]+\};',source)[0]
    structs+=re.search(r'struct sl_info_read \{[^}]+\};',source)[0]
    structs+=re.search(r'struct sl_tx_status_read \{[^}]+\};',source)[0]
    structs+=re.search(r'struct sparklink_credit_snapshot \{[^}]+\};',(root/'include/linux/sparklink_channel.h').read_text())[0]
    structs+=re.search(r'struct sl_receive \{[^}]+\};',source)[0]
    structs+=re.search(r'struct sl_admission \{[^}]+\};',source)[0]
    defines='\n'.join(re.search(r'^#define '+n+r' .*$',source,re.M)[0] for n in ['SL_CHANNEL_RX','SL_CHANNEL_TX'])
    bodies='\n'.join(function(source,n) for n in ['sl_bound_channel','sl_permits','sl_session_submit','sl_route','sl_admit','sl_take','sl_recvmsg','sl_poll','sl_tx_access','sl_publish_binding','sl_view_access','sl_read_info','sl_read_tx_status','sl_ioctl','sl_socket_fault','sl_fail_channel','sl_retire_tx','sl_transmit_channel'])
    fixture=inputs[paths[-1]].decode().replace('/* @@STRUCTS@@ */',structs).replace('/* @@LIMITS@@ */',defines).replace('/* @@FUNCTIONS@@ */',bodies)
    with tempfile.TemporaryDirectory(prefix='sparklink-session-dispatch-') as directory:
        tmp=Path(directory);(tmp/'test.c').write_text(fixture)
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-I'+str(net),'-iquote'+str(root/'include/uapi/linux'),str(tmp/'test.c'),str(net/'sle_channel_wire.c'),'-o',str(tmp/'test')],check=True)
        subprocess.run([str(tmp/'test')],check=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'))
    assert all(p.read_bytes()==b for p,b in inputs.items())
    result={'status':'ACTUAL_SESSION_ROUTE_SUBMIT_PASS','scope':'actual single-consumer two-slot route/local TCID+PI/independent finite RX and TX, retired-slot/peer isolation, queue and USB consent, full recvmsg retry/authorized dequeue/PEEK/TRUNC/zero/error paths, actual Session-owned physical TX/first-submit linearization/fd detach and original-deadline worker; kernel allocation/locks/Host authorization/wait/wakeup/copy are explicit dependencies; no running kernel or RF','physical_acceptance':False,'whole_session_proof':False,'bodies_sha256':hashlib.sha256(bodies.encode()).hexdigest(),'sources':{str(p.relative_to(root)):hashlib.sha256(b).hexdigest() for p,b in inputs.items()}}
    if output:output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
