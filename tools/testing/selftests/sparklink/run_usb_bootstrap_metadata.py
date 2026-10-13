#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual standard USB bootstrap/tuple getter with controlled response dependencies."""
import argparse,hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from run_connection_tx import function

def run(output):
 here=Path(__file__).resolve().parent;source=here.parents[3]/'net/sparklink/sle_usb_ffi.c';original=source.read_text();s=(here/'usb_bootstrap_metadata_fixture.c').read_text()
 header=(here.parents[3]/'include/linux/sparklink_usb.h').read_text(); start=header.index('struct sle_usb_capabilities {'); definition=header[start:header.index('};',start)+2]; s=s.replace('/* @@CAPABILITIES@@ */',definition)
 s=s.replace('/* @@DEFINES@@ */','\n'.join(re.search(r'(?m)^#define '+n+r' .+$',original).group() for n in ['SLE_OP_RESET','SLE_OP_READ_LOCAL_VERSION','SLE_OP_READ_CMD_LENGTH','SLE_OP_READ_BUFFER','SLE_OP_READ_FEATURES','SLE_OP_READ_MAC_ADDR','SLE_EVT_CMD_COMPLETE']))
 for marker,name in [('VALIDATOR','sle_usb_validate_init_reply'),('INIT','sle_usb_dev_init_controller_locked'),('GETTER','sle_usb_dev_get_version'),('CAPGETTER','sle_usb_dev_get_capabilities')]:s=s.replace('/* @@'+marker+'@@ */',function(original.replace('static int '+name,'int '+name),name))
 with tempfile.TemporaryDirectory(prefix='sparklink-usb-metadata-') as tmp:
  p=Path(tmp);(p/'actual.c').write_text(s);subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(p/'actual.c'),'-o',str(p/'test')],check=True);r=subprocess.check_output([str(p/'test')],text=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1'));print(r);result=json.loads(r)
 assert result['cases']==44 and source.read_text()==original
 record=dict(status=result['status'],cases=result['cases'],header_sha256=hashlib.sha256(header.encode()).hexdigest(),source_sha256=hashlib.sha256(original.encode()).hexdigest(),scope='Actual standard bootstrap, strict reply validator and locked tuple getter; synchronous response/USB/context dependencies are controlled fixtures. Fifth version byte preserved; failed requery invalidates observations, no partial commit/output overwrite. Actual command/buffer/features validation and coherent locked snapshot getter, standard 0406 address-type query. Not hardware, common provider migration or Ready proof.',physical_acceptance=False)
 if output:output.write_text(json.dumps(record,indent=2)+'\n')
 print(json.dumps(record,indent=2))
if __name__=='__main__':
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path);run(p.parse_args().output)
