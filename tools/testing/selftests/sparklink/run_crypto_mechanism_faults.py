#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual retained ECDH C bodies with explicit fault dependencies; no math/RF proof."""
import argparse, hashlib, json, os, subprocess, tempfile
from pathlib import Path
from run_security_remediation import function

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    here=Path(__file__).resolve().parent
    source=here.parents[3]/'net/sparklink/sle_crypto_ffi.c'
    original=source.read_bytes()
    fixture=(here/'security/ecdh_fixture.c').read_text()
    fixture=fixture.replace('@@PRODUCTION_GENERATE@@',function(original.decode(),'sle_ecdh_generate')).replace('@@PRODUCTION_SHARED@@',function(original.decode(),'sle_ecdh_shared_secret'))
    with tempfile.TemporaryDirectory(prefix='sparklink-ecdh-faults-') as name:
        temp=Path(name);(temp/'probe.c').write_text(fixture)
        subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(temp/'probe.c'),'-o',str(temp/'probe')],check=True)
        subprocess.run([str(temp/'probe')],check=True)
    if source.read_bytes()!=original:raise RuntimeError('production source changed during run')
    result={'status':'ACTUAL_ECDH_FAILURE_BOUNDARIES_PASS','source_sha256':hashlib.sha256(original).hexdigest(),'scope':'verbatim C generate/shared functions; allocated resources/atomic failure,8 finite invalid-scalar attempts, asynchronous partial-destination error','faults':'alloc_tfm,alloc_buffer,random_wait,encode,set_secret,invalid_scalar,alloc_request,partial_crypto_failure','limits':'Mock dependencies; no crypto math, kernel execution, pairing, trust or RF proof'}
    if args.output:args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
if __name__=='__main__':main()
