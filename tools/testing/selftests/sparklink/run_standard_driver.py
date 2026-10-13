#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual standard USB driver probe/disconnect/rejected-PM with controlled dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def run(output):
    here=Path(__file__).resolve().parent
    source=here.parents[3]/'drivers/sparklink/standard_usb.c'
    original=source.read_text()
    fixture=(here/'standard_driver_fixture.c').read_text()
    for marker,name in [('PROBE','sparklink_standard_usb_probe'),('DISCONNECT','sparklink_standard_usb_disconnect'),('SUSPEND','sparklink_standard_usb_suspend')]:
        fixture=fixture.replace('/* @@'+marker+'@@ */',original_body(original,name))
    with tempfile.TemporaryDirectory(prefix='sparklink-driver-binding-') as directory:
        path=Path(directory);(path/'actual.c').write_text(fixture)
        subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined',str(path/'actual.c'),'-o',str(path/'test')],check=True)
        data=json.loads(subprocess.check_output([str(path/'test')],text=True,env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',UBSAN_OPTIONS='halt_on_error=1')))
    assert data['cases']==6 and source.read_text()==original
    record=dict(status=data['status'],cases=6,source_sha256=hashlib.sha256(original.encode()).hexdigest(),scope='Actual driver probe/disconnect/PM rejection; Core/USB/init/install/dependency refs controlled. Original identity only, Core retirement before USB release, partial init/failure cleanup and no silent PM; not real module/IRQ/URB/refcount/lifetime/physical proof.',physical_acceptance=False)
    if output:output.write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps(record,indent=2))


def original_body(source,name):
    import re
    match=re.search(r'(?m)^static (?:int|void) '+name+r'\(',source);start=match.start();brace=source.index('{',start);depth=1;end=brace+1
    while depth:
        depth+=(source[end]=='{')-(source[end]=='}');end+=1
    return source[start:end]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path);run(parser.parse_args().output)
