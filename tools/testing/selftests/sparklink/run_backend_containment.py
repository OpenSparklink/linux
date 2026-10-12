#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute archived UART/SPI rejection methods; no production/hardware claims."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def method(text, name):
    start = text.index('    fn '+name+'(', text.index('impl SleController for '))
    brace = text.index('{', start)
    end, depth = brace+1, 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def run(output):
    here = Path(__file__).resolve().parent
    fixture = (here/'security/backend_fixture.rs').read_text()
    records = {}
    sources = {}
    for name in ('uart', 'spi'):
        path = here/'retired-transport'/('sle_'+name+'.rs')
        data = path.read_text()
        sources[path] = data
        bodies = '\n'.join(method(data, n) for n in ('info', 'open', 'send_command', 'send_data', 'reset'))
        fixture = fixture.replace('// @@'+name.upper()+'_METHODS@@', bodies)
        records[path.name] = {'sha256': hashlib.sha256(data.encode()).hexdigest(),
                              'methods_sha256': hashlib.sha256(bodies.encode()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix='sparklink-backend-') as temp:
        tmp = Path(temp)
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D',
                        'warnings', str(tmp/'fixture.rs'), '-o', str(tmp/'test')], check=True)
        subprocess.run([str(tmp/'test')], check=True)
    if any(p.read_text() != data for p, data in sources.items()):
        raise RuntimeError('production input changed during tests')
    result = {'status': 'BACKEND_CONTAINMENT_PASS', 'sources': records, 'tests': 2,
              'scope': 'archived unsupported trait bodies preserved outside production, fixture types; no UART/SPI hardware/framing qualification',
              'physical_acceptance': False}
    if output:
        output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
