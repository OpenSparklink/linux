#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual crypto/security code with fault dependencies; no hardware access."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile


def function(text, name):
    start = text.index('int ' + name + '(')
    # Skip the forward declaration.
    while text.index(';', start) < text.index('{', start):
        start = text.index('int ' + name + '(', start + 1)
    body = text.index('{', start)
    depth = 1
    end = body + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]


def run(output):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    paths = [root/'net/sparklink'/name for name in
             ('sle_crypto.rs', 'sle_security.rs', 'sle_crypto_ffi.c')]
    contents = {p.name: p.read_bytes() for p in paths}
    with tempfile.TemporaryDirectory(prefix='sparklink-security-') as temp:
        tmp = Path(temp)
        # No production statements are rewritten: append child tests for private state.
        (tmp/'sle_crypto.rs').write_bytes(contents['sle_crypto.rs'])
        (tmp/'sle_security.rs').write_bytes(contents['sle_security.rs'] + b'\n' +
                                          (here/'security/security_regression.rs').read_bytes())
        fixture = (here/'security/kernel_fixture.rs').read_text()
        fixture += '#[path = "sle_crypto.rs"] mod sle_crypto;\n#[path = "sle_security.rs"] mod sle_security;\n'
        (tmp/'fixture.rs').write_text(fixture)
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                        '-D', 'warnings', str(tmp/'fixture.rs'), '-o', str(tmp/'rust-test')], check=True)
        subprocess.run([str(tmp/'rust-test'), '--test-threads=1'], check=True)
        ctr = function(contents['sle_crypto_ffi.c'].decode(), 'sle_sm4_ctr_crypt')
        c = (here/'security/ctr_fixture.c').read_text().replace('@@PRODUCTION_CTR@@', ctr)
        (tmp/'ctr.c').write_text(c)
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-fsanitize=address,undefined', '-g', str(tmp/'ctr.c'), '-o', str(tmp/'ctr-test')], check=True)
        subprocess.run([str(tmp/'ctr-test')], check=True)
    for path in paths:
        if path.read_bytes() != contents[path.name]:
            raise RuntimeError('production input changed during test')
    record = {'status': 'SECURITY_FAILURE_BOUNDARY_PASS', 'physical_acceptance': False,
              'scope': 'actual Rust wrappers/security + C CTR body; mocked dependencies, not crypto vectors or RF',
              'sources': {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()},
              'ctr_body_sha256': hashlib.sha256(ctr.encode()).hexdigest(),
              'rust_tests': 6, 'c_fault_stages': 5,
              'remaining': ['Per-connection authenticated pairing/relay/real encryption installation',
                            'Standard crypto vectors, zeroization audit and real peer interoperability',
                            'New kernel VM WS73 discovery/recovery regression']}
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
