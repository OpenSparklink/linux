#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Current declarations/numeric ABI and exact retired witnesses, never a VM verdict.

The original independently compiled x86_64/i386 values are test inputs. Live
syscall ENOTTY/usercopy/authorization is checked separately in the test VM.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def check_sources(header, policy, numbers, retained, retired):
    errors = []
    public = re.findall(r'^#define (SL_IOCTL_\w+)\s', header, re.M)
    classified = re.findall(r'\bSL_IOCTL_\w+\b', policy)
    if len(public) != len(set(public)) or set(public) != set(retained):
        errors.append('public commands differ from reviewed current contract')
    if sorted(classified) != sorted(retained):
        errors.append('authorization does not classify exactly the current commands')
    if not re.search(r'_\s*=>\s*Err\(ENOTTY\)', policy):
        errors.append('unknown commands must be ENOTTY before authorization/usercopy')
    encoded = dict(re.findall(r'^#define SL_TEST_RETIRED_(\w+) (0x[0-9a-f]+)U$', numbers, re.M))
    expected = {name.removeprefix('SL_IOCTL_'): value for name, value in retired.items()}
    if {name: int(value, 16) for name, value in encoded.items()} != expected:
        errors.append('private old numbers changed or use an alias instead of frozen values')
    if set(retained.values()) & set(retired.values()):
        errors.append('current command reuses a retired encoded number')
    return errors


def run(output):
    retained_path = HERE / 'retired-raw-uapi/retained-numbers.json'
    audit_path = HERE / 'retired-raw-uapi/retirement-audit.json'
    retained = json.loads(retained_path.read_text())['commands']
    retired = json.loads(audit_path.read_text())['old_numbers']
    header_path = ROOT / 'include/uapi/linux/sparklink_ioctl.h'
    policy_path = ROOT / 'net/sparklink/sle_authorization.rs'
    numbers_path = HERE / 'retired_ioctl_numbers.h'
    header, policy, numbers = (p.read_text() for p in [header_path, policy_path, numbers_path])
    assert not check_sources(header, policy, numbers, retained, retired)
    archived = json.loads((HERE / 'retired-raw-uapi/test-migration-audit.json').read_text())
    for name, digest in archived['files'].items():
        assert hashlib.sha256((HERE / 'retired-raw-uapi' / name).read_bytes()).hexdigest() == digest, name
    negatives = []
    for name, h, p, n in [
        ('restore-old-entry', header + '\n#define SL_IOCTL_DLI_SEND_CMD 1\n', policy, numbers),
        ('drop-live-authorization', header, policy.replace('SL_IOCTL_DEV_INFO', 'REMOVED'), numbers),
        ('wrong-unknown-error', header, policy.replace('Err(ENOTTY)', 'Err(EINVAL)'), numbers),
        ('private-alias', header, policy, numbers.replace('0xc010533dU', 'SL_IOCTL_MGMT_STATS')),
    ]:
        result = check_sources(h, p, n, retained, retired)
        assert result, name
        negatives.append(dict(name=name, result='REJECTED', errors=result))
    builds = []
    compiler = shlex.split(os.environ.get('CC', 'clang'))
    with tempfile.TemporaryDirectory(prefix='sparklink-raw-contract-') as temp:
        temp = Path(temp)
        assertions = [f'#include {json.dumps(str(header_path))}',
                      f'#include {json.dumps(str(numbers_path))}']
        for name, value in retained.items():
            assertions.append(f'_Static_assert({name} == {value}U, "current {name}");')
        for name, value in retired.items():
            private = name.replace('SL_IOCTL_', 'SL_TEST_RETIRED_')
            assertions.append(f'_Static_assert({private} == {value}U, "retired {name}");')
        source = temp / 'numbers.c'
        source.write_text('\n'.join(assertions) + '\n')
        for bits in [64, 32]:
            command = compiler + [f'-m{bits}', '-ffreestanding', '-std=c11', '-Wall',
                                  '-Wextra', '-Werror', '-c', str(source), '-o', str(temp / f'{bits}.o')]
            result = subprocess.run(command, text=True, capture_output=True)
            builds.append(dict(bits=bits, command=command, exit=result.returncode,
                               stdout=result.stdout, stderr=result.stderr))
            assert result.returncode == 0, builds[-1]
        # A changed live wire number must fail the actual compiler assertions.
        bad_header = temp / 'wrong.h'
        bad_header.write_text(re.sub(r"(#define\s+SL_MAGIC\s+)'S'", r"\1'T'", header))
        assert bad_header.read_text() != header
        bad = temp / 'wrong.c'
        bad.write_text(source.read_text().replace(str(header_path), str(bad_header)))
        result = subprocess.run(compiler + ['-ffreestanding', '-c', str(bad), '-o', str(temp / 'bad.o')],
                                text=True, capture_output=True)
        assert result.returncode != 0 and 'static assertion' in result.stderr
        negatives.append(dict(name='compiler-wire-number-mutation', result='REJECTED',
                              exit=result.returncode, stderr=result.stderr))
    sources = [header_path, policy_path, numbers_path, retained_path, audit_path,
               Path(__file__), HERE / 'retired-raw-uapi/test-migration-audit.json']
    record = dict(status='OFFLINE_RAW_ABI_RETIREMENT_PASS', retained_commands=len(retained),
                  retired_commands=len(retired), compiled_targets=builds, negative_controls=negatives,
                  sources={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources},
                  scope='Declarations, actual compiler numeric assertions, exact archived bytes and static source boundary; not syscall, kernel concurrency, full caller absence, RF or natural recovery proof',
                  physical_acceptance=False)
    if output:
        with output.open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
    print(record['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
