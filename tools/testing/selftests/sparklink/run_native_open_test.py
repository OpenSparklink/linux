#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guest-only native API open/retirement gate; never WS73 hardware/RF evidence."""
import argparse
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess

from qemu_verdict import KERNEL_FAULT
from run_runtime_lifecycle import file_record

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[3]


def checked_kernel_inputs(build):
    config = (build / '.config').read_text()
    for symbol in ['RUST', 'SPARKLINK', 'SPARKLINK_WS73_USB', 'MODULES']:
        if f'CONFIG_{symbol}=y\n' not in config:
            raise RuntimeError('missing kernel configuration: ' + symbol)
    manifest = json.loads((build / 'manifest.json').read_text())
    for record in manifest['artifacts']:
        if file_record(Path(record['path'])) != record:
            raise RuntimeError('kernel artifact does not match compiled manifest')
    return [file_record(build / 'manifest.json'), *manifest['artifacts']]


def assess(console, qemu_exit):
    console = console.replace('\r', '')
    errors = []
    if qemu_exit or KERNEL_FAULT.search(console) or 'NATIVE_FAILURE:' in console:
        errors.append('QEMU/guest/kernel failure')
    snapshots = re.findall(r'^NATIVE_OPEN_SNAPSHOT: slot=(\d+) elapsed_ms=([^ ]+)$', console, re.M)
    pending = re.findall(r'^NATIVE_OPEN_PENDING: slot=(\d+) id=(\d+) generation=(\d+) '
                         r'snapshot_ms=([^ ]+) lease_eagain=1 refs=1 sends=0$', console, re.M)
    if len(pending) != 4 or console.count('NATIVE_OPEN_PENDING:') != 4:
        errors.append('missing, duplicate or malformed opening observations')
    else:
        try:
            if ([int(p[0]) for p in pending] != list(range(4)) or
                    [int(p[1]) for p in pending] != [1] * 4 or
                    any(not 0 < int(p[2]) <= 2**64 - 1 for p in pending) or
                    any(int(pending[i][2]) >= int(pending[i + 1][2]) for i in range(3)) or
                    any(not math.isfinite(float(p[3])) or not 0 <= float(p[3]) < 200 for p in pending)):
                errors.append('invalid owner/generation or blocked snapshot')
        except ValueError:
            errors.append('invalid opening measurement')
        if snapshots != [(p[0], p[3]) for p in pending] or console.count('NATIVE_OPEN_SNAPSHOT:') != 4:
            errors.append('missing or inconsistent actual snapshot measurements')
    retiring = re.findall(r'^NATIVE_OPEN_RETIRING: slot=(\d+) blocked=1 admission_closed=1 '
                          r'close=0 put=0$', console, re.M)
    if retiring != ['2', '3'] or console.count('NATIVE_OPEN_RETIRING:') != 2:
        errors.append('missing, duplicate or malformed pre-join retirement evidence')
    cases = re.findall(r'^NATIVE_OPEN_CASE: slot=(\d+) mode=(\d+) retiring=(\d+) result=(-?\d+) '
                       r'close=(\d+) get=1 put=1 sends=0 survivor=1 stale=1$', console, re.M)
    expected = [('0', '0', '0', '0', '1'), ('1', '1', '0', '-5', '0'),
                ('2', '0', '1', '-19', '1'), ('3', '1', '1', '-5', '0')]
    if cases != expected or console.count('NATIVE_OPEN_CASE:') != 4:
        errors.append('missing, duplicate or incorrect terminal lifetime evidence')
    sequence = re.findall(r'^NATIVE_OPEN_(SNAPSHOT|PENDING|RETIRING|CASE): slot=(\d+)', console, re.M)
    if sequence != [('SNAPSHOT', '0'), ('PENDING', '0'), ('CASE', '0'),
                    ('SNAPSHOT', '1'), ('PENDING', '1'), ('CASE', '1'),
                    ('SNAPSHOT', '2'), ('PENDING', '2'), ('RETIRING', '2'), ('CASE', '2'),
                    ('SNAPSHOT', '3'), ('PENDING', '3'), ('RETIRING', '3'), ('CASE', '3')]:
        errors.append('out-of-order open lifecycle phases')
    exact = ['NATIVE_HOST: index=0 queries=18 features=80 version=5 dialect_reject=1',
             'NATIVE_OPEN_LIFECYCLE: PASS synthetic_only=1 cases=4',
             'NATIVE_OPEN_MODULE_EXIT: 0', 'RUNTIME_GUEST_EXIT: 0']
    for marker in exact:
        if console.splitlines().count(marker) != 1:
            errors.append('missing or duplicate ' + marker)
    positions = [console.find('NATIVE_OPEN_CASE: slot=3'), *[console.find(p) for p in exact],
                 console.find('RUNTIME_KERNEL_LOG_BEGIN'), console.find('RUNTIME_KERNEL_LOG_END')]
    if any(p < 0 for p in positions) or positions != sorted(positions):
        errors.append('out-of-order completion/process/log evidence')
    if re.findall(r'^NATIVE_OPEN_MODULE_EXIT: (.*)$', console, re.M) != ['0'] or \
            re.findall(r'^RUNTIME_GUEST_EXIT: (.*)$', console, re.M) != ['0']:
        errors.append('unsuccessful or malformed process exit')
    if console.count('RUNTIME_KERNEL_LOG_BEGIN') != 1 or console.count('RUNTIME_KERNEL_LOG_END') != 1:
        errors.append('missing or duplicate full kernel log')
    else:
        log = console.split('RUNTIME_KERNEL_LOG_BEGIN', 1)[1].split('RUNTIME_KERNEL_LOG_END', 1)[0]
        if '[    0.000000]' not in log:
            errors.append('kernel log missing early record')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--module-build', type=Path)
    parser.add_argument('--fixture-module', type=Path)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--busybox', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = dict(status='RUNNING', physical_acceptance=False,
                    scope='blocked native callback fixture and synthetic WS73 survivor')
    try:
        kernel = args.kernel_build.resolve() / 'arch/x86/boot/bzImage'
        manifest['kernel_inputs'] = checked_kernel_inputs(args.kernel_build.resolve())
        sources = [HERE / 'ws73_native_open_test.c', HERE / 'ws73_native_runtime_test.c',
                   HERE / 'native-open/native_open_fixture.c', HERE / 'native-open/native_open_fixture.h',
                   HERE / 'native-open/Makefile', Path(__file__).resolve(), HERE / 'qemu_verdict.py',
                   HERE / 'run_runtime_lifecycle.py']
        manifest['sources'] = [file_record(p) for p in sources]
        manifest['inputs'] = [file_record(p) for p in [kernel, args.kernel_build / '.config',
                                                      args.qemu, args.busybox]]
        if args.fixture_module:
            module = args.fixture_module.resolve()
            manifest['module_input'] = file_record(module)
        else:
            build = (args.module_build or args.kernel_build).resolve()
            if hashlib.sha256((build / '.config').read_bytes()).digest() != \
                    hashlib.sha256((args.kernel_build / '.config').read_bytes()).digest():
                raise RuntimeError('module/kernel config mismatch')
            module_build = output / 'module-build'
            shutil.copytree(HERE / 'native-open', module_build)
            command = ['make', '-C', str(SOURCE), 'O=' + str(build), 'LLVM=1',
                       'CC=/usr/bin/clang', 'HOSTCC=/usr/bin/clang',
                       'M=' + str(module_build), 'modules']
            manifest['module_compile_args'] = command
            manifest['module_symvers'] = file_record(build / 'Module.symvers')
            with (output / 'module-build.log').open('wb') as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
            module = module_build / 'native_open_fixture.ko'
        initroot = output / 'initramfs'
        for name in ['bin', 'dev', 'proc', 'sys', 'lib/firmware/sparklink/ws73']:
            (initroot / name).mkdir(parents=True)
        shutil.copy2(args.busybox, initroot / 'bin/busybox')
        for applet in ['sh', 'mount', 'mdev', 'sleep', 'poweroff', 'dmesg', 'insmod', 'rmmod']:
            (initroot / 'bin' / applet).symlink_to('busybox')
        shutil.copy2(module, initroot / 'native_open_fixture.ko')
        command = ['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                   str(HERE / 'ws73_native_open_test.c'), '-o', str(initroot / 'bin/open_test')]
        manifest['guest_compile_args'] = command
        with (output / 'guest-build.log').open('wb') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        firmware = initroot / 'lib/firmware/sparklink/ws73'
        (firmware / 'bsle_custom.bin').write_bytes(bytes(range(140)))
        (firmware / 'pm_config.bin').write_bytes(bytes.fromhex('01000000'))
        (initroot / 'init').write_text('''#!/bin/sh
export PATH=/bin
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev || mdev -s
insmod /native_open_fixture.ko
status=$?
if [ "$status" = 0 ]; then
    /bin/open_test
    status=$?
fi
rmmod native_open_fixture
module_status=$?
echo "NATIVE_OPEN_MODULE_EXIT: $module_status"
echo "RUNTIME_GUEST_EXIT: $status"
echo "RUNTIME_KERNEL_LOG_BEGIN"
dmesg
echo "RUNTIME_KERNEL_LOG_END"
poweroff -f
''')
        (initroot / 'init').chmod(0o755)
        manifest['guest_files'] = [file_record(p) for p in sorted(initroot.rglob('*'))
                                   if p.is_file() and not p.is_symlink()]
        names = b'\0'.join(os.fsencode(str(p.relative_to(initroot)))
                           for p in sorted(initroot.rglob('*'))) + b'\0'
        with (output / 'pack.log').open('wb') as log:
            packed = subprocess.run(['cpio', '--null', '-o', '--format=newc'], cwd=initroot,
                                    input=names, stdout=subprocess.PIPE, stderr=log, check=True).stdout
        archive = output / 'initramfs.cpio.gz'
        archive.write_bytes(gzip.compress(packed, mtime=0))
        manifest['initramfs'] = file_record(archive)
        console = output / 'console.log'
        command = [str(args.qemu.resolve()), '-kernel', str(kernel), '-initrd', str(archive),
                   '-append', 'console=ttyS0 loglevel=5 log_buf_len=4M panic=1 oops=panic',
                   '-serial', 'file:' + str(console), '-display', 'none', '-no-reboot',
                   '-m', '256M', '-smp', '2', '-device', 'qemu-xhci,id=xhci',
                   '-device', 'usb-ws73-test,id=sle0,bus=xhci.0,port=1']
        if os.access('/dev/kvm', os.R_OK | os.W_OK):
            command.append('-enable-kvm')
        manifest['qemu_args'] = command
        with (output / 'qemu-stderr.log').open('wb') as log:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=log)
            try:
                code = process.wait(timeout=45)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise RuntimeError('guest timed out')
        manifest['qemu_exit'] = code
        manifest['errors'] = assess(console.read_text(errors='replace'), code)
        for record in manifest['sources'] + manifest['inputs']:
            if file_record(Path(record['path'])) != record:
                manifest['errors'].append('input changed during test: ' + record['path'])
        manifest['kernel_inputs_after'] = checked_kernel_inputs(args.kernel_build.resolve())
        if manifest['kernel_inputs'] != manifest['kernel_inputs_after']:
            manifest['errors'].append('compiled kernel inputs changed during test')
        manifest['status'] = 'FAIL' if manifest['errors'] else 'PASS'
    except Exception as error:
        manifest.update(status='FAIL', error=str(error))
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(status=manifest['status'], errors=manifest.get('errors'),
                          error=manifest.get('error'), physical_acceptance=False)))
    return int(manifest['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
