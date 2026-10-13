#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual optional Virtual + Core/Host in empty-USB KVM; never host driver I/O."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    here = Path(__file__).resolve().parent
    out = args.output.resolve()
    out.mkdir(mode=0o700)  # Reject old image/transcript/result.
    root = out / 'root'
    root.mkdir()
    for name in ('bin', 'dev', 'proc', 'sys', 'lib64'):
        (root / name).mkdir()
    paths = {name: getattr(args, name).resolve(strict=True)
             for name in ('kernel', 'module', 'qemu', 'busybox', 'qemu_data')}
    info = {name: subprocess.check_output(['modinfo', '-F', name, str(paths['module'])],
                                          text=True).strip()
            for name in ('name', 'vermagic', 'signer', 'depends')}
    if info['name'] != 'sparklink_virtual' or not info['signer'] or info['depends']:
        raise ValueError('matching signed standalone virtual module required')
    if 'INTERP' in subprocess.check_output(['readelf', '-l', str(paths['busybox'])], text=True):
        raise ValueError('static busybox required')
    record = {'status': 'PREPARING', 'physical_acceptance': False,
              'scope': 'Empty-USB KVM, actual test provider + Core/Host; no RF/data/recovery proof',
              'module_info': info, 'source_sha256': sha(here / 'virtual_runtime_test.c'),
              'registry_probe_sha256': sha(here / 'genl_registry_test.c'),
              'inputs': {name: sha(path) for name, path in paths.items() if path.is_file()}}
    manifest = out / 'manifest.json'

    def save():
        manifest.write_text(json.dumps(record, indent=2) + '\n')

    save()
    try:
        binary = root / 'bin/test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-Wall', '-Wextra',
                        '-Werror', str(here / 'virtual_runtime_test.c'), '-o', str(binary)], check=True)
        libs = subprocess.check_output(['ldd', str(binary)], text=True)
        resolved = []
        for line in libs.splitlines():
            words = line.split()
            if '=>' in words:
                resolved.append(Path(words[words.index('=>') + 1]))
            elif words and words[0].startswith('/'):
                resolved.append(Path(words[0]))
        if set(p.name for p in resolved) != {'libc.so.6', 'ld-linux-x86-64.so.2'}:
            raise ValueError('unexpected test ELF dependencies')
        for path in resolved:
            dest = root / path.relative_to('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            record['inputs'][str(path)] = sha(dest)
        shutil.copy2(paths['busybox'], root / 'bin/busybox')
        (root / 'bin/sh').symlink_to('busybox')
        shutil.copy2(paths['module'], root / 'virtual.ko')
        init = '''#!/bin/sh
export PATH=/bin
fail() { echo VIRTUAL_VM_FAIL; busybox dmesg; busybox poweroff -f; exit 1; }
busybox mount -t proc none /proc || fail
busybox mount -t sysfs none /sys || fail
busybox mount -t devtmpfs none /dev || fail
busybox mkdir -p /sys/kernel/config || fail
busybox mount -t configfs none /sys/kernel/config || fail
'''
        init += '[ "$(busybox uname -r)" = "' + info['vermagic'].split()[0] + '" ] || fail\n'
        init += '''for round in 1 2; do
busybox insmod /virtual.ko || fail
[ -c /dev/sparklink_virtual ] || fail
/bin/test || fail
busybox rmmod sparklink_virtual || fail
[ ! -d /sys/module/sparklink_virtual ] || fail
echo VIRTUAL_MODULE_ROUND_PASS:$round
done
[ "$(busybox cat /proc/sys/kernel/tainted)" = 0 ] || fail
echo VIRTUAL_VM_PASS
busybox dmesg
busybox poweroff -f
'''
        (root / 'init').write_text(init)
        (root / 'init').chmod(0o755)
        entries = '\n'.join(['.'] + sorted(str(p.relative_to(root)) for p in root.rglob('*'))) + '\n'
        with (out / 'initramfs.cpio').open('wb') as target:
            subprocess.run(['cpio', '-o', '-H', 'newc', '--quiet'], cwd=root,
                           input=entries.encode(), stdout=target, check=True)
        command = [str(paths['qemu']), '-L', str(paths['qemu_data']), '-machine', 'q35,accel=kvm',
                   '-cpu', 'host', '-m', '2048M', '-smp', '2', '-nodefaults', '-display', 'none',
                   '-monitor', 'none', '-serial', 'stdio', '-no-reboot', '-nic', 'none',
                   '-kernel', str(paths['kernel']), '-initrd', str(out / 'initramfs.cpio'),
                   '-append', 'rdinit=/init console=ttyS0 loglevel=6 panic=1 oops=panic']
        record.update(status='RUNNING', command=command, initramfs_sha256=sha(out / 'initramfs.cpio'))
        save()
        with (out / 'console.log').open('wb') as console:
            result = subprocess.run(command, stdout=console, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, timeout=120)
        log = (out / 'console.log').read_text(errors='replace')
        record.update(qemu_exit=result.returncode, console_sha256=sha(out / 'console.log'))
        if (result.returncode or log.count('VIRTUAL_RUNTIME_PASS:') != 2
                or log.count('VIRTUAL_QUERY_RELEASE_PASS:') != 2
                or log.count('VIRTUAL_DIAGNOSTIC_FD_PASS:') != 2
                or log.count('VIRTUAL_POWER_UNSUPPORTED_PASS:') != 4
                or log.count('VIRTUAL_GLOBAL_POWER_POLICY_PASS:') != 2
                or log.count('GENL_REGISTRY_PASS:') != 10
                or log.count('GENL_REGISTRY_PASS: uid=1000') != 2
                or 'VIRTUAL_MODULE_ROUND_PASS:2' not in log or 'VIRTUAL_VM_PASS' not in log
                or any(marker in log for marker in ('VIRTUAL_VM_FAIL', 'VIRTUAL_RUNTIME_FAIL',
                                                    'Kernel panic', 'BUG:', 'WARNING:'))):
            raise RuntimeError('VM gates failed; retain transcript')
        if any(sha(path) != record['inputs'][name]
               for name, path in paths.items() if path.is_file()):
            raise RuntimeError('input changed during VM')
        record.update(status='PASS_VIRTUAL_CORE_HOST_VM', module_rounds=2,
                      registry_results=[line for line in log.splitlines() if 'GENL_REGISTRY_PASS:' in line],
                      power_results=[line for line in log.splitlines() if 'VIRTUAL_POWER_' in line or 'VIRTUAL_GLOBAL_POWER_' in line],
                      query_results=[line for line in log.splitlines() if 'VIRTUAL_RUNTIME_PASS:' in line],
                      diagnostic_fd_results=[line for line in log.splitlines()
                                             if 'VIRTUAL_DIAGNOSTIC_FD_PASS:' in line])
        save()
        print(record['status'])
    except BaseException as exc:
        record.update(status='FAIL', error=str(exc))
        save()
        raise


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('kernel', 'module', 'qemu', 'busybox', 'qemu-data', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    run(parser.parse_args())
