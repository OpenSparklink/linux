#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual optional Virtual + Core/Host in empty-USB KVM; never host driver I/O."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_console(log, qemu_exit):
    if (qemu_exit or log.count('VIRTUAL_RUNTIME_PASS:') != 2
            or log.count('VIRTUAL_QUERY_RELEASE_PASS:') != 2
            or log.count('VIRTUAL_STANDARD_SNOOP_PASS:') != 2
            or len(re.findall(r'VIRTUAL_HARDWARE_ERROR_PASS: id=\d+ generation=\d+ requests=2 submitted=1 late_reply=ignored callback_return=1 credit=0 inherited_CAP=EPERM invalid=EINVAL bad_pointer=EFAULT retired_status=ENOTTY peer=1 reuse=1 raw_code=7 no_rf=1', log)) != 2
            or log.count('VIRTUAL_DIAGNOSTIC_FD_PASS:') != 2
            or len(re.findall(r'RETIRED_UAPI_ENOTTY_PASS: uid=(?:0|1000) cases=101 unchanged=101 checks=303 invalid_user_address=1 mixed_stats=ENOTTY',log)) != 4
            or log.count('RETIRED_UAPI_ENOTTY_PASS: uid=1000') != 2
            or log.count('RETIRED_UAPI_ENOTTY_PASS: uid=0') != 2
            or log.count('VIRTUAL_POWER_RETIRED_ABI_PASS:') != 4
            or log.count('VIRTUAL_GLOBAL_POWER_POLICY_PASS:') != 2
            or log.count('GENL_REGISTRY_PASS:') != 10
            or log.count('GENL_REGISTRY_PASS: uid=1000') != 2
            or 'VIRTUAL_MODULE_ROUND_PASS:2' not in log or 'VIRTUAL_VM_PASS' not in log
            or any(marker in log for marker in ('VIRTUAL_VM_FAIL', 'VIRTUAL_RUNTIME_FAIL',
                                                'Kernel panic', 'BUG:', 'WARNING:'))):
        raise RuntimeError('VM gates failed; retain transcript')
    fault_ids = set(re.findall(r'VIRTUAL_HARDWARE_ERROR_PASS: id=(\d+) generation=(\d+)', log))
    logged_faults = set(re.findall(r'sle(\d+) generation=(\d+) controller hardware error code=0x07; Host quarantined', log))
    if len(fault_ids) != 2 or not fault_ids <= logged_faults:
        raise ValueError('missing generation-bound hardware fault diagnostics')

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
              'scope': 'Empty-USB KVM,actual optional test provider plus production parser/Host/ledger/worker and ticket barrier;controlled hardware-error input is not a real WS73 fault or RF/recovery proof',
              'runner_sha256':sha(Path(__file__)), 'private_virtual_header_sha256':sha(here.parents[3]/'drivers/sparklink/virtual.h'),
              'module_info': info, 'source_sha256': sha(here / 'virtual_runtime_test.c'),
              'registry_probe_sha256': sha(here / 'genl_registry_test.c'),
              'retired_uapi_probe_sha256': sha(here / 'retired_uapi_test.c'),
              'retired_numbers_sha256': sha(here / 'retired_ioctl_numbers.h'),
              'retired_cases_sha256': sha(here / 'retired_ioctl_cases.h'),
              'file_affinity_sha256': sha(here / 'file_affinity_probe.h'),
              'current_uapi_sha256': sha(here.parents[3]/'include/uapi/linux/sparklink_ioctl.h'),
              'inputs': {name: sha(path) for name, path in paths.items() if path.is_file()}}
    manifest = out / 'manifest.json'

    def save():
        manifest.write_text(json.dumps(record, indent=2) + '\n')

    save()
    try:
        binary = root / 'bin/test'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-O2', '-Wall', '-Wextra',
                        '-Werror', str(here / 'virtual_runtime_test.c'), '-o', str(binary)], check=True)
        record['test_binary_sha256'] = sha(binary)
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
# VM-only ordinary observation access; Virtual injection device stays root-only.
busybox chown 0:1000 /dev/sparklink || fail
busybox chmod 0660 /dev/sparklink || fail
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
        if any(sha(path) != record['inputs'][name]
               for name, path in paths.items() if path.is_file()):
            raise RuntimeError('input changed during VM')
        verify_console(log, result.returncode)
        record.update(status='PASS_VIRTUAL_CORE_HOST_VM',
                      hardware_error_results=[line for line in log.splitlines() if 'VIRTUAL_HARDWARE_ERROR_PASS:' in line],
                      standard_snoop_results=[line for line in log.splitlines() if 'VIRTUAL_STANDARD_SNOOP_PASS:' in line], module_rounds=2,
                      registry_results=[line for line in log.splitlines() if 'GENL_REGISTRY_PASS:' in line],
                      retired_uapi_results=[line for line in log.splitlines() if 'RETIRED_UAPI_ENOTTY_PASS:' in line],
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
