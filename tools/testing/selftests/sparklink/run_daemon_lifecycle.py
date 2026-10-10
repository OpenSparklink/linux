#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run real slkd/slctl binaries as uid 1000 on synthetic WS73 controllers.

Host prepares a disposable guest, no host sudo/USB access required. This proves
userspace/kernel lifecycle integration only, never WS73 firmware or RF behavior.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from run_runtime_lifecycle import file_record, load_qmp, wait_marker
from qemu_verdict import KERNEL_FAULT

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[3]


def copy_elf(source, target, root):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    dependencies = subprocess.check_output(['ldd', str(source)], text=True)
    for dependency in re.findall(r'(?:=>\s+)?(/[^\s()]+)', dependencies):
        path = Path(dependency)
        if path.is_file():
            dest = root / str(path).lstrip('/')
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)


def assess(console, code):
    errors = []
    if code:
        errors.append(f'QEMU exit {code}')
    if KERNEL_FAULT.search(console):
        errors.append('kernel fault')
    if 'DAEMON_FAILURE:' in console:
        errors.append('guest assertion failed')
    markers = re.findall(r'^DAEMON_(UID: 1000|ADD_SECOND|REMOVE_FIRST|STALE_SELECTION: rejected|READD_FIRST|HOTPLUG: independent=2 same_process=1 new_generation=1|LIFECYCLE: PASS)$', console, re.M)
    if markers != ['UID: 1000', 'ADD_SECOND', 'REMOVE_FIRST', 'STALE_SELECTION: rejected',
                   'READD_FIRST', 'HOTPLUG: independent=2 same_process=1 new_generation=1', 'LIFECYCLE: PASS']:
        errors.append('missing, duplicate or out-of-order daemon proof')
    views = re.findall(r'^Adapter /org/sparklink/slk(\d+)_g(\d+):\n  State:       Ready\n  Generation:  (\d+)\n  Address:     ([0-9A-F:]+)\n  Profile:     1$', console, re.M)
    if [v[0] for v in views] != ['0', '1', '1', '0', '1'] or any(v[1] != v[2] for v in views):
        errors.append('missing or invalid selected Ready identity views')
    elif not (views[1] == views[2] == views[4] and views[0][1] != views[3][1]):
        errors.append('survivor changed or replacement generation reused')
    if re.findall(r'^DAEMON_GUEST_EXIT: (\d+)$', console, re.M) != ['0']:
        errors.append('guest exit missing or nonzero')
    if console.count('DAEMON_KERNEL_LOG_BEGIN') != 1 or console.count('DAEMON_KERNEL_LOG_END') != 1:
        errors.append('complete kernel log missing')
    elif '[    0.000000]' not in console.split('DAEMON_KERNEL_LOG_BEGIN', 1)[1].split('DAEMON_KERNEL_LOG_END', 1)[0]:
        errors.append('early kernel log missing')
    return errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['kernel-build', 'qemu', 'busybox', 'userspace', 'dbus-daemon', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'scope': 'real uid-1000 slkd/slctl on synthetic WS73: no firmware/RF acceptance',
                'started_at': datetime.now(timezone.utc).isoformat(), 'status': 'running'}
    process = monitor = None
    try:
        kernel = a.kernel_build.resolve() / 'arch/x86/boot/bzImage'
        userspace = a.userspace.resolve()
        manifest['inputs'] = [file_record(path) for path in [kernel, a.kernel_build / '.config', a.qemu, a.busybox,
            a.dbus_daemon, Path(__file__), HERE / 'daemon_lifecycle_guest.sh']]
        tracked = subprocess.check_output(['git', 'ls-files', 'crates', 'Cargo.toml', 'Cargo.lock'],
                                         cwd=userspace, text=True).splitlines()
        # Include untracked new implementation files before committing them.
        tracked += subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', 'crates'],
                                          cwd=userspace, text=True).splitlines()
        manifest['userspace_sources'] = [file_record(userspace / x) for x in sorted(set(tracked))]
        manifest['kernel_sources'] = [file_record(SOURCE / x) for x in subprocess.check_output(
            ['git', 'ls-files', '--modified', '--others', '--exclude-standard'], cwd=SOURCE, text=True).splitlines()
            if (SOURCE / x).is_file()]
        manifest['userspace_head'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=userspace, text=True).strip()
        with (output / 'build.log').open('w') as log:
            subprocess.run(['cargo', 'build', '-p', 'slkd', '-p', 'slctl'], cwd=userspace,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        root = output / 'initramfs'
        (root / 'bin').mkdir(parents=True)
        shutil.copy2(a.busybox, root / 'bin/busybox')
        for name in ['sh', 'mount', 'mdev', 'sleep', 'poweroff', 'dmesg', 'su', 'id', 'grep',
                     'awk', 'seq', 'cat', 'pidof', 'chmod', 'mkdir']:
            (root / 'bin' / name).symlink_to('busybox')
        for name in ['slkd', 'slctl']:
            copy_elf(userspace / 'target/debug' / name, root / 'bin' / name, root)
        copy_elf(a.dbus_daemon, root / 'bin/dbus-daemon', root)
        manifest['guest_programs'] = [file_record(root / 'bin' / name) for name in ['slkd', 'slctl', 'dbus-daemon']]
        for name in ['proc', 'sys', 'dev', 'etc', 'tmp']:
            (root / name).mkdir()
        (root / 'tmp').chmod(0o1777)
        (root / 'etc/passwd').write_text('root:x:0:0:root:/:/bin/sh\nws73:x:1000:1000:test:/tmp:/bin/sh\n')
        (root / 'etc/group').write_text('root:x:0:\nws73:x:1000:ws73\n')
        (root / 'etc/shadow').write_text('root::0:0:99999:7:::\nws73::0:0:99999:7:::\n')
        (root / 'etc/dbus.conf').write_text('''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path=/tmp/slkbus</listen>
<auth>EXTERNAL</auth><policy context="default"><allow own="*"/>
<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
        firmware = root / 'lib/firmware/sparklink/ws73'
        firmware.mkdir(parents=True)
        (firmware / 'bsle_custom.bin').write_bytes(bytes(range(140)))
        (firmware / 'pm_config.bin').write_bytes(bytes.fromhex('01000000'))
        shutil.copy2(HERE / 'daemon_lifecycle_guest.sh', root / 'bin/test-daemon')
        (root / 'bin/test-daemon').chmod(0o755)
        (root / 'init').write_text('''#!/bin/sh
export PATH=/bin
export DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/slkbus
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev || mdev -s
for n in $(seq 1 100); do [ -c /dev/sparklink ] && break; sleep 0.1; done
/bin/busybox chown 0:1000 /dev/sparklink
chmod 0660 /dev/sparklink
su ws73 -s /bin/sh -c 'exec /bin/dbus-daemon --config-file=/etc/dbus.conf --nofork' > /tmp/dbus.log 2>&1 &
for n in $(seq 1 100); do [ -S /tmp/slkbus ] && break; sleep 0.1; done
/bin/test-daemon
status=$?
echo "DAEMON_GUEST_EXIT: $status"
cat /tmp/dbus.log
echo "DAEMON_KERNEL_LOG_BEGIN"
dmesg
echo "DAEMON_KERNEL_LOG_END"
poweroff -f
''')
        (root / 'init').chmod(0o755)
        archive = output / 'initramfs.cpio.gz'
        with (output / 'pack.log').open('wb') as log, archive.open('wb') as packed:
            files = subprocess.Popen(['find', '.', '-print0'], cwd=root, stdout=subprocess.PIPE)
            cpio = subprocess.Popen(['cpio', '--null', '-o', '--format=newc'], cwd=root,
                                    stdin=files.stdout, stdout=subprocess.PIPE, stderr=log)
            files.stdout.close()
            gzip = subprocess.Popen(['gzip', '-n'], stdin=cpio.stdout, stdout=packed, stderr=log)
            cpio.stdout.close()
            if any([files.wait(), cpio.wait(), gzip.wait()]):
                raise RuntimeError('initramfs packing failed')
        manifest['initramfs'] = file_record(archive)
        manifest['guest_files'] = [file_record(x) for x in sorted(root.rglob('*')) if x.is_file() and not x.is_symlink()]
        with tempfile.TemporaryDirectory(prefix='sparklink-daemon-qmp-') as tmp:
            socket = Path(tmp) / 'monitor.sock'
            console = output / 'console.log'
            command = [str(a.qemu.resolve()), '-kernel', str(kernel), '-initrd', str(archive),
                '-append', 'console=ttyS0 loglevel=5 log_buf_len=4M panic=1 oops=panic',
                '-serial', f'file:{console}', '-display', 'none', '-no-reboot', '-m', '512M', '-smp', '2',
                '-qmp', f'unix:{socket},server=on,wait=off', '-device', 'qemu-xhci,id=xhci',
                '-device', 'usb-ws73-test,id=sle0,bus=xhci.0,port=1,runtime-discovery=on']
            if os.access('/dev/kvm', os.R_OK | os.W_OK):
                command.append('-enable-kvm')
            manifest['qemu_args'] = command
            with (output / 'qemu_stderr.log').open('wb') as stderr:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
                wait_marker(process, console, 'DAEMON_ADD_SECOND')
                monitor = load_qmp()(socket, output / 'qmp.jsonl')
                props = dict(driver='usb-ws73-test', bus='xhci.0', **{'runtime-discovery': True})
                monitor.execute('device_add', dict(id='sle1', port='2', **props))
                wait_marker(process, console, 'DAEMON_REMOVE_FIRST')
                monitor.execute('device_del', dict(id='sle0'))
                monitor.wait_deleted('sle0')
                wait_marker(process, console, 'DAEMON_READD_FIRST')
                monitor.execute('device_add', dict(id='sle0', port='1', **props))
                code = process.wait(timeout=30)
            manifest['qemu_exit'] = code
            errors = assess(console.read_text(errors='replace').replace('\r', ''), code)
            if errors:
                raise RuntimeError('; '.join(errors))
        manifest['status'] = 'PASS'
    except Exception as error:
        manifest['status'] = 'FAIL'
        manifest['error'] = str(error)
    finally:
        if monitor is not None:
            monitor.close()
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        manifest['finished_at'] = datetime.now(timezone.utc).isoformat()
        records = manifest.get('inputs', []) + manifest.get('userspace_sources', []) + manifest.get('kernel_sources', [])
        manifest['inputs_and_sources_unchanged'] = all(file_record(Path(x['path'])) == x for x in records)
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(manifest['status'], manifest.get('error', ''))
    return 0 if manifest['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
