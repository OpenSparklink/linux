#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run a root slkd and ordinary uid-1000 slctl on synthetic WS73 controllers.

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


def require_config(path, authorization=False):
    config = path.read_text().splitlines()
    names = ['RUST', 'SPARKLINK', 'SPARKLINK_SLE', 'SPARKLINK_WS73_USB']
    if authorization:
        names += ['SPARKLINK_GENL', 'CONFIGFS_FS']
    for name in names:
        if f'CONFIG_{name}=y' not in config:
            raise RuntimeError(f'required CONFIG_{name}=y missing; reject unqualified image')


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


def assess(console, code, radio=False, production_policy=False, kernel_authorization=False, management_handoff=False):
    errors = []
    if code:
        errors.append(f'QEMU exit {code}')
    if KERNEL_FAULT.search(console):
        errors.append('kernel fault')
    if re.search(r"thread .+ panicked at|there is no reactor running", console):
        errors.append('userspace runtime panic')
    if 'DAEMON_FAILURE:' in console:
        errors.append('guest assertion failed')
    if re.search(r'/bin/(?:test-daemon|test-radio):[^\n]*not found', console):
        errors.append('guest shell dependency missing')
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
    daemon_uid = 0
    bus = re.findall(rf'^DAEMON_BUS_IDENTITY: pid=([1-9][0-9]*) uid={daemon_uid} owner=(:[0-9]+\.[0-9]+) same_owner=1$',console,re.M)
    if len(bus) != 1 or console.count('DAEMON_BUS_IDENTITY:') != 1:
        errors.append('missing or changed bus-authenticated daemon identity')
    if production_policy:
        expected = ['observer-uid=1001 control-uid=1000 control-primary-gid=1002 control-supplementary-gid=1000 daemon-uid=0 read=allowed '
                    'control=denied observer-denials=16 control-own=denied']
        if re.findall(r'^DAEMON_AUTHORIZATION: (.*)$', console, re.M) != expected:
            errors.append('missing/duplicate/invalid production authorization proof')
        denials = re.findall(r'^AUTH_DENIED: (.*)$', console, re.M)
        if denials != ['own-service', 'StartDiscovery', 'StopDiscovery', 'SubmitScanning',
                       'SubmitStopScanning', 'SubmitStopAdvertising', 'SubmitAdvertising',
                       'unique-owner-write', 'interface-less-write', 'interface-less-read',
                       'Properties.Set', 'future-method', 'foreign-interface',
                       'RemoteService.Read', 'DequeueNotification', 'GetPasskey', 'own-service']:
            errors.append('authorization denial matrix incomplete or reordered')
        if re.findall(r'^AUTH_OBSERVE: (.*)$', console, re.M) != ['observer', 'control']:
            errors.append('observer/control read access missing')
        if re.findall(r'^AUTH_CREDENTIALS: (.*)$', console, re.M) != ['uid=1001 gid=1001 caps=0', 'uid=1000 gid=1002 caps=0']:
            errors.append('ordinary observer/control credentials missing')
    elif any(marker in console for marker in ['DAEMON_AUTHORIZATION:', 'AUTH_DENIED:', 'AUTH_CREDENTIALS:']):
        errors.append('unexpected production authorization evidence')
    if kernel_authorization:
        matrix = re.findall(r'^KERNEL_AUTHORIZATION: (.*)$', console, re.M)
        expected = [f'uid={uid} gid={gid} caps=0 inherited_fd=1 protected=101 denied=101 observe=35 configfs_denied=5 genl_denied=5 unknown=ENOTTY'
                    for uid, gid in [(1001,1001), (1000,1002), (0,0)]]
        if matrix != expected or re.findall(r'^KERNEL_AUTHORIZATION_STATE: (.*)$', console, re.M) != ['unchanged=1 native_admission=0 observe_no_power_sync=1']:
            errors.append('kernel authorization matrix missing, duplicated or incomplete')
        if 'KERNEL_AUTH_FAILURE:' in console:
            errors.append('kernel authorization assertion failed')
    elif 'KERNEL_AUTHORIZATION' in console:
        errors.append('unexpected kernel authorization evidence')
    if console.count('DAEMON_KERNEL_LOG_BEGIN') != 1 or console.count('DAEMON_KERNEL_LOG_END') != 1:
        errors.append('complete kernel log missing')
    elif '[    0.000000]' not in console.split('DAEMON_KERNEL_LOG_BEGIN', 1)[1].split('DAEMON_KERNEL_LOG_END', 1)[0]:
        errors.append('early kernel log missing')
    if radio:
        errors += assess_radio(console)
    elif 'DAEMON_RADIO_' in console:
        errors.append('unexpected radio evidence')
    if management_handoff:
        errors += assess_management(console)
    elif 'DAEMON_MANAGEMENT_' in console:
        errors.append('unexpected management handoff evidence')
    return errors


def assess_management(console):
    errors = []
    if console.count('DAEMON_MANAGEMENT_') != 12:
        errors.append('unexpected or incomplete management evidence')
    phases = re.findall(r'^DAEMON_MANAGEMENT_(BEGIN|RELEASE: signal=TERM retained_fd=2 actual_stop=2 free=2|RESTART: .*|END: signal=INT free=2)$', console, re.M)
    if (len(phases) != 4 or sum(console.count('DAEMON_MANAGEMENT_' + label) for label in ['BEGIN','RELEASE:','RESTART:','END:']) != 4 or phases[0] != 'BEGIN' or
        phases[1] != 'RELEASE: signal=TERM retained_fd=2 actual_stop=2 free=2' or
        not phases[2].startswith('RESTART: ') or phases[3] != 'END: signal=INT free=2'):
        errors.append('missing/duplicate/out-of-order management phases')
    observations = re.findall(r'^DAEMON_MANAGEMENT_OBSERVE: index=(\d+) generation=(\d+) state=(held|free) token_hidden=1 adv=([12]) scan=([12])$', console, re.M)
    views = re.findall(r'^Adapter /org/sparklink/slk(\d+)_g(\d+):', console, re.M)
    if len(views) == 5:
        a, b = views[3], views[4]
        expected = [(a[0],a[1],'held','2','1'), (b[0],b[1],'held','1','2')]
        expected += [(i,g,state,'1','1') for state in ['free','held','free'] for i,g in [a,b]]
        if observations != expected or console.count('DAEMON_MANAGEMENT_OBSERVE:') != 8:
            errors.append('management ownership/radio/generation observations incomplete')
    else:
        errors.append('management identity views missing')
    restart = re.findall(r'^DAEMON_MANAGEMENT_RESTART: old_pid=(\d+) new_pid=(\d+) old_owner=(:\d+\.\d+) new_owner=(:\d+\.\d+) same_generation=2 ready=2$', console, re.M)
    identity = re.findall(r'^DAEMON_BUS_IDENTITY: pid=(\d+) uid=0 owner=(:\d+\.\d+) same_owner=1$', console, re.M)
    if (len(restart) != 1 or len(identity) != 1 or
        restart[0][0] == restart[0][1] or restart[0][2] == restart[0][3] or
        (restart[0][0],restart[0][2]) != identity[0] or int(restart[0][1]) == 0):
        errors.append('management successor bus identity invalid')
    labels = ['DAEMON_HOTPLUG:', 'DAEMON_MANAGEMENT_BEGIN', 'DAEMON_MANAGEMENT_RELEASE:',
              'DAEMON_MANAGEMENT_RESTART:', 'DAEMON_MANAGEMENT_END:', 'DAEMON_LIFECYCLE:']
    positions = [console.find(label) for label in labels]
    if min(positions) < 0 or positions != sorted(positions):
        errors.append('management proof outside shutdown/restart phase')
    # Tie each observer result to its phase, rather than accepting a reordered
    # transcript with all the right strings.
    for n, match in enumerate(re.finditer(r'^DAEMON_MANAGEMENT_OBSERVE:', console, re.M)):
        bounds = [(1,2),(1,2),(2,3),(3,4)][min(n // 2,3)]
        if not positions[bounds[0]] < match.start() < positions[bounds[1]]:
            errors.append('management observation outside expected phase')
    if (console.count('adapter management relinquished while fd retained') != 4 or
        'adapter management cleanup failed' in console):
        errors.append('explicit retained-fd release missing or cleanup failed')
    return errors


def assess_radio(console):
    errors = []
    rounds = re.findall(r'^DAEMON_RADIO_ROUND: phase=(initial|replug) round=(\d+) tx=(/org/sparklink/slk\d+_g\d+) rx=(/org/sparklink/slk\d+_g\d+) marker=([0-9a-f]{32})$', console, re.M)
    expected = [('initial',i) for i in range(1,21)] + [('replug',i) for i in range(1,3)]
    if [(r[0],int(r[1])) for r in rounds] != expected or console.count('DAEMON_RADIO_ROUND:') != 22:
        errors.append('missing/duplicate/out-of-order typed radio rounds')
    if len({r[4] for r in rounds}) != 22:
        errors.append('radio markers not all fresh')
    for prev,cur in zip(rounds,rounds[1:]):
        if cur[0]==prev[0] and (cur[2]!=prev[3] or cur[3]!=prev[2]):
            errors.append('radio roles did not alternate')
    matches = re.findall(r'^NativeDiscoveryMatch: generation=(\d+) seq=(\d+) address=([0-9A-F:]+) RSSI=(-?\d+) marker=([0-9a-f]{32}) data=([0-9a-f]+) kernel_boottime_ns=(\d+) elapsed_ms=(\d+) lost=(\d+)$',console,re.M)
    if len(matches)!=22 or console.count('NativeDiscoveryMatch:') != 22:
        errors.append('missing/duplicate report identity/time/data proof')
    for match,round_record in zip(matches,rounds):
        gen,seq,addr,rssi,marker,data,boot,ms,lost=match
        expected_data=bytes([255,41,1,1,1,11,36])+('slk-'+marker).encode()
        if (marker!=round_record[4] or int(gen)!=int(round_record[3].split('_g')[1])
            or int(seq)==0 or int(rssi)!=-42 or bytes.fromhex(data)!=expected_data
            or int(boot)==0 or int(ms)>=10000 or int(lost)!=0):
            errors.append('invalid fresh report proof')
    identities = {f'/org/sparklink/slk{i}_g{g}': addr for i,g,addr in re.findall(
        r'^Adapter /org/sparklink/slk(\d+)_g(\d+):\n  State:       Ready\n  Generation:  \d+\n  Address:     ([0-9A-F:]+)', console, re.M)}
    seen = {}
    for match, round_record in zip(matches, rounds):
        gen, seq, addr, _, _, _, boot, _, _ = match
        tx, rx = round_record[2:4]
        if tx == rx or tx not in identities or rx not in identities or addr != identities.get(tx):
            errors.append('report address does not identify a distinct live transmitter')
        previous = seen.get(rx, (0, 0))
        if int(seq) <= previous[0] or int(boot) <= previous[1]:
            errors.append('receiver sequence/time did not advance')
        seen[rx] = (int(seq), int(boot))
    operations = re.findall(
        r'^NativeOperationResult: generation=(\d+) request=(\d+) operation=(\d+) state=(\d+) errno=(-?\d+) status=0x([0-9a-f]{2}) opcode=0x([0-9a-f]{4}) step=(\d+)/(\d+) power=(-?\d+) power_valid=(\d+) adv=(\d+) scan=(\d+) profile=(\d+)$', console, re.M)
    if len(operations) != 88 or console.count('NativeOperationResult:') != 88:
        errors.append('missing/duplicate/malformed typed operation results')
    if len({(r[0], r[1]) for r in operations}) != len(operations):
        errors.append('operation identity reused')
    terminal = {1: ('0c05','2','3','-42','1','2','1'),
                3: ('1002','1','2','0','0','1','2'),
                2: ('0c05','0','1','0','0','1','1'),
                4: ('1002','0','1','0','0','1','1')}
    for i, r in enumerate(operations):
        if i // 4 >= len(rounds):
            break
        phase, _, tx, rx, marker = rounds[i // 4]
        op = [1,3,2,4][i % 4]
        owner = tx if op in (1,2) else rx
        if (int(r[0]) != int(owner.split('_g')[1]) or int(r[1]) == 0
                or int(r[2]) != op or r[3:6] != ('3','0','00')
                or r[6:13] != terminal[op] or r[13] != '1'):
            errors.append('invalid selected typed transaction completion')
    admissions = re.findall(r'^NativeAdvertisementAccepted: request=(\d+) marker=([0-9a-f]{32}) data=([0-9a-f]+)$', console, re.M)
    if len(admissions) != 22 or console.count('NativeAdvertisementAccepted:') != 22:
        errors.append('missing/duplicate advertisement admission')
    for i, (request, marker, data) in enumerate(admissions):
        if i >= len(rounds) or i * 4 >= len(operations):
            break
        expected_data = bytes([255,41,1,1,1,11,36]) + ('slk-'+marker).encode()
        if request != operations[i * 4][1] or marker != rounds[i][4] or bytes.fromhex(data) != expected_data:
            errors.append('admission/result/received data correlation mismatch')
    for m in re.finditer(r'^DAEMON_RADIO_ROUND: phase=(initial|replug)', console, re.M):
        lower = console.find('DAEMON_ADD_SECOND' if m[1] == 'initial' else 'DAEMON_READD_FIRST')
        upper = console.find('DAEMON_REMOVE_FIRST' if m[1] == 'initial' else 'DAEMON_HOTPLUG:')
        if lower < 0 or upper < 0 or not lower < m.start() < upper:
            errors.append('radio proof outside live lifecycle phase')
    negatives = re.findall(r'^DAEMON_RADIO_NEGATIVE: phase=(initial|replug) no_new_report=1 duration_ms=2000$',console,re.M)
    if negatives!=['initial','replug']:
        errors.append('missing/duplicate transmitter-off negative control')
    return errors


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ['kernel-build', 'qemu', 'busybox', 'userspace', 'dbus-daemon', 'output']:
        p.add_argument('--' + name, type=Path, required=True)
    p.add_argument('--radio-policy', action='store_true', help='basic policy and explicit synthetic cross-controller medium; never real RF')
    p.add_argument('--production-policy', action='store_true', help='installed D-Bus policy, root daemon, uid-1000 control group and uid-1001 observer')
    p.add_argument('--kernel-authorization', action='store_true', help='actual inherited-fd ioctl/configfs credential-drop matrix')
    p.add_argument('--management-handoff', action='store_true', help='active radio cleanup on SIGTERM, same-generation successor, SIGINT cleanup; NO RF')
    a = p.parse_args()
    if a.management_handoff and not a.radio_policy:
        p.error('--management-handoff requires --radio-policy')
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'scope': 'actual slkd and uid-1000 slctl on synthetic WS73: no firmware/RF acceptance',
                'radio_policy': a.radio_policy,
                'production_policy': a.production_policy,
                'kernel_authorization': a.kernel_authorization,
                'management_handoff': a.management_handoff,
                'started_at': datetime.now(timezone.utc).isoformat(), 'status': 'running'}
    process = monitor = None
    try:
        kernel = a.kernel_build.resolve() / 'arch/x86/boot/bzImage'
        require_config(a.kernel_build.resolve() / '.config', a.kernel_authorization)
        userspace = a.userspace.resolve()
        if a.production_policy:
            policy = userspace / 'data/dbus/sparklink.conf'
            manifest['production_policy_input'] = file_record(policy)
        manifest['inputs'] = [file_record(path) for path in [kernel, a.kernel_build / '.config', a.qemu, a.busybox,
            a.dbus_daemon, Path(__file__), HERE / 'daemon_lifecycle_guest.sh', HERE / 'daemon_radio_guest.sh', HERE / 'qemu-sle-dli/usb-ws73-test.c']]
        if a.kernel_authorization:
            manifest['inputs'].append(file_record(HERE / 'kernel_authorization_test.c'))
        if a.management_handoff:
            manifest['inputs'].append(file_record(HERE / 'daemon_management_test.c'))
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
            build = ['cargo', 'build', '-p', 'slkd', '-p', 'slctl']
            if a.production_policy:
                build += ['--bins', '--examples']
            subprocess.run(build, cwd=userspace,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        root = output / 'initramfs'
        (root / 'bin').mkdir(parents=True)
        shutil.copy2(a.busybox, root / 'bin/busybox')
        if a.kernel_authorization:
            with (output / 'kernel-authorization-build.log').open('w') as log:
                subprocess.run(['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-o', str(root / 'bin/kernel-authorization'), str(HERE / 'kernel_authorization_test.c')],
                    stdout=log, stderr=subprocess.STDOUT, check=True)
        if a.management_handoff:
            with (output / 'management-build.log').open('w') as log:
                subprocess.run(['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-o', str(root / 'bin/daemon-management'), str(HERE / 'daemon_management_test.c')],
                    stdout=log, stderr=subprocess.STDOUT, check=True)
        for name in ['sh', 'mount', 'mdev', 'sleep', 'poweroff', 'dmesg', 'su', 'id', 'grep',
                     'awk', 'seq', 'cat', 'pidof', 'chmod', 'mkdir']:
            (root / 'bin' / name).symlink_to('busybox')
        for name in ['slkd', 'slctl']:
            copy_elf(userspace / 'target/debug' / name, root / 'bin' / name, root)
        if a.production_policy:
            copy_elf(userspace / 'target/debug/examples/bus_policy_probe', root / 'bin/bus-policy-probe', root)
            # Additional debug Rust ELF can exhaust a 512M guest's initramfs.
            # Strip only disposable copies; preserve original/program hashes.
            manifest['unstripped_programs'] = [file_record(userspace / name) for name in
                ['target/debug/slkd', 'target/debug/slctl', 'target/debug/examples/bus_policy_probe']]
            for name in ['slkd', 'slctl', 'bus-policy-probe']:
                subprocess.run(['strip', '--strip-debug', str(root / 'bin' / name)], check=True)
            manifest['guest_strip_debug'] = True
        copy_elf(a.dbus_daemon, root / 'bin/dbus-daemon', root)
        programs = ['slkd', 'slctl', 'dbus-daemon'] + (['bus-policy-probe'] if a.production_policy else []) + (['kernel-authorization'] if a.kernel_authorization else [])
        if a.management_handoff:
            programs.append('daemon-management')
        manifest['guest_programs'] = [file_record(root / 'bin' / name) for name in programs]
        for name in ['proc', 'sys', 'dev', 'etc', 'tmp']:
            (root / name).mkdir()
        (root / 'tmp').chmod(0o1777)
        (root / 'etc/passwd').write_text('root:x:0:0:root:/:/bin/sh\nws73:x:1000:1000:test:/tmp:/bin/sh\n')
        (root / 'etc/group').write_text('root:x:0:\nws73:x:1000:ws73\n')
        (root / 'etc/shadow').write_text('root::0:0:99999:7:::\nws73::0:0:99999:7:::\n')
        (root / 'etc/dbus.conf').write_text('''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>session</type><listen>unix:path=/tmp/slkbus</listen>
<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>
<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
        if a.production_policy:
            (root / 'etc/passwd').write_text((root / 'etc/passwd').read_text().replace('ws73:x:1000:1000:', 'ws73:x:1000:1002:') + 'observer:x:1001:1001:test:/tmp:/bin/sh\n')
            (root / 'etc/group').write_text('root:x:0:\nsparklink:x:1000:ws73\nobserver:x:1001:observer\nws73:x:1002:ws73\n')
            (root / 'etc/shadow').write_text((root / 'etc/shadow').read_text() + 'observer::0:0:99999:7:::\n')
            shutil.copy2(policy, root / 'etc/sparklink.conf')
            config = root / 'etc/dbus.conf'
            config.write_text(config.read_text().replace('</busconfig>', '<include>/etc/sparklink.conf</include></busconfig>'))
        firmware = root / 'lib/firmware/sparklink/ws73'
        firmware.mkdir(parents=True)
        (firmware / 'bsle_custom.bin').write_bytes(bytes(range(140)))
        (firmware / 'pm_config.bin').write_bytes(bytes.fromhex('01000000'))
        shutil.copy2(HERE / 'daemon_radio_guest.sh', root / 'bin/test-radio')
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
/bin/dbus-daemon --config-file=/etc/dbus.conf --nofork > /tmp/dbus.log 2>&1 &
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
        if a.radio_policy:
            f = root / 'init'; f.write_text(f.read_text().replace('export PATH=/bin', 'export PATH=/bin\nexport SPARKLINK_TEST_RADIO=1'))
        if a.production_policy:
            f = root / 'init'
            f.write_text(f.read_text().replace('export PATH=/bin', 'export PATH=/bin\nexport SPARKLINK_TEST_PRODUCTION_POLICY=1'))
        if a.kernel_authorization:
            f = root / 'init'; f.write_text(f.read_text().replace('export PATH=/bin', 'export PATH=/bin\nexport SPARKLINK_TEST_KERNEL_AUTHORIZATION=1'))
        if a.management_handoff:
            f = root / 'init'; f.write_text(f.read_text().replace('export PATH=/bin', 'export PATH=/bin\nexport SPARKLINK_TEST_MANAGEMENT_HANDOFF=1'))
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
                '-device', 'usb-ws73-test,id=sle0,bus=xhci.0,port=1,runtime-discovery=on' + (',runtime-policy=on,runtime-medium=1' if a.radio_policy else '')]
            if os.access('/dev/kvm', os.R_OK | os.W_OK):
                command.append('-enable-kvm')
            manifest['qemu_args'] = command
            with (output / 'qemu_stderr.log').open('wb') as stderr:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
                wait_marker(process, console, 'DAEMON_ADD_SECOND')
                monitor = load_qmp()(socket, output / 'qmp.jsonl')
                props = dict(driver='usb-ws73-test', bus='xhci.0', **{'runtime-discovery': True})
                if a.radio_policy:
                    props.update({'runtime-policy': True, 'runtime-medium': 1})
                monitor.execute('device_add', dict(id='sle1', port='2', **props))
                wait_marker(process, console, 'DAEMON_REMOVE_FIRST')
                monitor.execute('device_del', dict(id='sle0'))
                monitor.wait_deleted('sle0')
                wait_marker(process, console, 'DAEMON_READD_FIRST')
                monitor.execute('device_add', dict(id='sle0', port='1', **props))
                code = process.wait(timeout=30)
            manifest['qemu_exit'] = code
            errors = assess(console.read_text(errors='replace').replace('\r', ''), code, a.radio_policy, a.production_policy, a.kernel_authorization, a.management_handoff)
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
        if 'production_policy_input' in manifest:
            records.append(manifest['production_policy_input'])
        manifest['inputs_and_sources_unchanged'] = all(file_record(Path(x['path'])) == x for x in records)
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(manifest['status'], manifest.get('error', ''))
    return 0 if manifest['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
