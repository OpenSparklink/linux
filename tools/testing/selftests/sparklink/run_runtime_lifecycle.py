#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Virtual Runtime hotplug support gate; never a real WS73/RF verdict."""
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from qemu_verdict import KERNEL_FAULT

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[3]


def assess(console, qemu_exit, recipes=False):
    console = console.replace('\r', '')
    errors = []
    if qemu_exit:
        errors.append(f'QEMU exit {qemu_exit}')
    if KERNEL_FAULT.search(console):
        errors.append('kernel fault')
    if 'RUNTIME_FAILURE:' in console:
        errors.append('guest assertion failure')
    markers = re.findall(r'^RUNTIME_(ADD_SECOND|REMOVE_FIRST|READD_FIRST|LIFECYCLE: PASS)$',
                         console, re.MULTILINE)
    if markers != ['ADD_SECOND', 'REMOVE_FIRST', 'READD_FIRST', 'LIFECYCLE: PASS']:
        errors.append('missing, duplicate or out-of-order lifecycle markers')
    queries = re.findall(r'^RUNTIME_QUERY: index=(\d+) addr=([0-9a-f]{2}(?::[0-9a-f]{2}){5})$',
                         console, re.MULTILINE)
    if [index for index, _ in queries] != ['0', '1', '1', '0', '1']:
        errors.append('missing or unexpected DLI queries')
    elif queries[1][1] != queries[2][1] or queries[1][1] != queries[4][1]:
        errors.append('unaffected adapter address changed')
    bursts = re.findall(r'^RUNTIME_HOST_BURST: index=(\d+) mac=12 reset=2 '
                        r'submitted=13 resolved=13 timeouts=0$', console, re.MULTILINE)
    if sorted(bursts) != ['0', '1']:
        errors.append('missing, duplicate or incorrect per-owner Host burst evidence')
    proofs = re.findall(r'^RUNTIME_RECIPE: index=(\d+) adv_complete=2 scan_complete=2 '
                        r'status=4 mac=4 isolated=1$', console, re.MULTILINE)
    if recipes and sorted(proofs) != ['0', '1']:
        errors.append('missing, duplicate or incorrect typed recipe proof')
    if recipes:
        if len(re.findall(r'^RUNTIME_RECIPE:', console, re.MULTILINE)) != len(proofs):
            errors.append('malformed typed recipe evidence')
        remove = console.find('RUNTIME_REMOVE_FIRST')
        if any(match.start() > remove for match in re.finditer(r'^RUNTIME_RECIPE:', console, re.MULTILINE)):
            errors.append('typed recipe evidence after removal')
        if (console.count('RUNTIME_KERNEL_LOG_BEGIN') != 1
                or console.count('RUNTIME_KERNEL_LOG_END') != 1):
            errors.append('missing or duplicate complete recipe kernel log')
        else:
            log = console.split('RUNTIME_KERNEL_LOG_BEGIN', 1)[1].split('RUNTIME_KERNEL_LOG_END', 1)[0]
            if '[    0.000000]' not in log:
                errors.append('recipe kernel log missing early record')
    if not recipes and 'RUNTIME_RECIPE:' in console:
        errors.append('unexpected typed recipe evidence')
    if re.findall(r'^RUNTIME_GUEST_EXIT: (\d+)$', console, re.MULTILINE) != ['0']:
        errors.append('missing or unsuccessful guest exit')
    return errors


def assess_native(console, qemu_exit, fault=False, events=False):
    console = console.replace('\r', '')
    errors = []
    if qemu_exit:
        errors.append(f'QEMU exit {qemu_exit}')
    if KERNEL_FAULT.search(console):
        errors.append('kernel fault')
    if (console.count('RUNTIME_KERNEL_LOG_BEGIN') != 1
            or console.count('RUNTIME_KERNEL_LOG_END') != 1):
        errors.append('missing or duplicate complete native kernel log')
    else:
        log = console.split('RUNTIME_KERNEL_LOG_BEGIN', 1)[1].split('RUNTIME_KERNEL_LOG_END', 1)[0]
        if '[    0.000000]' not in log:
            errors.append('native kernel log missing early record')
    if 'NATIVE_FAILURE:' in console:
        errors.append('native guest assertion failure')
    markers = re.findall(r'^NATIVE_(ADD_SECOND|REMOVE_FIRST|FAULT_FIRST|READD_FIRST|LIFECYCLE: PASS)$',
                         console, re.MULTILINE)
    removal = 'FAULT_FIRST' if fault else 'REMOVE_FIRST'
    if markers != ['ADD_SECOND', removal, 'READD_FIRST', 'LIFECYCLE: PASS']:
        errors.append('missing, duplicate or out-of-order native lifecycle markers')
    hosts = re.findall(r'^NATIVE_HOST: index=(\d+) queries=18 features=80 version=5 dialect_reject=1$',
                       console, re.MULTILINE)
    if sorted(hosts) != (['1'] if fault else ['0', '1']):
        errors.append('missing or duplicate independent native Host queries')
    evidence = 'NATIVE_FAULT: id=0 removed errno=71' if fault else 'NATIVE_RAW_STATUS: fe preserved'
    if console.count(evidence) != 1:
        errors.append('missing or duplicate exact native status/fault evidence')
    generations = re.findall(r'^NATIVE_LIFETIME: old=(\d+) new=(\d+) unaffected=(\d+)$',
                            console, re.MULTILINE)
    if len(generations) != 1:
        errors.append('missing or duplicate native generation evidence')
    else:
        old, new, unaffected = map(int, generations[0])
        if not old or new <= old or not unaffected or unaffected in (old, new):
            errors.append('invalid native generation isolation')
    if re.findall(r'^RUNTIME_GUEST_EXIT: (\d+)$', console, re.MULTILINE) != ['0']:
        errors.append('missing or unsuccessful guest exit')
    event_evidence = re.findall(r'^NATIVE_EVENTS: index=(\d+) retained=32 first=9 last=40 '
                                r'lost=8 payload=278 fanout=2 fault_retry=1 poll=1$',
                                console, re.MULTILINE)
    if sorted(event_evidence) != (['0', '1'] if events else []):
        errors.append('missing, duplicate or unexpected complete native event evidence')
    replug = 'NATIVE_EVENTS_REPLUG: seq=9 lost=8 old_hup=1 new_generation=1'
    if console.count(replug) != (1 if events else 0):
        errors.append('missing, duplicate or unexpected native event replug evidence')
    return errors


def file_record(path):
    path = Path(path).resolve()
    return dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest())


def wait_marker(process, console, marker):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        data = console.read_text(errors='replace') if console.exists() else ''
        if marker in data:
            return
        if 'RUNTIME_FAILURE:' in data or 'NATIVE_FAILURE:' in data:
            # Let init print dmesg and power off before terminating a failed VM.
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            raise RuntimeError(f'guest assertion before {marker}')
        if process.poll() is not None:
            raise RuntimeError(f'guest stopped before {marker}')
        time.sleep(0.05)
    raise TimeoutError(f'guest deadline for {marker}')


def load_qmp():
    spec = importlib.util.spec_from_file_location('runtime_lab_qmp', HERE / 'ws73-lab.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.Qmp


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel-build', type=Path, required=True)
    parser.add_argument('--qemu', type=Path, required=True)
    parser.add_argument('--busybox', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-ws73', action='store_true',
                        help='synthetic WS73 HCC/BSLE/URB bootstrap; never real WS73/RF')
    parser.add_argument('--standard-host-recipes', action='store_true',
                        help='standard USB typed controls wait for delayed Complete; not native WS73 RF')
    parser.add_argument('--native-ws73-fault', action='store_true',
                        help='inject one malformed native aggregate, retaining the other owner')
    parser.add_argument('--native-ws73-fault-mode', choices=['hcc', 'short-reply', 'trailing-reply'],
                        default='hcc', help='fault boundary: HCC aggregate or successful Complete schema')
    parser.add_argument('--native-ws73-events', action='store_true',
                        help='synthetic maximum reports, fanout/loss/poll/copy-fault and replug')
    args = parser.parse_args()
    if args.standard_host_recipes and args.native_ws73:
        parser.error('--standard-host-recipes cannot use --native-ws73')
    if args.native_ws73_fault and not args.native_ws73:
        parser.error('--native-ws73-fault requires --native-ws73')
    if args.native_ws73_fault_mode != 'hcc' and not args.native_ws73_fault:
        parser.error('--native-ws73-fault-mode requires --native-ws73-fault')
    if args.native_ws73_events and (not args.native_ws73 or args.native_ws73_fault):
        parser.error('--native-ws73-events requires --native-ws73 without --native-ws73-fault')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    build = args.kernel_build.resolve()
    kernel = build / 'arch/x86/boot/bzImage'
    console = output / 'console.log'
    scope = ('synthetic WS73 USB HCC/BSLE/native SETUP lifetime; no ROM/RF/slkd/no-sudo acceptance'
             if args.native_ws73 else 'virtual standard-DLI Runtime lifetime; not WS73/RF/slkd/no-sudo acceptance')
    manifest = dict(scope=scope, native_fault_injection=args.native_ws73_fault,
                    standard_host_recipes=args.standard_host_recipes,
                    native_fault_mode=args.native_ws73_fault_mode if args.native_ws73_fault else None,
                    native_event_stream=args.native_ws73_events,
                    started_at=datetime.now(timezone.utc).isoformat(), status='running')
    process = monitor = None
    try:
        config = (build / '.config').read_text()
        for symbol in ['RUST', 'SPARKLINK', 'USB', 'SPARKLINK_SLE']:
            if f'CONFIG_{symbol}=y\n' not in config:
                raise RuntimeError(f'CONFIG_{symbol}=y required')
        if 'statically linked' not in subprocess.check_output(
                ['file', str(args.busybox)], text=True):
            raise RuntimeError('static busybox required')
        changes = subprocess.check_output(['git', 'ls-files', '--modified', '--others',
                                          '--exclude-standard'], cwd=SOURCE, text=True).splitlines()
        manifest['sources'] = [file_record(SOURCE / p) for p in sorted(set(changes))
                               if (SOURCE / p).is_file()]
        manifest['head'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'],
                                                    cwd=SOURCE, text=True).strip()
        manifest['dirty_diff_sha256'] = hashlib.sha256(subprocess.check_output(
            ['git', 'diff'], cwd=SOURCE)).hexdigest()
        manifest['inputs'] = [file_record(p) for p in [kernel, build / '.config', args.qemu,
                                                       args.busybox, HERE / 'ws73-lab.py',
                                                       HERE / 'qemu_verdict.py']]
        prefix = 'NATIVE' if args.native_ws73 else 'RUNTIME'
        model = 'usb-ws73-test' if args.native_ws73 else 'usb-sle-dli'
        source = HERE / ('ws73_native_runtime_test.c' if args.native_ws73 else 'sparklink_runtime_test.c')
        initroot = output / 'initramfs'
        (initroot / 'bin').mkdir(parents=True)
        for name in ['proc', 'sys', 'dev']:
            (initroot / name).mkdir()
        shutil.copy2(args.busybox, initroot / 'bin/busybox')
        for applet in ['sh', 'mount', 'mdev', 'sleep', 'poweroff', 'dmesg']:
            (initroot / 'bin' / applet).symlink_to('busybox')
        compile_args = ['gcc', '-static', '-O2', '-Wall', '-Wextra', '-Werror',
                        str(source), '-o',
                        str(initroot / 'bin/sparklink_runtime_test')]
        manifest['compile_args'] = compile_args
        with (output / 'build.log').open('wb') as log:
            subprocess.run(compile_args, stdout=log, stderr=subprocess.STDOUT, check=True)
        if args.native_ws73:
            firmware = initroot / 'lib/firmware/sparklink/ws73'
            firmware.mkdir(parents=True)
            # Arbitrary synthetic bytes, explicitly never deployable calibration.
            (firmware / 'bsle_custom.bin').write_bytes(bytes(range(140)))
            (firmware / 'pm_config.bin').write_bytes(bytes.fromhex('01000000'))
            manifest['synthetic_configuration'] = [file_record(firmware / name)
                                                   for name in ['bsle_custom.bin', 'pm_config.bin']]
        (initroot / 'init').write_text('''#!/bin/sh
export PATH=/bin
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev || mdev -s
for n in 1 2 3 4 5 6 7 8 9 10; do
    [ -c /dev/sparklink ] && break
    sleep 0.1
done
/bin/sparklink_runtime_test
status=$?
echo "RUNTIME_GUEST_EXIT: $status"
echo "RUNTIME_KERNEL_LOG_BEGIN"
dmesg
echo "RUNTIME_KERNEL_LOG_END"
poweroff -f
''')
        if args.native_ws73_fault:
            initfile = initroot / 'init'
            initfile.write_text(initfile.read_text().replace('/bin/sparklink_runtime_test\n',
                                                          '/bin/sparklink_runtime_test --fault\n'))
        if args.native_ws73_events:
            initfile = initroot / 'init'
            initfile.write_text(initfile.read_text().replace('/bin/sparklink_runtime_test\n',
                                                          '/bin/sparklink_runtime_test --events\n'))
        if args.standard_host_recipes:
            initfile = initroot / 'init'
            initfile.write_text(initfile.read_text().replace('/bin/sparklink_runtime_test\n',
                                                          '/bin/sparklink_runtime_test --recipes\n'))
        (initroot / 'init').chmod(0o755)
        archive = output / 'initramfs.cpio.gz'
        with (output / 'pack.log').open('wb') as log, archive.open('wb') as packed:
            files = subprocess.Popen(['find', '.', '-print0'], cwd=initroot, stdout=subprocess.PIPE)
            cpio = subprocess.Popen(['cpio', '--null', '-o', '--format=newc'], cwd=initroot,
                                    stdin=files.stdout, stdout=subprocess.PIPE, stderr=log)
            files.stdout.close()
            gzip = subprocess.Popen(['gzip', '-n'], stdin=cpio.stdout, stdout=packed, stderr=log)
            cpio.stdout.close()
            codes = [files.wait(), cpio.wait(), gzip.wait()]
            if any(codes):
                raise RuntimeError(f'initramfs packing failed: {codes}')
        manifest['initramfs'] = file_record(archive)
        with tempfile.TemporaryDirectory(prefix='sparklink-runtime-qmp-') as temp:
            sock = Path(temp) / 'monitor.sock'
            command = [str(args.qemu.resolve()), '-kernel', str(kernel), '-initrd', str(archive),
                       '-append', 'console=ttyS0 loglevel=5 log_buf_len=4M panic=1 oops=panic',
                       '-serial', f'file:{console}', '-display', 'none', '-no-reboot',
                       '-m', '256M', '-smp', '2', '-qmp', f'unix:{sock},server=on,wait=off',
                       '-device', 'qemu-xhci,id=xhci',
                       '-device', f'{model},id=sle0,bus=xhci.0,port=1' +
                       (',runtime-fault=' + str({'hcc': 1, 'short-reply': 2, 'trailing-reply': 3}[
                            args.native_ws73_fault_mode]) if args.native_ws73_fault else
                        ',runtime-status=254' if args.native_ws73 else '') +
                       (',runtime-reports=40' if args.native_ws73_events else '')]
            if args.standard_host_recipes:
                command[-1] += ',recipe-status=on'
            if os.access('/dev/kvm', os.R_OK | os.W_OK):
                command.append('-enable-kvm')
            manifest['qemu_args'] = command
            with (output / 'qemu_stderr.log').open('wb') as stderr:
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=stderr)
                wait_marker(process, console, f'{prefix}_ADD_SECOND')
                monitor = load_qmp()(sock, output / 'qmp.jsonl')
                event_properties = {'runtime-reports': 40} if args.native_ws73_events else {}
                if args.standard_host_recipes:
                    event_properties['recipe-status'] = True
                monitor.execute('device_add', dict(driver=model, id='sle1',
                                                    bus='xhci.0', port='2', **event_properties))
                wait_marker(process, console, f'{prefix}_FAULT_FIRST' if args.native_ws73_fault
                            else f'{prefix}_REMOVE_FIRST')
                monitor.execute('device_del', dict(id='sle0'))
                monitor.wait_deleted('sle0')
                wait_marker(process, console, f'{prefix}_READD_FIRST')
                monitor.execute('device_add', dict(driver=model, id='sle0',
                                                    bus='xhci.0', port='1', **event_properties))
                exit_code = process.wait(timeout=30)
            manifest['qemu_exit'] = exit_code
            verify = assess_native if args.native_ws73 else assess
            errors = (verify(console.read_text(errors='replace'), exit_code, args.native_ws73_fault,
                             args.native_ws73_events)
                      if args.native_ws73 else verify(console.read_text(errors='replace'), exit_code,
                                                     args.standard_host_recipes))
            if errors:
                raise RuntimeError('; '.join(errors))
        manifest['status'] = 'PASS'
    except Exception as error:
        manifest['status'] = 'FAIL'
        manifest['error'] = f'{type(error).__name__}: {error}'
    finally:
        if monitor:
            monitor.close()
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if 'inputs' in manifest:
            try:
                manifest['input_files_unchanged'] = all(file_record(p['path']) == p
                                                       for p in manifest['inputs'])
                changes = subprocess.check_output(['git', 'ls-files', '--modified', '--others',
                                                  '--exclude-standard'], cwd=SOURCE, text=True).splitlines()
                final_sources = [file_record(SOURCE / p) for p in sorted(set(changes))
                                 if (SOURCE / p).is_file()]
                final_diff = hashlib.sha256(subprocess.check_output(['git', 'diff'], cwd=SOURCE)).hexdigest()
                manifest['source_files_unchanged'] = (final_sources == manifest['sources']
                                                     and final_diff == manifest['dirty_diff_sha256'])
                if not manifest['input_files_unchanged'] or not manifest['source_files_unchanged']:
                    manifest['status'] = 'FAIL'
                    manifest['error'] = manifest.get('error', '') + '; input artifacts or source changed during run'
            except Exception as error:
                manifest['status'] = 'FAIL'
                manifest['error'] = manifest.get('error', '') + f'; final input verification: {error}'
        manifest['completed_at'] = datetime.now(timezone.utc).isoformat()
        manifest['artifacts'] = [file_record(p) for p in output.iterdir() if p.is_file()]
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    label = 'SYNTHETIC_WS73_RUNTIME' if args.native_ws73 else 'VIRTUAL_RUNTIME_LIFECYCLE'
    print(f'{label}: {manifest["status"]}')
    if manifest.get('error'):
        print(manifest['error'])
    return 0 if manifest['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
