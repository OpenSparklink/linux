#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a WS73 test kernel and run a headless KVM USB-passthrough gate."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

SOURCE = Path(__file__).resolve().parents[4]
WORKSPACE = SOURCE.parent
IMAGES = ("ws73.bin", "wifi_cali.bin", "btc_cali.bin")
MANIFEST_VERSION = 1
PACK_MANIFEST = 'ws73-firmware-manifest.json'
BUILD_MANIFEST = 'ws73-kernel-build.json'


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return dict(path=str(path.resolve()), size=size, sha256=digest.hexdigest())


def write_json(path, value):
    """Replace a complete record atomically, including after a failed run."""
    with tempfile.NamedTemporaryFile(mode='w', dir=path.parent,
                                     prefix=path.name + '.', delete=False) as output:
        temporary = Path(output.name)
        try:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write('\n')
            output.close()
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


def version(command):
    argv = [str(x) for x in command]
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=10)
        return dict(argv=argv, returncode=result.returncode,
                    output=result.stdout.strip())
    except (OSError, subprocess.TimeoutExpired) as error:
        return dict(argv=argv, unavailable=str(error))


def source_snapshot(path):
    """Include untracked source: new drivers are not in git diff HEAD yet."""
    def git(*arguments):
        return subprocess.check_output(['git', '-C', str(path), *arguments],
                                       stderr=subprocess.PIPE)

    try:
        root = Path(os.fsdecode(git('rev-parse', '--show-toplevel')).strip())
        if root.resolve() != path.resolve():
            return dict(path=str(path), unavailable='not a repository root')
        revision = git('rev-parse', 'HEAD').decode().strip()
        status = git('status', '--porcelain=v1', '-z')
        diff = git('diff', '--binary', 'HEAD', '--')
        untracked = []
        for name in sorted(git('ls-files', '--others', '--exclude-standard', '-z').split(b'\0')):
            if not name:
                continue
            relative = os.fsdecode(name)
            source = path / relative
            if source.is_symlink():
                record = dict(path=relative, symlink=os.readlink(source))
            else:
                record = file_record(source)
                record['path'] = relative
            untracked.append(record)
        return dict(path=str(path.resolve()), revision=revision, dirty=bool(status),
                    tracked_diff_sha256=sha256(diff), status_sha256=sha256(status),
                    untracked=untracked,
                    untracked_sha256=sha256(json.dumps(untracked, sort_keys=True).encode()))
    except (OSError, subprocess.CalledProcessError) as error:
        return dict(path=str(path), unavailable=str(error))


def sources():
    return {name: source_snapshot(WORKSPACE / name)
            for name in ('linux', 'sparklink', 'libws73-usb', 'ws73_SDK')}


@contextmanager
def lab_lock(args, path=None):
    """One inode is kept across commands, so unlocking cannot race unlink."""
    path = path or WORKSPACE / '.dev/ws73-lab.lock'
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a+') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError(f'another WS73 lab command owns {path}') from error
        lock.seek(0)
        lock.truncate()
        json.dump(dict(pid=os.getpid(), action=args.action,
                       build_dir=str(args.build_dir), started_at=utc_now()), lock)
        lock.flush()
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def checked(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def inventory():
    result = []
    for device in sorted(Path('/sys/bus/usb/devices').iterdir()):
        try:
            if (device / 'idVendor').read_text().strip() != 'ffff' or \
               (device / 'idProduct').read_text().strip() != '3733':
                continue
            bus = int((device / 'busnum').read_text())
            address = int((device / 'devnum').read_text())
            node = Path(f'/dev/bus/usb/{bus:03d}/{address:03d}')
            interfaces = []
            for intf in sorted(device.glob(device.name + ':*')):
                driver = intf / 'driver'
                interfaces.append(dict(name=intf.name,
                    endpoints=int((intf / 'bNumEndpoints').read_text(), 16),
                    driver=driver.resolve().name if driver.exists() else None))
            result.append(dict(path=device.name, bus=bus, address=address,
                               node=str(node), writable=os.access(node, os.W_OK),
                               interfaces=interfaces))
        except (FileNotFoundError, NotADirectoryError):
            continue
    return result


def make_args(args):
    tools = WORKSPACE / '.dev/tools/bin'
    rustc = args.rustc or shutil.which('rustc')
    if not rustc:
        raise ValueError('rustc is required')
    sysroot = subprocess.check_output([rustc, '--print', 'sysroot'], text=True).strip()
    # Resolve rustup proxies once, so rustc and its rust-src match.
    rustbin = Path(sysroot) / 'bin'
    bindgen = args.bindgen or str(tools / 'bindgen')
    if not Path(bindgen).is_file():
        bindgen = shutil.which('bindgen')
    if not bindgen:
        raise ValueError('bindgen is required; install bindgen-cli into .dev/tools')
    return ['make', '-C', SOURCE, f'O={args.build_dir}', 'LLVM=1',
            'CC=/usr/bin/clang', 'HOSTCC=/usr/bin/clang',
            f'RUSTC={rustbin / "rustc"}', f'RUSTDOC={rustbin / "rustdoc"}',
            f'BINDGEN={bindgen}']


def configure(args):
    command = make_args(args)
    checked(command + ['rustavailable'])
    checked(command + ['x86_64_defconfig'])
    config = [SOURCE / 'scripts/config', '--file', args.build_dir / '.config']
    for option in ('RUST', 'SPARKLINK', 'SPARKLINK_DRIVERS', 'SPARKLINK_WS73_USB',
                   'CRYPTO_LIB_SHA256', 'USB', 'USB_XHCI_HCD', 'USB_XHCI_PCI',
                   'DEVTMPFS', 'DEVTMPFS_MOUNT', 'BLK_DEV_INITRD', 'IKCONFIG',
                   'IKCONFIG_PROC', 'CONFIGFS_FS', 'RUST_FW_LOADER_ABSTRACTIONS'):
        config += ['--enable', option]
    for option in ('WERROR', 'DEBUG_INFO', 'DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT',
                   'MODVERSIONS', 'MODULE_SIG', 'SYSTEM_TRUSTED_KEYRING'):
        config += ['--disable', option]
    checked(config)
    checked(command + ['olddefconfig'])
    actual = (args.build_dir / '.config').read_text()
    for option in ('RUST', 'SPARKLINK', 'SPARKLINK_WS73_USB', 'USB_XHCI_PCI'):
        if f'CONFIG_{option}=y\n' not in actual:
            raise ValueError(f'CONFIG_{option} was disabled by dependencies')


def build(args):
    command = make_args(args) + [f'-j{args.jobs}', 'bzImage']
    before = source_snapshot(SOURCE)
    tools = {'make': version(['make', '--version'])}
    for option in command:
        if isinstance(option, str) and option.startswith(('CC=', 'HOSTCC=', 'RUSTC=',
                                                         'RUSTDOC=', 'BINDGEN=')):
            name, binary = option.split('=', 1)
            tools[name] = version([binary, '--version'])
    checked(command)
    after = source_snapshot(SOURCE)
    configuration = (args.build_dir / '.config').read_bytes()
    (args.build_dir / 'ws73-kernel.config').write_bytes(configuration)
    write_json(args.build_dir / BUILD_MANIFEST, dict(
        schema_version=MANIFEST_VERSION, created_at=utc_now(),
        kernel=file_record(args.build_dir / 'arch/x86/boot/bzImage'),
        config_sha256=sha256(configuration), config_snapshot='ws73-kernel.config',
        source_before=before, source_after=after,
        source_unchanged=bool(before.get('revision') and before == after),
        command=[str(x) for x in command], tools=tools))


def firmware(args):
    verified = {}
    for name in IMAGES:
        path = args.firmware_dir / name
        blob = path.read_bytes()
        if not 64 < len(blob) <= 204800:
            raise ValueError(f'{path}: invalid size')
        if not re.fullmatch(b'[0-9a-f]{64}', blob[:64]) or \
           hashlib.sha256(blob[64:]).hexdigest().encode() != blob[:64]:
            raise ValueError(f'{path}: invalid SDK SHA-256 header')
        verified[name] = blob
    return verified


def copy_binary(root, binary, destination):
    target = root / destination.lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, target)
    dependencies = subprocess.check_output(['ldd', str(binary)], text=True)
    for lib in re.findall(r'(/[^\s()]+)', dependencies):
        path = Path(lib)
        if path.is_file():
            target = root / lib.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)


RUNTIME_CONFIG = {'bsle_custom.bin': 140, 'pm_config.bin': 4}


def runtime_configuration(args):
    directory = getattr(args, 'runtime_config_dir', None)
    if directory is None:
        return {}
    blobs = {name: (directory / name).read_bytes() for name in RUNTIME_CONFIG}
    for name, data in blobs.items():
        if len(data) != RUNTIME_CONFIG[name]:
            raise ValueError(f'{name}: expected {RUNTIME_CONFIG[name]} raw bytes')
    return blobs


def pack(args):
    blobs = firmware(args)  # Refuse bad images before building a runnable VM.
    runtime = runtime_configuration(args)  # Explicit board inputs only.
    args.build_dir.mkdir(parents=True, exist_ok=True)
    init = args.build_dir / 'ws73-lab-init'
    init_source = SOURCE / 'tools/testing/selftests/sparklink/ws73-lab-init.c'
    init_source_record = file_record(init_source)
    checked(['/usr/bin/gcc', '-Wall', '-Wextra', '-Werror', '-O2',
             init_source, '-o', init])
    if file_record(init_source) != init_source_record:
        raise ValueError('init source changed during compilation; run pack again')
    archive = args.build_dir / 'ws73-initramfs.cpio.gz'
    with tempfile.TemporaryDirectory(prefix='ws73-root-', dir=args.build_dir) as tmp:
        root = Path(tmp)
        for directory in ('dev', 'proc', 'sys', 'tmp', 'lib/firmware/sparklink/ws73'):
            (root / directory).mkdir(parents=True, exist_ok=True)
        copy_binary(root, init, '/init')
        for name, blob in (blobs | runtime).items():
            (root / 'lib/firmware/sparklink/ws73' / name).write_bytes(blob)
        paths = sorted(str(p.relative_to(root)) for p in root.rglob('*'))
        cpio = subprocess.run(['cpio', '--null', '-o', '-H', 'newc', '--quiet'],
                              cwd=root, input=('\0'.join(paths) + '\0').encode(),
                              stdout=subprocess.PIPE, check=True)
        archive.write_bytes(gzip.compress(cpio.stdout, mtime=0))
    images = {name: dict(source_path=str((args.firmware_dir / name).resolve()),
                        archive_path=f'/lib/firmware/sparklink/ws73/{name}',
                        size=len(blob), file_sha256=sha256(blob),
                        payload_size=len(blob) - 64, payload_sha256=sha256(blob[64:]),
                        sdk_header_sha256=blob[:64].decode('ascii'))
              for name, blob in blobs.items()}
    write_json(args.build_dir / PACK_MANIFEST, dict(
        schema_version=MANIFEST_VERSION, created_at=utc_now(), images=images,
        runtime_configuration={name: dict(
            source_path=str((args.runtime_config_dir / name).resolve()),
            archive_path=f'/lib/firmware/sparklink/ws73/{name}',
            size=len(blob), file_sha256=sha256(blob)) for name, blob in runtime.items()},
        initramfs=file_record(archive), init=file_record(init),
        init_source=init_source_record,
        compiler=version(['/usr/bin/gcc', '--version']),
        tools={'cpio': version(['cpio', '--version']), 'python': sys.version},
        source=source_snapshot(SOURCE)))
    print(archive)
    print(args.build_dir / PACK_MANIFEST)


def read_manifest(path):
    try:
        manifest = json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f'{path}: missing or invalid manifest; rebuild/repack with this lab') from error
    if not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int or \
       manifest['schema_version'] != MANIFEST_VERSION:
        raise ValueError(f'{path}: unsupported manifest version')
    return manifest


def validate_artifacts(build_dir):
    """Bind evidence to actual artifacts, never infer firmware from the SDK now."""
    kernel = build_dir / 'arch/x86/boot/bzImage'
    initramfs = build_dir / 'ws73-initramfs.cpio.gz'
    pack_record = read_manifest(build_dir / PACK_MANIFEST)
    build_record = read_manifest(build_dir / BUILD_MANIFEST)
    actual_kernel, actual_initramfs = file_record(kernel), file_record(initramfs)
    recorded_kernel = build_record.get('kernel')
    recorded_initramfs = pack_record.get('initramfs')
    if not isinstance(recorded_kernel, dict) or \
       actual_kernel['sha256'] != recorded_kernel.get('sha256'):
        raise ValueError('kernel hash differs from build manifest; run build again')
    if not isinstance(recorded_initramfs, dict) or \
       actual_initramfs['sha256'] != recorded_initramfs.get('sha256'):
        raise ValueError('initramfs hash differs from firmware manifest; run pack again')
    configuration = (build_dir / '.config').read_bytes()
    saved_config = build_dir / 'ws73-kernel.config'
    if sha256(configuration) != build_record.get('config_sha256') or \
       saved_config.read_bytes() != configuration:
        raise ValueError('kernel config differs from build manifest; run build again')
    images = pack_record.get('images')
    if not isinstance(images, dict) or set(images) != set(IMAGES):
        raise ValueError('firmware manifest has an incomplete image set; run pack again')
    for name, image in images.items():
        if not isinstance(image, dict) or image.get('archive_path') != \
           f'/lib/firmware/sparklink/ws73/{name}' or \
           not isinstance(image.get('source_path'), str) or \
           type(image.get('size')) is not int or not 64 < image['size'] <= 204800 or \
           type(image.get('payload_size')) is not int or \
           image['payload_size'] != image['size'] - 64 or \
           image.get('sdk_header_sha256') != image.get('payload_sha256') or \
           any(not isinstance(image.get(field), str) or
               not re.fullmatch(r'[0-9a-f]{64}', image[field])
               for field in ('file_sha256', 'payload_sha256')):
            raise ValueError(f'{name}: invalid firmware manifest; run pack again')
    runtime = pack_record.get('runtime_configuration', {})
    if not isinstance(runtime, dict) or (runtime and set(runtime) != set(RUNTIME_CONFIG)):
        raise ValueError('invalid runtime configuration manifest')
    for name, image in runtime.items():
        if not isinstance(image, dict) or image.get('archive_path') != \
           f'/lib/firmware/sparklink/ws73/{name}' or \
           not isinstance(image.get('source_path'), str) or \
           type(image.get('size')) is not int or image['size'] != RUNTIME_CONFIG[name] or \
           not isinstance(image.get('file_sha256'), str) or \
           not re.fullmatch(r'[0-9a-f]{64}', image['file_sha256']):
            raise ValueError(f'{name}: invalid runtime configuration manifest')
    return dict(kernel=actual_kernel, initramfs=actual_initramfs,
                config_sha256=sha256(configuration)), build_record, pack_record


class Qmp:
    """Small synchronous monitor used only to reconnect selected USB ports."""
    def __init__(self, path, record):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(20)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rb')
        self.events = []
        self.sequence = 0
        self.record = record
        self.read()
        self.execute('qmp_capabilities')

    def read(self):
        line = self.stream.readline()
        if not line:
            raise ValueError('QEMU monitor closed')
        response = json.loads(line)
        with self.record.open('a') as output:
            output.write(json.dumps(dict(direction='rx', message=response)) + '\n')
        return response

    def execute(self, command, arguments=None):
        self.sequence += 1
        message = dict(execute=command, id=self.sequence)
        if arguments is not None:
            message['arguments'] = arguments
        with self.record.open('a') as output:
            output.write(json.dumps(dict(direction='tx', message=message)) + '\n')
        self.socket.sendall((json.dumps(message) + '\n').encode())
        while True:
            response = self.read()
            if 'event' in response:
                self.events.append(response)
            elif response.get('id') == self.sequence:
                if 'error' in response:
                    raise ValueError(f'QMP {command}: {response["error"]}')
                return response.get('return')

    def wait_deleted(self, identity):
        while True:
            for index, event in enumerate(self.events):
                if event.get('event') == 'DEVICE_DELETED' and \
                   event.get('data', {}).get('device') == identity:
                    self.events.pop(index)
                    return
            self.events.append(self.read())

    def close(self):
        self.stream.close()
        self.socket.close()


def validate_ports(ports):
    if not ports:
        raise ValueError('select physical ports explicitly using --ports 1-2.1.1')
    if len(set(ports)) != len(ports):
        raise ValueError('duplicate USB ports')
    if len(ports) > 4:
        raise ValueError('the boot gate supports 1..4 devices')
    if any(not re.fullmatch(r'\d+-\d+(?:\.\d+)*', port) for port in ports):
        raise ValueError('USB ports must be physical paths, for example 1-2.1.1')


def boot_gate_result(console, returncode, expected):
    matches = re.findall(r'^WS73_BOOT_GATE: (PASS|FAIL) '
                         r'\(runtime interfaces (\d+)/(\d+); SLE not tested\)\r?$',
                         console, re.MULTILINE)
    diagnostics = re.findall(r'^.*(?:BUG:|Oops:|Kernel panic|WARNING:|KASAN:|KCSAN:).*$',
                             console, re.MULTILINE)
    passed = returncode == 0 and len(matches) == 1 and \
             matches[0] == ('PASS', str(expected), str(expected)) and not diagnostics
    return dict(status='PASS' if passed else 'FAIL', qemu_returncode=returncode,
                markers=matches, kernel_diagnostics=diagnostics)


def run(args):
    validate_ports(args.ports)
    args.build_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%SZ')
    run_dir = Path(tempfile.mkdtemp(prefix=f'ws73-run-{stamp}-', dir=args.build_dir))
    manifest = dict(schema_version=MANIFEST_VERSION, started_at=utc_now(),
                    status='RUNNING', phase='preflight', expected_devices=len(args.ports),
                    gate='firmware-boot-runtime-interface-binding',
                    gate_scope=['selected runtime USB interfaces bound simultaneously'],
                    not_tested=['SLE handshake', 'DLI transactions', 'RF traffic',
                                'pairing/encryption', 'runtime PM', 'parallel firmware upload'],
                    cold_boot_requires='pre-run boot descriptors and per-device download trace',
                    runner=file_record(Path(__file__)),
                    mapping=[dict(physical_port=port, guest_device_id=f'ws73_{index}',
                                  guest_bus='ws73xhci.0', guest_port=str(index + 1),
                                  controller_id=None, controller_generation=None)
                             for index, port in enumerate(args.ports)],
                    controller_identity_note='boot gate does not register a ready controller')
    record = run_dir / 'manifest.json'
    write_json(record, manifest)
    try:
        devices = {d['path']: d for d in inventory()}
        write_json(run_dir / 'inventory.json', devices)  # Retain the original filename.
        write_json(run_dir / 'inventory-before.json', devices)
        artifacts, build_record, pack_record = validate_artifacts(args.build_dir)
        manifest['artifacts'] = artifacts
        write_json(run_dir / BUILD_MANIFEST, build_record)
        write_json(run_dir / PACK_MANIFEST, pack_record)
        (run_dir / 'kernel.config').write_bytes((args.build_dir / '.config').read_bytes())
        manifest['config_snapshot'] = file_record(run_dir / 'kernel.config')
        manifest['sources_at_run'] = sources()
        manifest['source_matches_kernel_build'] = \
            manifest['sources_at_run']['linux'] == build_record.get('source_after')
        manifest['tools_at_run'] = dict(
            python=sys.version, qemu=version(['qemu-system-x86_64', '--version']),
            gcc=version(['/usr/bin/gcc', '--version']),
            clang=version(['/usr/bin/clang', '--version']))
        qemu = shutil.which('qemu-system-x86_64')
        if qemu:
            manifest['qemu_binary'] = file_record(Path(qemu))
        for port in args.ports:
            if port not in devices or not devices[port]['writable']:
                raise ValueError(f'{port}: not a writable WS73; check udev permissions')
            if any(i['driver'] for i in devices[port]['interfaces']):
                raise ValueError(f'{port}: already owned by a host driver; not detaching it')
        if not os.access('/dev/kvm', os.R_OK | os.W_OK):
            raise ValueError('/dev/kvm access is required; nested virtualization is not needed')
        manifest['phase'] = 'vm'
        write_json(record, manifest)
        result = run_vm(args, run_dir, devices, manifest)
        manifest['result'] = result
        after, _, _ = validate_artifacts(args.build_dir)
        manifest['artifacts_unchanged'] = after == artifacts
        if not manifest['artifacts_unchanged']:
            raise ValueError('test artifacts changed during the run')
        if result['status'] != 'PASS':
            raise ValueError('firmware boot gate failed; this gate does not test SLE/DLI or RF')
        manifest['status'] = 'PASS'
        manifest['phase'] = 'complete'
    except BaseException as error:
        manifest['status'] = 'FAIL'
        manifest['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        try:
            write_json(run_dir / 'inventory-after.json', {d['path']: d for d in inventory()})
        except OSError as error:
            manifest['inventory_after_error'] = str(error)
            manifest['status'] = 'FAIL'
        manifest['finished_at'] = utc_now()
        write_json(record, manifest)
        print(f'Manifest: {record}')
    if manifest['status'] != 'PASS':
        raise ValueError('run evidence is incomplete; inspect the manifest')


def run_vm(args, run_dir, devices, manifest):
    kernel = args.build_dir / 'arch/x86/boot/bzImage'
    initramfs = args.build_dir / 'ws73-initramfs.cpio.gz'
    # UNIX sockets have short path limits; keep it outside the long build path.
    monitor_dir = tempfile.TemporaryDirectory(prefix='ws73-qmp-')
    monitor_path = Path(monitor_dir.name) / 'monitor.sock'
    command = ['qemu-system-x86_64', '-machine', 'q35,accel=kvm', '-cpu', 'host',
               '-m', '2048', '-smp', '4', '-display', 'none', '-serial', 'stdio',
               '-monitor', 'none', '-no-reboot', '-nic', 'none',
               '-qmp', f'unix:{monitor_path},server=on,wait=off',
               '-kernel', str(kernel), '-initrd', str(initramfs),
               '-append', f'console=ttyS0 panic=1 oops=panic ws73.expected={len(args.ports)}',
               '-device', 'qemu-xhci,id=ws73xhci,p2=8,p3=8']
    # Start one boot transport at a time. Other controllers remain attached
    # once ready, so the final gate still checks all interfaces simultaneously.
    for index, port in enumerate(args.ports[:1]):
        bus, path = port.split('-', 1)
        command += ['-device', f'usb-host,id=ws73_{index},bus=ws73xhci.0,port={index + 1},hostbus={int(bus)},hostport={path},vendorid=65535,productid=14131,guest-reset=false,guest-resets-all=false,kernel-driver-detach=false,host-reset=false']
    write_json(run_dir / 'command.json', command)
    manifest['qemu_command'] = command
    write_json(run_dir / 'manifest.json', manifest)
    write_json(run_dir / 'reattach.json', [])
    log = run_dir / 'console.log'
    process = None
    monitor = None
    with log.open('wb') as output:
        try:
            process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + args.timeout
            while not monitor_path.exists() and process.poll() is None:
                if time.monotonic() > deadline:
                    raise ValueError(f'QEMU monitor startup timed out; inspect {log}')
                time.sleep(0.1)
            if process.poll() is None:
                monitor = Qmp(monitor_path, run_dir / 'qmp.jsonl')
            addresses = {p: devices[p]['address'] for p in args.ports}
            reattached = []
            active = 1
            while process.poll() is None:
                if time.monotonic() > deadline:
                    raise ValueError(f'VM timed out; inspect {log}')
                current = {d['path']: d for d in inventory()}
                for index, port in enumerate(args.ports[:active]):
                    device = current.get(port)
                    if device is None or device['address'] == addresses[port]:
                        continue
                    if not device['writable']:
                        continue  # Wait for udev to apply the rule to the new node.
                    identity = f'ws73_{index}'
                    monitor.execute('device_del', dict(id=identity))
                    monitor.wait_deleted(identity)
                    bus, path = port.split('-', 1)
                    monitor.execute('device_add', dict(driver='usb-host', id=identity,
                        bus='ws73xhci.0', port=str(index + 1), hostbus=int(bus),
                        hostport=path, vendorid=0xffff, productid=0x3733,
                        **{'guest-reset': False, 'guest-resets-all': False,
                           'kernel-driver-detach': False, 'host-reset': False}))
                    addresses[port] = device['address']
                    reattached.append(dict(port=port, address=device['address']))
                    write_json(run_dir / 'reattach.json', reattached)
                console = log.read_text(errors='replace')
                if active < len(args.ports) and re.search(
                    rf'sparklink_ws73_usb \d+-{active}:1\.0: WS73 runtime interface', console):
                    bus, path = args.ports[active].split('-', 1)
                    monitor.execute('device_add', dict(driver='usb-host', id=f'ws73_{active}',
                        bus='ws73xhci.0', port=str(active + 1), hostbus=int(bus),
                        hostport=path, vendorid=0xffff, productid=0x3733,
                        **{'guest-reset': False, 'guest-resets-all': False,
                           'kernel-driver-detach': False, 'host-reset': False}))
                    active += 1
                time.sleep(0.5)
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process is not None:
                manifest['qemu_returncode'] = process.returncode
            try:
                if monitor:
                    monitor.close()
            finally:
                monitor_dir.cleanup()
    console = log.read_text(errors='replace')
    print(console)
    print(f'Log: {log}')
    return boot_gate_result(console, process.returncode, len(args.ports))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inventory', 'configure', 'build', 'pack', 'run'))
    parser.add_argument('--build-dir', type=Path, default=WORKSPACE / '.dev/kernel')
    parser.add_argument('--firmware-dir', type=Path, default=WORKSPACE / 'ws73_SDK/firmware/us')
    parser.add_argument('--runtime-config-dir', type=Path,
                        help='board-approved raw bsle_custom.bin and pm_config.bin; never synthesized')
    parser.add_argument('--rustc', help='rustc binary with matching rust-src installed')
    parser.add_argument('--bindgen')
    parser.add_argument('--jobs', type=int, default=12)
    parser.add_argument('--ports', nargs='+', default=[])
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if args.jobs <= 0 or args.timeout <= 0:
        parser.error('--jobs and --timeout must be positive')
    args.build_dir = args.build_dir.resolve()
    args.firmware_dir = args.firmware_dir.resolve()
    if args.runtime_config_dir is not None:
        args.runtime_config_dir = args.runtime_config_dir.resolve()
    if args.action == 'inventory':
        print(json.dumps(inventory(), indent=2))
    else:
        with lab_lock(args):
            if args.action == 'configure':
                configure(args)
            elif args.action == 'build':
                build(args)
            elif args.action == 'pack':
                pack(args)
            else:
                run(args)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
