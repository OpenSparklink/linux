#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""WS73 lab evidence unit tests. No VM process or USB I/O is launched."""
import contextlib
import copy
import gzip
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('ws73-lab.py')
spec = importlib.util.spec_from_file_location('ws73_lab', SCRIPT)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class ArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ws73-evidence-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.kernel = self.root / 'arch/x86/boot/bzImage'
        self.kernel.parent.mkdir(parents=True)
        self.kernel.write_bytes(b'unit-test synthetic kernel, not a bootable artifact')
        self.archive = self.root / 'ws73-initramfs.cpio.gz'
        self.archive.write_bytes(b'unit-test synthetic initramfs')
        self.config = b'CONFIG_SPARKLINK_WS73_USB=y\n'
        (self.root / '.config').write_bytes(self.config)
        (self.root / 'ws73-kernel.config').write_bytes(self.config)
        self.build = dict(schema_version=1, kernel=lab.file_record(self.kernel),
                          config_sha256=lab.sha256(self.config),
                          source_after={'test_fixture': True}, source_unchanged=True)
        self.pack = dict(schema_version=1, initramfs=lab.file_record(self.archive),
                         images={n: dict(archive_path=f'/lib/firmware/sparklink/ws73/{n}',
                                         source_path=f'/unit-test/{n}', size=164,
                                         payload_size=100,
                                         file_sha256='a' * 64,
                                         payload_sha256='b' * 64,
                                         sdk_header_sha256='b' * 64)
                                 for n in lab.IMAGES})
        self.records()

    def records(self):
        lab.write_json(self.root / lab.BUILD_MANIFEST, self.build)
        lab.write_json(self.root / lab.PACK_MANIFEST, self.pack)

    def test_matching_artifacts(self):
        actual, build, pack = lab.validate_artifacts(self.root)
        self.assertEqual(actual['kernel']['sha256'], self.build['kernel']['sha256'])
        self.assertEqual(build, self.build)
        self.assertEqual(pack, self.pack)
        # Exercise build provenance without invoking make or pretending that
        # this non-bootable fixture is a compiled kernel.
        args = SimpleNamespace(build_dir=self.root, jobs=2)
        source = dict(revision='a' * 40, dirty=False, test_fixture=True)
        with patch.object(lab, 'make_args', return_value=['make', 'CC=/test/clang']), \
             patch.object(lab, 'checked') as make, \
             patch.object(lab, 'source_snapshot', return_value=source), \
             patch.object(lab, 'version', return_value={'test_fixture': True}):
            lab.build(args)
            make.assert_called_once_with(['make', 'CC=/test/clang', '-j2', 'bzImage'])
        built = json.loads((self.root / lab.BUILD_MANIFEST).read_text())
        self.assertEqual(built['kernel']['sha256'], self.build['kernel']['sha256'])
        self.assertEqual(built['config_sha256'], lab.sha256(self.config))
        self.assertEqual(built['source_before'], source)
        self.assertEqual(built['source_after'], source)
        self.assertTrue(built['source_unchanged'])
        self.assertIn('CC', built['tools'])

    def test_runtime_configuration_manifest_is_strict(self):
        configs = {n: dict(source_path=f'/unit-test/{n}',
                           archive_path=f'/lib/firmware/sparklink/ws73/{n}',
                           size=size, file_sha256='c' * 64)
                   for n, size in lab.RUNTIME_CONFIG.items()}
        self.pack['runtime_configuration'] = configs
        self.records()
        lab.validate_artifacts(self.root)
        for invalid in ([], {'bsle_custom.bin': configs['bsle_custom.bin']},
                        {**configs, 'pm_config.bin': {**configs['pm_config.bin'], 'size': True}},
                        {**configs, 'pm_config.bin': {**configs['pm_config.bin'], 'file_sha256': 'bad'}},
                        {**configs, 'pm_config.bin': {**configs['pm_config.bin'], 'archive_path': '/elsewhere'}}):
            with self.subTest(invalid=invalid):
                self.pack['runtime_configuration'] = invalid
                self.records()
                with self.assertRaisesRegex(ValueError, 'runtime configuration manifest'):
                    lab.validate_artifacts(self.root)

    def test_raw_runtime_inputs_required_and_exact_size(self):
        args = SimpleNamespace(runtime_config_dir=None)
        self.assertEqual(lab.runtime_configuration(args), {})
        args.runtime_config_dir = self.root
        with self.assertRaises(FileNotFoundError):
            lab.runtime_configuration(args)
        for name, size in lab.RUNTIME_CONFIG.items():
            (self.root / name).write_bytes(bytes(size))
        self.assertEqual(set(lab.runtime_configuration(args)), set(lab.RUNTIME_CONFIG))
        for name, size in lab.RUNTIME_CONFIG.items():
            for wrong in (0, size - 1, size + 1):
                with self.subTest(name=name, size=wrong):
                    (self.root / name).write_bytes(bytes(wrong))
                    with self.assertRaisesRegex(ValueError, 'expected .* raw bytes'):
                        lab.runtime_configuration(args)
            (self.root / name).write_bytes(bytes(size))

    def test_changed_kernel_rejected(self):
        self.kernel.write_bytes(b'different')
        with self.assertRaisesRegex(ValueError, 'kernel hash'):
            lab.validate_artifacts(self.root)

    def test_changed_archive_rejected(self):
        self.archive.write_bytes(b'different')
        with self.assertRaisesRegex(ValueError, 'initramfs hash'):
            lab.validate_artifacts(self.root)

    def test_current_and_saved_config_rejected(self):
        for name in ('.config', 'ws73-kernel.config'):
            with self.subTest(name=name):
                (self.root / name).write_bytes(b'different')
                with self.assertRaisesRegex(ValueError, 'kernel config'):
                    lab.validate_artifacts(self.root)
                (self.root / name).write_bytes(self.config)

    def test_missing_manifest_rejected(self):
        (self.root / lab.PACK_MANIFEST).unlink()
        with self.assertRaisesRegex(ValueError, 'missing or invalid manifest'):
            lab.validate_artifacts(self.root)

    def test_invalid_manifest_headers_rejected(self):
        for record in ([], {'schema_version': 2}, {'schema_version': True}):
            with self.subTest(record=record):
                lab.write_json(self.root / lab.PACK_MANIFEST, record)
                with self.assertRaisesRegex(ValueError, 'manifest version'):
                    lab.validate_artifacts(self.root)

    def test_binary_or_malformed_json_rejected(self):
        for data in (b'not-json', b'\xff'):
            with self.subTest(data=data):
                (self.root / lab.PACK_MANIFEST).write_bytes(data)
                with self.assertRaisesRegex(ValueError, 'missing or invalid manifest'):
                    lab.validate_artifacts(self.root)

    def test_invalid_nested_records_rejected(self):
        self.pack['initramfs'] = []
        self.records()
        with self.assertRaisesRegex(ValueError, 'initramfs hash'):
            lab.validate_artifacts(self.root)

    def test_incomplete_or_invalid_image_metadata_rejected(self):
        original = copy.deepcopy(self.pack)
        mutations = [lambda x: x['images'].pop('ws73.bin'),
                     lambda x: x['images']['ws73.bin'].update(file_sha256=None),
                     lambda x: x['images']['ws73.bin'].update(payload_sha256='c' * 64),
                     lambda x: x['images']['ws73.bin'].update(payload_size=999),
                     lambda x: x['images']['ws73.bin'].update(size=True),
                     lambda x: x['images']['ws73.bin'].update(archive_path='/wrong/path')]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                self.pack = copy.deepcopy(original)
                mutate(self.pack)
                self.records()
                with self.assertRaises(ValueError):
                    lab.validate_artifacts(self.root)

    def test_preflight_failure_has_terminal_manifest_and_inventory(self):
        args = SimpleNamespace(ports=['1-2.1.1'], build_dir=self.root, action='run')
        with patch.object(lab, 'inventory', return_value=[]), \
             patch.object(lab, 'sources', return_value={'linux': {'test_fixture': True}}), \
             patch.object(lab, 'version', return_value={'test_fixture': True}), \
             patch.object(lab.shutil, 'which', return_value=None), \
             patch.object(lab, 'run_vm') as vm, \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'QEMU requires guarded usb-host'):
                lab.run(args)
            vm.assert_not_called()
        run_dir, = self.root.glob('ws73-run-*')
        record = json.loads((run_dir / 'manifest.json').read_text())
        self.assertEqual(record['status'], 'FAIL')
        self.assertEqual(record['phase'], 'preflight')
        self.assertIn('finished_at', record)
        self.assertEqual(record['mapping'][0]['physical_port'], '1-2.1.1')
        self.assertEqual(record['mapping'][0]['guest_port'], '1')
        self.assertIsNone(record['mapping'][0]['controller_id'])
        for name in ('kernel.config', lab.BUILD_MANIFEST, lab.PACK_MANIFEST,
                     'inventory-before.json', 'inventory-after.json'):
            self.assertTrue((run_dir / name).is_file(), name)


class GateTests(unittest.TestCase):
    def test_scope_count_exit_and_diagnostics_are_strict(self):
        valid = 'WS73_BOOT_GATE: PASS (runtime interfaces 4/4; SLE not tested)\r\n'
        self.assertEqual(lab.boot_gate_result(valid, 0, 4)['status'], 'PASS')
        for console, code, expected in [(valid, 1, 4), (valid, 0, 3),
                                         (valid + valid, 0, 4),
                                         (valid.replace('4/4', '1/4'), 0, 4),
                                         (valid.replace('PASS', 'FAIL'), 0, 4),
                                         ('prefix ' + valid, 0, 4),
                                         (valid + '[ 1.0] WARNING: invalid context\n', 0, 4),
                                         (valid + '[ 1.0] Kernel panic: test\n', 0, 4),
                                         ('WS73_BOOT_GATE: PASS\n', 0, 4)]:
            with self.subTest(console=console, code=code, expected=expected):
                self.assertEqual(lab.boot_gate_result(console, code, expected)['status'], 'FAIL')

    def test_baseline_is_only_boot_scope(self):
        # A runtime bind is a boot marker, not a SLE-ready/RF result. This
        # synthetic transcript has no dependency on archived hardware runs.
        console = ('runtime transport present; SLE handshake not implemented\n'
                   'WS73_BOOT_GATE: PASS (runtime interfaces 4/4; SLE not tested)\n')
        result = lab.boot_gate_result(console, 0, 4)
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['markers'], [('PASS', '4', '4')])

    def test_invalid_ports_rejected(self):
        lab.validate_ports(['1-2.1.1', '1-2.1.2'])
        for ports in ([], ['1-2.1.1'] * 2, ['bus=1'], ['1-1', '1-2', '1-3', '1-4', '1-5']):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                lab.validate_ports(ports)


class ProvenanceTests(unittest.TestCase):
    def test_lock_conflict_and_release_keep_inode(self):
        with tempfile.TemporaryDirectory(prefix='ws73-evidence-lock-') as tmp:
            lock = Path(tmp) / 'lab.lock'
            a = SimpleNamespace(action='run', build_dir=Path(tmp) / 'one')
            b = SimpleNamespace(action='pack', build_dir=Path(tmp) / 'two')
            with lab.lab_lock(a, lock):
                inode = lock.stat().st_ino
                with self.assertRaisesRegex(ValueError, 'another WS73 lab command'):
                    with lab.lab_lock(b, lock):
                        self.fail('second command acquired lock')
                child = subprocess.run([
                    sys.executable, '-c',
                    'import fcntl,sys; f=open(sys.argv[1], "a+"); '
                    'fcntl.flock(f.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)', str(lock)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertNotEqual(child.returncode, 0)
                self.assertIn(b'BlockingIOError', child.stderr)
                self.assertEqual(json.loads(lock.read_text())['action'], 'run')
            with lab.lab_lock(b, lock):
                self.assertEqual(lock.stat().st_ino, inode)
                self.assertEqual(json.loads(lock.read_text())['action'], 'pack')

    def test_snapshot_includes_tracked_diff_untracked_data_and_symlink(self):
        with tempfile.TemporaryDirectory(prefix='ws73-evidence-git-') as tmp:
            root = Path(tmp)
            subprocess.run(['git', '-C', tmp, 'init', '-q'], check=True)
            (root / 'tracked').write_text('before\n')
            subprocess.run(['git', '-C', tmp, 'add', 'tracked'], check=True)
            subprocess.run(['git', '-C', tmp, '-c', 'user.name=Unit Test',
                            '-c', 'user.email=test@example.invalid',
                            '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                            'commit', '-qm', 'fixture'], check=True)
            clean = lab.source_snapshot(root)
            self.assertFalse(clean['dirty'])
            (root / 'tracked').write_text('after\n')
            (root / 'untracked').write_text('new\n')
            (root / 'link').symlink_to('untracked')
            dirty = lab.source_snapshot(root)
            self.assertTrue(dirty['dirty'])
            self.assertNotEqual(clean['tracked_diff_sha256'], dirty['tracked_diff_sha256'])
            self.assertEqual({x['path'] for x in dirty['untracked']}, {'untracked', 'link'})
            (root / 'untracked').write_text('changed\n')
            self.assertNotEqual(dirty['untracked_sha256'], lab.source_snapshot(root)['untracked_sha256'])

    @unittest.skipUnless(Path('/usr/bin/gcc').is_file() and shutil.which('ldd') and
                         shutil.which('cpio'), 'pack fixture needs lab gcc/ldd/cpio')
    def test_fixture_pack_image_bytes_match_all_manifest_hashes(self):
        with tempfile.TemporaryDirectory(prefix='ws73-evidence-pack-') as tmp:
            base = Path(tmp)
            images, root, unpacked = base / 'images', base / 'build', base / 'unpacked'
            images.mkdir()
            unpacked.mkdir()
            for index, name in enumerate(lab.IMAGES):
                payload = bytes([index]) + bytes(range(256)) * 3
                (images / name).write_bytes(lab.sha256(payload).encode() + payload)
            runtime = root / 'synthetic-runtime'
            runtime.mkdir(parents=True)
            for name, size in lab.RUNTIME_CONFIG.items():
                (runtime / name).write_bytes(bytes(range(size)))
            args = SimpleNamespace(build_dir=root, firmware_dir=images, action='pack',
                                   runtime_config_dir=runtime)
            with contextlib.redirect_stdout(io.StringIO()):
                lab.pack(args)
            manifest = json.loads((root / lab.PACK_MANIFEST).read_text())
            archive = root / 'ws73-initramfs.cpio.gz'
            self.assertEqual(lab.file_record(archive)['sha256'], manifest['initramfs']['sha256'])
            subprocess.run(['cpio', '-id', '--quiet'], input=gzip.decompress(archive.read_bytes()),
                           cwd=unpacked, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for name, record in manifest['images'].items():
                data = (unpacked / record['archive_path'].lstrip('/')).read_bytes()
                self.assertEqual(lab.sha256(data), record['file_sha256'])
                self.assertEqual(lab.sha256(data[64:]), record['payload_sha256'])
                self.assertEqual(data[:64].decode(), record['sdk_header_sha256'])
                self.assertEqual(len(data), record['size'])
                self.assertEqual(len(data) - 64, record['payload_size'])
                self.assertEqual(data, Path(record['source_path']).read_bytes())
            self.assertEqual(set(manifest['runtime_configuration']), set(lab.RUNTIME_CONFIG))
            for name, record in manifest['runtime_configuration'].items():
                data = (unpacked / record['archive_path'].lstrip('/')).read_bytes()
                self.assertEqual(lab.sha256(data), record['file_sha256'])
                self.assertEqual(len(data), lab.RUNTIME_CONFIG[name])
                self.assertEqual(data, (runtime / name).read_bytes())


if __name__ == '__main__':
    unittest.main(verbosity=2)
