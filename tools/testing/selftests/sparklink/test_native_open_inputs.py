# SPDX-License-Identifier: GPL-2.0-only
"""Receipt/schema negative controls only; byte fixtures are not kernel builds."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from run_native_open_test import checked_kernel_inputs


class NativeOpenInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        files = {'.config': b'CONFIG_RUST=y\nCONFIG_SPARKLINK=y\nCONFIG_MODULES=y\nCONFIG_SPARKLINK_WS73_USB=m\n',
                 'arch/x86/boot/bzImage': b'fixture-not-an-image', 'Module.symvers': b'fixture',
                 'include/config/kernel.release': b'fixture-release', 'vmlinux': b'fixture-not-an-ELF'}
        self.data = dict(status='NATIVE_BUILD_ARTIFACTS_VERIFIED', inputs={})
        for name, blob in files.items():
            path = self.root / ('vmlinux' if name == 'vmlinux' else 'artifacts/' + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(blob)
            self.data['inputs'][name] = dict(size=len(blob), sha256=hashlib.sha256(blob).hexdigest())
        self.save()

    def save(self):
        (self.root / 'manifest.json').write_text(json.dumps(self.data))

    def check(self):
        # This function only requires explicit modular input; real ELF/modinfo
        # and the loaded guest path are independent runner/VM gates.
        return checked_kernel_inputs(self.root, Path('/fixture-argument-only'))

    def test_matching_sealed_bytes(self):
        self.assertEqual(len(self.check()), 6)

    def test_m_missing_explicit_module(self):
        with self.assertRaisesRegex(RuntimeError, 'explicit matching module'):
            checked_kernel_inputs(self.root)

    def test_unqualified_status(self):
        self.data['status'] = 'BUILDING'
        self.save()
        with self.assertRaises(RuntimeError):
            self.check()

    def test_missing_required_receipt_entry(self):
        del self.data['inputs']['Module.symvers']
        self.save()
        with self.assertRaises(RuntimeError):
            self.check()

    def test_bad_hash_and_size(self):
        record = self.data['inputs']['Module.symvers']
        for key, bad in [('sha256', '0' * 64), ('size', 1000)]:
            old = record[key]
            record[key] = bad
            self.save()
            with self.assertRaises(RuntimeError):
                self.check()
            record[key] = old

    def test_missing_or_changed_sealed_artifact(self):
        path = self.root / 'vmlinux'
        path.write_bytes(b'changed')
        with self.assertRaises(RuntimeError):
            self.check()
        path.unlink()
        with self.assertRaises(OSError):
            self.check()

    def test_escape_receipt_path(self):
        self.data['inputs']['../outside'] = dict(size=0, sha256='0' * 64)
        self.save()
        with self.assertRaisesRegex(RuntimeError, 'invalid sealed artifact path'):
            self.check()


if __name__ == '__main__':
    unittest.main()
