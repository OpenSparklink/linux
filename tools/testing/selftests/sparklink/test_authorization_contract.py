# SPDX-License-Identifier: GPL-2.0-only
"""A new public ioctl must be reviewed rather than accidentally gaining access."""
from pathlib import Path
import re
import unittest
import tempfile
from run_daemon_lifecycle import require_config

ROOT = Path(__file__).resolve().parents[4]


class AuthorizationContract(unittest.TestCase):
    def test_entire_public_ioctl_space_reviewed(self):
        public = re.findall(r'^#define (SL_IOCTL_\w+)\s',
                            (ROOT / 'include/uapi/linux/sparklink_ioctl.h').read_text(), re.M)
        classified = re.findall(r'\bSL_IOCTL_\w+\b',
                                (ROOT / 'net/sparklink/sle_authorization.rs').read_text())
        self.assertCountEqual(public, classified)

    def test_guest_matrix_covers_all_access_classes(self):
        source = (ROOT / 'tools/testing/selftests/sparklink/kernel_authorization_test.c').read_text()
        for kind, access in [('protected','Protected'),('observe','Observe')]:
            guest = re.search(rf'{kind}\[\] = \{{(.*?)\}};', source, re.S)[1]
            policy = (ROOT / 'net/sparklink/sle_authorization.rs').read_text()
            branch = re.search(rf'((?:\s*(?:\| )?SL_IOCTL_\w+)+)\s+=> Ok\(Access::{access}\)', policy)[1]
            expected = re.findall(r'SL_IOCTL_\w+',branch)
            if kind == 'protected':
                privileged = re.search(r'((?:\s*(?:\| )?SL_IOCTL_\w+)+)\s+=> Ok\(Access::PrivilegedObserve\)', policy)[1]
                expected += re.findall(r'SL_IOCTL_\w+',privileged)
            self.assertCountEqual(re.findall(r'SL_IOCTL_\w+',guest),expected)

    def test_missing_feature_config_rejected(self):
        names = ['RUST','SPARKLINK','SPARKLINK_WS73_USB']
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.config'
            path.write_text(''.join(f'CONFIG_{name}=y\n' for name in names))
            require_config(path)
            for missing in names:
                with self.subTest(missing=missing):
                    path.write_text(''.join(f'CONFIG_{name}=y\n' for name in names if name != missing))
                    with self.assertRaisesRegex(RuntimeError, 'reject unqualified image'):
                        require_config(path)

    def test_authorization_needs_all_entrypoints(self):
        names = ['RUST','SPARKLINK','SPARKLINK_WS73_USB','SPARKLINK_GENL','CONFIGFS_FS']
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / '.config'
            path.write_text(''.join(f'CONFIG_{name}=y\n' for name in names))
            require_config(path, authorization=True)
            for missing in ['SPARKLINK_GENL','CONFIGFS_FS']:
                path.write_text(''.join(f'CONFIG_{name}=y\n' for name in names if name != missing))
                with self.assertRaisesRegex(RuntimeError, 'reject unqualified image'):
                    require_config(path, authorization=True)


if __name__ == '__main__':
    unittest.main()
