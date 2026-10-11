#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Apply the opt-out USB host lifecycle patch; reject unexpected source drift."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def apply(source):
    # Later patches can change an earlier patch's context. Validate the complete
    # chain in a private tree, including all supported previously applied prefixes,
    # before changing the caller's file. A partial/context drift never mutates it.
    names = ['usb-host-boundary.patch', 'usb-host-retry.patch',
             'usb-host-reenumeration.patch', 'usb-host-autoscan.patch',
             'usb-host-runtime-error.patch', 'usb-host-runtime-hold.patch',
             'usb-host-enumeration-once.patch']
    patches = [Path(__file__).with_name(name).resolve() for name in names]
    host = source / 'hw/usb/host-libusb.c'
    original = host.read_bytes()
    with tempfile.TemporaryDirectory(prefix='ws73-usb-patch-') as directory:
        tree = Path(directory)
        copy = tree / 'hw/usb/host-libusb.c'
        copy.parent.mkdir(parents=True)
        for prefix in range(len(patches), -1, -1):
            copy.write_bytes(original)
            commands = [('reverse', patch) for patch in reversed(patches[:prefix])]
            commands += [('forward', patch) for patch in patches]
            for direction, patch in commands:
                result = subprocess.run(['patch', '--batch', '--fuzz=0', '-p1',
                                         '--' + direction, '-i', str(patch)],
                                        cwd=tree, capture_output=True, text=True)
                if result.returncode:
                    break
            else:
                updated = copy.read_bytes()
                if host.read_bytes() != original:
                    raise ValueError('USB host source changed during patch validation')
                if updated != original:
                    host.write_bytes(updated)
                print('USB host patch chain ' + ('already applied' if updated == original else 'applied'))
                return
    raise ValueError('QEMU USB host source differs from patch context; '
                     'do not build an unguarded physical runner')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    apply(parser.parse_args().source.resolve())
