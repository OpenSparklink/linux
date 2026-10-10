#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Apply the opt-out USB host lifecycle patch; reject unexpected source drift."""
import argparse
from pathlib import Path
import subprocess


def apply_one(source, name):
    patch = Path(__file__).with_name(name)
    command = ['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)]
    forward = subprocess.run([*command, '--forward', '--dry-run'], cwd=source,
                             capture_output=True, text=True)
    if forward.returncode == 0:
        subprocess.run([*command, '--forward'], cwd=source, check=True)
        print(name + ' applied')
        return
    reverse = subprocess.run([*command, '--reverse', '--dry-run'], cwd=source,
                             capture_output=True, text=True)
    if reverse.returncode == 0:
        print(name + ' already applied')
        return
    raise ValueError('QEMU USB host source differs from patch context; '
                     'do not build an unguarded physical runner\n' +
                     forward.stdout + forward.stderr)


def apply(source):
    for name in ['usb-host-boundary.patch', 'usb-host-retry.patch',
                 'usb-host-reenumeration.patch', 'usb-host-autoscan.patch']:
        apply_one(source, name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    apply(parser.parse_args().source.resolve())
