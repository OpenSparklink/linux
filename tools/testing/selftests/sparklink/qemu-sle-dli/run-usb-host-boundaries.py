#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reproduce actual QEMU host dependency checks from the pinned upstream archive.

No USB matching or guest execution. An optional already-built QEMU is probed
only with a paused/unattached TCG object. Fixtures do not qualify live USB,
the QEMU timer scheduler, on-wire cancellation or natural fault recovery.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile


ARCHIVE_SHA256 = 'f859f0bc65e1f533d040bbe8c92bcfecee5af2c921a6687c652fb44d089bd894'


def check(args):
    digest = hashlib.sha256(args.archive.read_bytes()).hexdigest()
    if digest != ARCHIVE_SHA256:
        raise ValueError('not the pinned QEMU 9.2.0 upstream archive')
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.output / 'source'
    # Read only these exact members; never extract arbitrary archive paths.
    with tarfile.open(args.archive) as archive:
        for name in ['hw/usb/host-libusb.c', 'include/hw/usb.h']:
            member = archive.getmember('qemu-9.2.0/' + name)
            if not member.isfile():
                raise ValueError('upstream source member is not a regular file')
            destination = source / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(member) as content:
                destination.write_bytes(content.read())
    helpers = Path(__file__).resolve().parent
    subprocess.run([sys.executable, str(helpers / 'apply-usb-host-boundary.py'), str(source)], check=True)
    boundary = [sys.executable, str(helpers / 'check-usb-host-boundary.py'),
                '--source', str(source), '--output', str(args.output / 'chain'), '--cc', args.cc]
    if args.qemu:
        boundary += ['--qemu', str(args.qemu)]
    subprocess.run(boundary, check=True)
    for name in ['error', 'hold']:
        subprocess.run([sys.executable, str(helpers / f'check-usb-host-runtime-{name}.py'),
                        '--source', str(source / 'hw/usb/host-libusb.c'),
                        '--output', str(args.output / name), '--cc', args.cc, '--sanitize'], check=True)
    subprocess.run([sys.executable, str(helpers / 'check-usb-host-enumeration-once.py'),
                    '--source', str(source / 'hw/usb/host-libusb.c'),
                    '--output', str(args.output / 'enumeration-once'), '--cc', args.cc], check=True)
    record = {'status': 'PASS_PINNED_QEMU_DEPENDENCY_BOUNDARIES',
              'archive_sha256': digest, 'upstream_version': '9.2.0',
              'source_sha256': hashlib.sha256((source / 'hw/usb/host-libusb.c').read_bytes()).hexdigest(),
              'chain': json.loads((args.output / 'chain/result.json').read_text()),
              'error': json.loads((args.output / 'error/manifest.json').read_text()),
              'hold': json.loads((args.output / 'hold/manifest.json').read_text()),
              'enumeration_once': json.loads((args.output / 'enumeration-once/manifest.json').read_text()),
              'live_usb_acceptance': False, 'live_on_wire_cancel_acceptance': False,
              'qemu_scheduler_acceptance': False, 'natural_fault_root_cause_closed': False}
    (args.output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(record['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cc', default='clang')
    parser.add_argument('--qemu', type=Path)
    args = parser.parse_args()
    args.archive = args.archive.resolve()
    args.output = args.output.resolve()
    if args.qemu:
        args.qemu = args.qemu.resolve()
    check(args)
