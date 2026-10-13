#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Live USB parser bounds plus historical codec witnesses; not USB/RF qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from run_connection_tx import function
from run_usb_discovery import block


def run(output):
    here = Path(__file__).resolve().parent
    net = here.parents[3] / 'net/sparklink'
    live = (net/'sle_usb.rs').read_text()
    archive = (here/'retired-usb-registration/legacy_usb_codec.rs').read_text()
    fixture = (here/'retired-usb-registration/codec_fixture.rs').read_text()
    fixture = fixture.replace('// @@ARCHIVE@@', archive)
    fixture = fixture.replace('// @@EVENT_STRUCT@@', block(live, live.index('struct DliUsbEvent {')))
    fixture = fixture.replace('// @@EVENT_PARSE@@', function(live, 'parse_event_packet'))
    with tempfile.TemporaryDirectory(prefix='sparklink-usb-codec-isolation-') as tmp:
        source = Path(tmp)/'fixture.rs'
        source.write_text(fixture)
        exe = Path(tmp)/'test'
        subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test', '-D', 'warnings', str(source), '-o', str(exe)], check=True)
        subprocess.run([str(exe)], check=True)
    assert live == (net/'sle_usb.rs').read_text()
    record = dict(status='LIVE_USB_PARSER_AND_HISTORICAL_CODEC_WITNESSES_PASS',
                  live_parser_tests=4, historical_witnesses=3,
                  sources={'sle_usb.rs': hashlib.sha256(live.encode()).hexdigest(),
                           'legacy_usb_codec.rs': hashlib.sha256(archive.encode()).hexdigest()},
                  scope='Actual live parse_event_packet/structure; allocation/errno dependencies are fixtures. Historical encoder/header witnesses record retired behavior, not production functionality or standard conformance.',
                  historical_truncation_supported=False, physical_acceptance=False,
                  live_callback_lifetime_proven=False)
    if output:
        output.write_text(json.dumps(record, indent=2)+'\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    run(parser.parse_args().output)
