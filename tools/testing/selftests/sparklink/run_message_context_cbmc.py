#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""CBMC of actual pure receipt header, with epoch and missing-property controls.

Observed Owner level/revision are symbolic inputs. No model of kernel locks,
references, controller truth, cryptography, credit or whole temporal lifecycle.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

EXPECTED = {
 'known receipt requires matching original epoch and bounded Owner observation',
 'unknown receipt has no asserted grade',
 'dequeue cannot upgrade historical grade or epoch',
 'current receipt needs same epoch and sufficient live mechanism',
 'old receipt never obtains current qualification',
}



def inspect(raw, code):
    properties = [p for item in raw for p in item.get('result', [])]
    diagnostics = [i for i in raw if i.get('messageType') in ('WARNING', 'ERROR')]
    terminal = [i['cProverStatus'] for i in raw if 'cProverStatus' in i]
    complete = EXPECTED <= {p.get('description') for p in properties}
    good = code == 0 and terminal == ['success'] and complete and not diagnostics and properties and all(p.get('status') == 'SUCCESS' for p in properties)
    return dict(status='BOUNDED_HELPER_PASS' if good else 'NOT_PROVEN',
                properties=len(properties), complete_inventory=complete,
                terminal=terminal, diagnostics=diagnostics,
                failed=[p.get('description') for p in properties if p.get('status') == 'FAILURE'])


def run(output):
    if not __debug__:
        raise RuntimeError('verification must not disable assertions')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    header = root / 'net/sparklink/sle_message_security.h'
    harness = here / 'session/message_context_cbmc.c'
    inputs = {p: p.read_bytes() for p in [header, harness, root/'include/uapi/linux/sparklink_socket.h', Path(__file__).resolve()]}
    report = dict(status='RUNNING_NOT_PROVEN', source_head=subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip(),
                  source_tree_clean=not subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain'], text=True).strip(),
                  sources={str(p.relative_to(root)): hashlib.sha256(b).hexdigest() for p, b in inputs.items()},
                  tool=subprocess.check_output(['cbmc', '--version'], text=True).strip(),
                  scope='Actual production receipt/dequeue helpers; arbitrary64bit ingress/arrival/current epochs and full signed32bit Owner results; one receipt then one dequeue observation, not long-running invariants or actual Owner/Host locks/ref/USB/queue/RF/firmware proof',
                  assumptions=['Valid kernel-owned pointers', 'Runtime supplies truthful level/revision observations from sole physical Owner under its locks; helpers do not prove that source, locking, reference retention or dequeue integration'],
                  expected=sorted(EXPECTED), runs=[])
    path = output / 'report.json'
    def save():
        temporary = path.with_suffix('.tmp')
        temporary.write_text(json.dumps(report, indent=2) + '\n')
        temporary.replace(path)
    save()
    try:
        for kind in ['production', 'missing-epoch-negative', 'missing-level-negative', 'missing-properties-negative']:
            folder = output / kind
            folder.mkdir()
            source = inputs[header].decode()
            if kind == 'missing-epoch-negative':
                assert 'm->security_epoch == current' in source
                source = source.replace('m->security_epoch == current', '1')
            if kind == 'missing-level-negative':
                assert 'level >= 0 && level <= 2' in source
                source = source.replace('level >= 0 && level <= 2', '1')
            (folder / header.name).write_text(source)
            (folder / 'harness.c').write_bytes(inputs[harness])
            (folder/'sparklink_socket.h').write_bytes(inputs[root/'include/uapi/linux/sparklink_socket.h'])
            command = ['cbmc', str(folder / 'harness.c'), '-I', str(folder), '--function',
                       'empty_check' if kind == 'missing-properties-negative' else 'verify_message_receipt',
                       '--drop-unused-functions', '--unwind', '3', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                       '--pointer-overflow-check', '--signed-overflow-check', '--unsigned-overflow-check', '--json-ui', '--trace']
            raw_path = folder / 'raw.json'
            with raw_path.open('x') as stream:
                done = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=120)
            raw = json.loads(raw_path.read_text())
            verdict = inspect(raw, done.returncode)
            row = dict(kind=kind, command=command, exit=done.returncode,
                       raw_sha256=hashlib.sha256(raw_path.read_bytes()).hexdigest(), **verdict)
            report['runs'].append(row)
            save()
            if kind == 'production':
                assert verdict['status'] == 'BOUNDED_HELPER_PASS', row
            elif kind == 'missing-epoch-negative':
                assert done.returncode == 10 and verdict['terminal'] == ['failure'] and not verdict['diagnostics']
                assert 'old receipt never obtains current qualification' in verdict['failed']
            elif kind == 'missing-level-negative':
                assert done.returncode == 10 and verdict['terminal'] == ['failure'] and not verdict['diagnostics']
                assert 'known receipt requires matching original epoch and bounded Owner observation' in verdict['failed']
            else:
                assert done.returncode == 0 and verdict['terminal'] == ['success'] and not verdict['complete_inventory'] and verdict['status'] == 'NOT_PROVEN'
        assert all(p.read_bytes() == b for p, b in inputs.items())
        report['status'] = 'BOUNDED_RECEIPT_HELPER_AND_THREE_NEGATIVES_PASS'
    except BaseException as error:
        report.update(status='NOT_PROVEN', error_type=type(error).__name__, error=str(error))
        raise
    finally:
        report['end_wall_ns'] = time.time_ns()
        save()
    print(report['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    run(parser.parse_args().output)
