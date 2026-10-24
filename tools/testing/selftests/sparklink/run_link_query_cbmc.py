#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual WS73 typed link recipe/validator; bounded proof with source mutants.

Optional CBMC invocation, never a driver, concurrent lifecycle or RF test.
The default selftest tests this verdict parser without needing CBMC.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time

PROPERTIES = {
    'LQI_u32_model', 'LQI_output_guards', 'LQI_invalid_rejected',
    'LQI_failure_atomic', 'LQI_valid_accepted', 'LQI_typed_recipe',
    'LQI_LE16_handle', 'LQI_LE16_payload', 'LQI_unused_bytes_zero', 'LQI_plan_validates',
    'LQI_validator_shape',
}


def audit(raw, stderr, code, expected_failure=None):
    """Missing properties, warnings, incomplete unwinds or traces fail closed."""
    try:
        rows = json.loads(raw)
        if type(rows) is not list or any(type(r) is not dict for r in rows):
            return False
        properties = [p for r in rows for p in r.get('result', [])]
        if not properties or any(type(p) is not dict for p in properties):
            return False
        ids = [p['property'] for p in properties]
        named = [p['description'] for p in properties if p.get('description', '').startswith('LQI_')]
        if (stderr or len(set(ids)) != len(ids) or set(named) != PROPERTIES
                or len(named) != len(PROPERTIES)
                or any(r.get('messageType', '').upper() in ('WARNING', 'ERROR') for r in rows)
                or any(re.search(r'unsupported|warning|not supported', r.get('messageText', ''), re.I) for r in rows)):
            return False
        terminal = [r['cProverStatus'] for r in rows if 'cProverStatus' in r]
        failed = [p for p in properties if p.get('status') != 'SUCCESS']
        if expected_failure is None:
            return code == 0 and terminal == ['success'] and not failed
        return (expected_failure in PROPERTIES and code == 10 and terminal == ['failure']
                and len(failed) == 1 and failed[0].get('description') == expected_failure
                and failed[0].get('status') == 'FAILURE' and bool(failed[0].get('trace')))
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(output, timeout):
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    driver = root/'drivers/sparklink/ws73'
    production = driver/'connection.c'
    harness = here/'connection/link_query_cbmc.c'
    paths = [production, driver/'connection.h', root/'include/linux/sparklink_connection.h',
             harness, Path(__file__).resolve()]
    sources = {str(p.relative_to(root)): sha(p) for p in paths}
    output.mkdir(parents=True, exist_ok=False)
    report = dict(status='RUNNING_UNPROVED', source_head=subprocess.check_output(
        ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(), sources=sources,
        source_tree_clean=not bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)),
        timeout_seconds_per_case=timeout, cases=[], real_acceptance=False,
        assumptions=['Valid allocated C objects or NULL; arbitrary-invalid caller pointers excluded.',
                     'Sequential actual prepare/validate functions, 64-bit little-endian C target.',
                     'CBMC C frontend, SAT solver and C integer/object model are trusted.'],
        bounds=['Selectors4/5/6; arbitrary32bit request fields and all parameter bytes.',
                'Validator arbitrary32bit opcode/64bit length and32byte buffer or NULL.',
                'Unwind64 with unwinding assertions; intentional unsigned LE16 narrowing checked by exact bytes.'],
        properties=sorted(PROPERTIES),
        source_mapping={'prepare': 'drivers/sparklink/ws73/connection.c:ws73_connection_prepare',
                        'validate': 'drivers/sparklink/ws73/connection.c:ws73_connection_validate'},
        not_proved=['Host locks/references/lifetime/generation/Grant and final USB ticket commit.',
                    'Command/data credit, NOCP accuracy, late/duplicate events and reuse barriers.',
                    'Kernel execution, firmware identity/semantics, peer delivery, temporal liveness or refinement.'])
    result_path = output/'report.json'
    result_path.write_text(json.dumps(report, indent=2)+'\n')
    try:
        report['tool_version'] = subprocess.check_output(['cbmc', '--version'], text=True).strip()
        include = output/'include/linux'
        include.mkdir(parents=True)
        (include/'sparklink_connection.h').symlink_to(paths[2])
        original = production.read_text()
        cases = [('production', None, None, None),
                 ('big-endian-payload', '            put16(candidate.params + 2, request->payload_octets);',
                  '            candidate.params[2] = request->payload_octets >> 8; candidate.params[3] = request->payload_octets;',
                  'LQI_LE16_payload'),
                 ('big-endian-handle', '        put16(candidate.params, request->handle);',
                  '        candidate.params[0] = request->handle >> 8; candidate.params[1] = request->handle;',
                  'LQI_LE16_handle'),
                 ('early-output-write', '    struct sparklink_connection_plan candidate = {0};',
                  '    if (request && out) memset(out, 0, sizeof(*out));\n    struct sparklink_connection_plan candidate = {0};',
                  'LQI_failure_atomic')]
        for name, before, after, expected in cases:
            folder = output/name
            folder.mkdir()
            source = production
            if before is not None:
                if original.count(before) != 1:
                    raise ValueError('mutant source anchor changed: '+name)
                source = folder/'connection.c'
                source.write_text(original.replace(before, after))
            command = ['cbmc', str(harness), str(source), '-I'+str(output/'include'),
                       '-I'+str(driver), '--function', 'main', '--64', '--little-endian',
                       '--unwind', '64', '--unwinding-assertions', '--bounds-check',
                       '--pointer-check', '--pointer-overflow-check', '--signed-overflow-check',
                       '--div-by-zero-check', '--trace', '--json-ui']
            row = dict(name=name, command=command, source_sha256=sha(source),
                       expected_failure=expected, start_ns=time.time_ns(), audited=False)
            report['cases'].append(row)
            try:
                process = subprocess.run(command, capture_output=True, timeout=timeout)
                raw, stderr = process.stdout, process.stderr
                row.update(exit=process.returncode, audited=audit(raw, stderr, process.returncode, expected))
            except subprocess.TimeoutExpired as error:
                raw, stderr = error.stdout or b'', error.stderr or b''
                row.update(exit=None, error='TIMEOUT_UNPROVED')
            (folder/'raw.json').write_bytes(raw)
            (folder/'stderr.txt').write_bytes(stderr)
            row.update(end_ns=time.time_ns(), raw_sha256=sha(folder/'raw.json'), stderr_sha256=sha(folder/'stderr.txt'))
        if sources != {str(p.relative_to(root)): sha(p) for p in paths}:
            raise ValueError('production or proof source changed while running')
        if all(r['audited'] for r in report['cases']):
            report['status'] = 'PRODUCTION_LINK_COMMAND_RECIPE_BOUNDED_PASS'
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        report.update(status='UNPROVED', error=str(error))
    if report['status'] == 'RUNNING_UNPROVED':
        report['status'] = 'UNPROVED'
    report['end_ns'] = time.time_ns()
    temporary = result_path.with_suffix('.tmp')
    temporary.write_text(json.dumps(report, indent=2)+'\n')
    temporary.replace(result_path)
    print(report['status'])
    return report['status'] == 'PRODUCTION_LINK_COMMAND_RECIPE_BOUNDED_PASS'


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 3600:
        parser.error('timeout must be between1 and3600 seconds')
    raise SystemExit(0 if run(args.output.resolve(), args.timeout) else 1)
