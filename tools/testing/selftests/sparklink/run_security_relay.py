#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test actual production per-connection relay transitions; no devices or RF."""
import argparse
import hashlib
import json
import os
import re
import signal
from pathlib import Path
import subprocess
import tempfile

here = Path(__file__).resolve().parent
root = here.parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path)
parser.add_argument('--kani', action='store_true', help='verify the same production source in a private mirrored tree')
parser.add_argument('--kani-harness', choices=['capability_withdraw_deadline_and_submit', 'capability_requires_peer_and_terminal_complete','key_agreement_job_cancel_and_physical_obligation','installation_submit_cancel_accept_and_event'], help='select one relay proof; requires --kani')
parser.add_argument('--timeout', type=int, default=300, help='formal tool seconds; timeout is NOT_PROVEN')
args = parser.parse_args()
if args.kani_harness and not args.kani:parser.error('--kani-harness requires --kani')
paths = [root / 'net/sparklink/sle_security_relay_state.rs', here / 'security/relay_session.rs']
if args.kani:
    paths.append(here / 'security/relay_session_kani.rs')
originals = {p: p.read_bytes() for p in paths}
runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
with tempfile.TemporaryDirectory(prefix='sparklink-relay-session-') as directory:
    binary = str(Path(directory) / 'regression')
    subprocess.run(['rustc', '--edition=2024', '--test', '-Dwarnings', str(paths[1]), '-o', binary], check=True)
    regression=subprocess.run([binary],check=False,text=True,capture_output=True)
    print(regression.stdout,end="")
    print(regression.stderr,end="")
    regression.check_returncode()
    counts=re.findall(r"test result: ok\. (\d+) passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",regression.stdout)
    if len(counts)!=1 or int(counts[0])==0:raise ValueError("complete nonempty regression verdict required")
    test_count=int(counts[0])
    formal = None
    if args.kani:
        mirror = Path(directory) / 'linux'
        for path, contents in originals.items():
            target = mirror / path.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
        model = mirror / paths[-1].relative_to(root)
        command = ['kani', str(model)]
        if args.kani_harness:command += ['--harness',args.kani_harness]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=args.timeout)
            log = stdout + stderr
            status = 'BOUNDED_PASS' if process.returncode == 0 else 'NOT_PROVEN'
            expected_harnesses=1 if args.kani_harness else 6
            verdict=re.findall(r'Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.',log)
            if verdict!=[(str(expected_harnesses),'0',str(expected_harnesses))]:status='NOT_PROVEN_INCOMPLETE'
            if 'unsupported' in log.lower():
                status = 'NOT_PROVEN_UNSUPPORTED'
            formal = dict(status=status, exit=process.returncode,
                          generated_checks=[int(n) for n in re.findall(r'0 of (\d+) failed', log)],
                          command=['kani', str(paths[-1].relative_to(root))]+(['--harness',args.kani_harness] if args.kani_harness else []),
                          log_sha256=hashlib.sha256(log.encode()).hexdigest(),
                          version=subprocess.check_output(['kani', '--version'], text=True).strip())
        except subprocess.TimeoutExpired:
            # Stop the verifier's whole process group, including solver/compiler.
            # A timed-out parent must not leave an untracked verification run.
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
            log = stdout + stderr
            formal = dict(status='NOT_PROVEN_TIMEOUT', timeout=args.timeout,
                          log_sha256=hashlib.sha256(log.encode()).hexdigest())
        if args.output:
            args.output.with_suffix('.kani.log').write_text(log)
assert all(p.read_bytes() == data for p, data in originals.items())
record = dict(status='PRODUCTION_RELAY_SESSION_REGRESSION_PASS', tests=test_count,
              default_kernel_implementation=True, rf_acceptance=False,
              source_head=subprocess.check_output(['git','-C',str(root),'rev-parse','HEAD'],text=True).strip(),
              source_tree_clean=not subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip(),
              runner_sha256=runner_sha256,
              rustc=subprocess.check_output(['rustc', '--version'], text=True).strip(),
              sources={str(p.relative_to(root)): hashlib.sha256(data).hexdigest() for p, data in originals.items()})
if formal is not None:
    record['formal'] = formal
    record['proof_scope'] = dict(harness=args.kani_harness or 'all6', queue_depth=2,
        capability_payload_bytes=10, capability_exchanges=1, capability_terminal_replies=1,
        arbitrary_commit_time_u64=args.kani_harness in [None,'capability_withdraw_deadline_and_submit'], unwind=80 if args.kani_harness in [None,'key_agreement_job_cancel_and_physical_obligation','installation_submit_cancel_accept_and_event'] else 12,
        property_inventory_by_harness={
            'capability_withdraw_deadline_and_submit':[
                'No callback after prior withdraw/expiry or foreign identity',
                'Submit failure is nondeterministic; only accepted callback creates obligation',
                'Withdraw/expiry preserve submitted obligation until matching terminal reply'],
            'capability_requires_peer_and_terminal_complete':[
                'Successful Status alone cannot pay obligation or complete exchange',
                'Both peer ingress and real Complete required in either order; terminal failure cannot revive'],
            'key_agreement_job_cancel_and_physical_obligation':[
                'G public crypto job cannot be created before T response actually submits',
                'Withdraw/expiry reject either successful or failed crypto receipt and create no continuation',
                'Submitted T response obligation remains until its actual matching terminal reply']},
        assumptions=['Caller serializes exact production methods under Owner lock',
                     'Host/gate identity is current; driver callback atomically accepts or NEVER queues',
                     'Input reply ticket already resolved by Host; peer ingress identity already frozen'],
        excluded=['Actual locks/references/IRQ/USB callback drain and Host-to-driver mapping',
                  'Wire Complete uniqueness, late/duplicate handle attribution, firmware state clear/reuse barrier',
                  'Unbounded execution, cryptography, authentication, Agent, actual controller key installation and natural recovery'])
    if args.kani_harness == 'installation_submit_cancel_accept_and_event':
        record['proof_scope'].update(role='G only', original_deadline=100,
            logical_schedule='fixed0..28, expiry100 and lateroff101/102; not arbitrary time or kernel clock proof',
            wire_inputs='knownoffer10, ownpub64/encoded70, peerpub64 and16byte confirmation/nonce/proof fixtures',
            crypto_jobs=4, local_relays=4, installation_intents=1,
            crypto_dependency='success/failure nondeterministic, not valid-point/math proof',
            installation_scope='actual metadata transitions; opaque C key copy and actual driver lock/reference/USB excluded')
        record['proof_scope']['property_inventory_by_harness']['installation_submit_cancel_accept_and_event']=[
            'Drive actual G capability/public/confirm/nonce/proof transitions before installation; no force-ready model',
            'Every actual submit and crypto job has failure branches; accepted command and real0011 independently required',
            'Withdraw/expiry before materialize or final submit prevents callback; cancel after submit retains obligation until matching reply',
            'Late reply or encryption event cannot revive cancelled/failed Session; post-success off invalidates even beyond original deadline',
            'Command Status pays only command obligation; pending asynchronous install survives cancel/expiry until actual domain evidence or physical retirement']
        record['proof_scope']['request_cancel_scope'] = 'Before materialization/final submit and after actual submit/Status, nondeterministic choice of author withdraw or actual production Session.cancel; cancellation idempotence checked. Original File/request validation and Runtime locking are outside this pure harness.'
        record['proof_scope']['excluded'] += ['Actual C key copy, firmware encryption truth, independent radio cipher attestation, T role installation model and uncertain USB failure combination']
    record['regression_status'] = 'PASS'
    if formal['status'] != 'BOUNDED_PASS':
        record['status'] = 'PRODUCTION_RELAY_SESSION_FORMAL_NOT_PROVEN'
if args.output:
    args.output.write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record))
if formal is not None and formal['status'] != 'BOUNDED_PASS':
    raise SystemExit(1)
