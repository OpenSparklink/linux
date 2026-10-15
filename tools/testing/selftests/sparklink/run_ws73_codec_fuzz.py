#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline libFuzzer on unchanged production C. Never loads a driver or USB.

A completed bounded exploration is not a proof, kernel concurrency/sanitizer
qualification, firmware behavior, or real-device acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
REQUIRED = ['ws73_wire_receive', 'ws73_wire_acb_fragment_decode',
            'ws73_wire_acb_fragment', 'ws73_dli_validate_security_event',
            'ws73_dli_validate_reply', 'ws73_dli_link_outcome']


def completed(text, code):
    """Fail closed even when an incorrect wrapper masks a sanitizer exit."""
    faults = ['ERROR:', 'runtime error:', 'AddressSanitizer:',
              'UndefinedBehaviorSanitizer:', 'LeakSanitizer:', 'libFuzzer: deadly signal',
              'LeakSanitizer has encountered a fatal error', 'unsupported instrumentation']
    stats = re.search(r'stat::number_of_executed_units:\s*(\d+)', text)
    done = re.search(r'Done (\d+) runs in \d+ second', text)
    return (code == 0 and not any(word in text for word in faults)
            and bool(re.search(r'#\d+\s+DONE\s+cov:', text))
            and stats is not None and done is not None
            and int(stats[1]) == int(done[1]) and int(done[1]) > 0)


def coverage_counts(document):
    counts = {}
    for section in document['data']:
        for entry in section['functions']:
            name = entry['name'].split(':')[-1]
            if name in REQUIRED:
                counts[name] = counts.get(name, 0) + entry['count']
    if set(counts) != set(REQUIRED) or any(n <= 0 for n in counts.values()):
        raise ValueError('required actual production functions did not execute')
    return counts


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = [HERE/'fuzz/ws73_codec_fuzz.c', HERE/'fuzz/ws73_codec_corpus.json',
               Path(__file__), HERE/'fuzz/test_ws73_codec_verdict.py', ROOT/'drivers/sparklink/ws73/wire.c',
               ROOT/'drivers/sparklink/ws73/wire.h', ROOT/'drivers/sparklink/ws73/dli.c',
               ROOT/'drivers/sparklink/ws73/dli.h', ROOT/'drivers/sparklink/ws73/bsle.h']
    snapshot = {str(p.relative_to(ROOT)): digest(p) for p in sources}
    report = dict(schema_version=1, status='RUNNING_NOT_QUALIFIED', completed=False,
                  accepted_exploration=False, proof=False, physical_acceptance=False,
                  source_commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                  source_hashes=snapshot, source_worktree_status=subprocess.check_output(['git','status','--porcelain'],cwd=ROOT,text=True).splitlines(), phases=[], bounds=dict(runs=args.runs,seed=args.seed,
                  max_input_bytes=20480,input_timeout_seconds=2,phase_wall_timeout_seconds=60,
                  software_memory_mb=512),
                  real_dependencies='Production wire.c/dli.c, libc malloc, Clang libFuzzer/ASAN/UBSAN and LLVM coverage; no protocol/USB/clock/lock success stubs',
                  fixture='Hand-authored legal/malformed input corpus and input-bounds observer callback with explicit ECANCELED outcome',
                  excluded=['kernel allocator/locks/refcounts/USB callbacks and real concurrency',
                            'BSLE/query state machines, split/concatenation transport, data credit/tickets/Grant',
                            'full input/state proof, hardware/firmware behavior, security/trusted identity and natural recovery'])
    report_file = out/'report.json'
    def save():
        temporary = out/'report.pending.json'
        temporary.write_text(json.dumps(report,indent=2)+'\n')
        temporary.replace(report_file)
    def invoke(name, command, env=None, timeout=60):
        row = dict(name=name, command=command, status='RUNNING', start_ns=time.time_ns())
        report['phases'].append(row); save()
        try:
            p = subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                               env=env,timeout=timeout,cwd=ROOT)
            row['exit']=p.returncode; raw=p.stdout
        except subprocess.TimeoutExpired as e:
            raw=e.stdout or b'';row['exit']='TIMEOUT'
        (out/(name+'.log')).write_bytes(raw)
        row.update(log_sha256=hashlib.sha256(raw).hexdigest(),end_ns=time.time_ns())
        row['status']='COMMAND_COMPLETED' if row['exit']==0 else 'FAILED_OR_UNVERIFIED'
        save()
        if row['exit']!=0: raise RuntimeError(name+' failed or timed out')
        return raw.decode(errors='replace')
    try:
        compiler=os.environ.get('CC','clang')
        profdata=os.environ.get('LLVM_PROFDATA','llvm-profdata')
        cov=os.environ.get('LLVM_COV','llvm-cov')
        for name in [compiler, profdata,cov,'nm']:
            if not shutil.which(name):raise RuntimeError('required tool unavailable: '+name)
        report['tools']={name:subprocess.check_output([name,'--version'],text=True).splitlines()[0]
                         for name in [compiler,profdata,cov]}
        catalog=json.loads((HERE/'fuzz/ws73_codec_corpus.json').read_text())
        if catalog['schema_version']!=1 or len(catalog['seeds'])<10:raise ValueError('bounded fixed corpus missing')
        fixed=out/'fixed-corpus';fixed.mkdir()
        for name,hexdata in catalog['seeds'].items():
            if not re.fullmatch(r'[a-z0-9-]+',name):raise ValueError('invalid seed name')
            data=bytes.fromhex(hexdata)
            if len(data)>20480:raise ValueError('seed exceeds input budget')
            (fixed/name).write_bytes(data)
        report['fixed_corpus']={p.name:digest(p) for p in sorted(fixed.iterdir())}
        binary=out/'ws73-codec-fuzz'
        command=[compiler,'-std=c11','-g','-O1','-Wall','-Wextra','-Werror',
                 '-fsanitize=fuzzer,address,undefined','-fno-omit-frame-pointer',
                 '-fprofile-instr-generate','-fcoverage-mapping',
                 str(HERE/'fuzz/ws73_codec_fuzz.c'),str(ROOT/'drivers/sparklink/ws73/wire.c'),
                 str(ROOT/'drivers/sparklink/ws73/dli.c'),'-o',str(binary)]
        invoke('compile',command)
        symbols=subprocess.check_output(['nm',str(binary)],text=True)
        for symbol in ['__asan_init','__ubsan_handle_', '__sanitizer_cov_8bit_counters_init','LLVMFuzzerTestOneInput']:
            if symbol not in symbols:raise ValueError('missing instrumentation: '+symbol)
        report['binary_sha256']=digest(binary)
        for phase,runs in [('replay',0),('explore',args.runs)]:
            corpus=out/(phase+'-corpus');shutil.copytree(fixed,corpus)
            env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                     UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1',
                     LLVM_PROFILE_FILE=str(out/(phase+'-%p.profraw')))
            command=[str(binary),str(corpus),'-runs='+str(runs),'-seed='+str(args.seed),
                     '-max_len=20480','-timeout=2','-rss_limit_mb=512','-print_final_stats=1',
                     '-artifact_prefix='+str(out)+'/' ]
            text=invoke(phase,command,env)
            if not completed(text,0):raise ValueError(phase+' missing complete, clean libFuzzer result')
            count=int(re.search(r'stat::number_of_executed_units:\s*(\d+)',text)[1])
            if phase=='explore' and count<args.runs:raise ValueError('exploration budget incomplete')
            report['phases'][-1].update(status='BOUNDED_COMPLETED_NO_FINDING',executed_units=count)
        profiles=sorted(out.glob('*.profraw'))
        if not profiles:raise ValueError('coverage profiles missing')
        merged=out/'merged.profdata'
        invoke('merge-coverage',[profdata,'merge','-sparse',*[str(p) for p in profiles],'-o',str(merged)])
        raw=invoke('export-coverage',[cov,'export',str(binary),'-instr-profile='+str(merged)])
        report['actual_production_execution_counts']=coverage_counts(json.loads(raw))
        report['final_corpus']={p.name:digest(p) for p in sorted((out/'explore-corpus').iterdir())}
        if snapshot!={str(p.relative_to(ROOT)):digest(p) for p in sources}:raise ValueError('source changed during run')
        report.update(status='BOUNDED_FUZZ_COMPLETED_NO_FINDING',accepted_exploration=True)
    except (OSError,ValueError,RuntimeError,KeyError,subprocess.SubprocessError) as error:
        report.update(status='FAILED_OR_UNVERIFIED',error=str(error))
    finally:
        report['completed']=True;save()
    print(report['status'],report_file)
    return 0 if report['accepted_exploration'] else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True,help='new directory; never overwrite failures/corpus')
    parser.add_argument('--runs',type=int,default=20000)
    parser.add_argument('--seed',type=int,default=730111)
    args=parser.parse_args()
    if not 1000<=args.runs<=1000000 or not 0<=args.seed<2**32:parser.error('bounded runs1000..1000000 and u32 seed required')
    raise SystemExit(run(args))
