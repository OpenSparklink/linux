#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual bounded BSLE attempt wrapper/getter;explicit non-kernel dependencies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from run_native_ticket_driver import function


def run(output, artifacts):
    if output:
        output.write_text(json.dumps(dict(status='RUNNING_NOT_QUALIFIED', completed=False))+'\n')
    here = Path(__file__).resolve().parent
    root = here.parents[3]
    source = root/'drivers/sparklink/ws73/usb.c'
    fixture = here/'ws73-runtime-rx/boot_attempt_fixture.c'
    files = [source, fixture, Path(__file__).resolve(), here/'run_native_ticket_driver.py',
             root/'drivers/sparklink/ws73/bsle.h', root/'drivers/sparklink/ws73/wire.h']
    inputs = {p: p.read_bytes() for p in files}
    text = inputs[source].decode()
    definitions = []
    for name in ['enum ws73_stage', 'enum ws73_bsle_attempt_kind',
                 'struct ws73_bsle_attempt_record', 'struct ws73_bsle_attempt_history']:
        start = text.index(name+' {')
        definitions.append(text[start:text.index('\n};', start)+3])
    define = re.search(r'^#define WS73_BSLE_ATTEMPTS_MAX .*$', text, re.M)[0]
    wrapper = function(text, 'ws73_run_bsle_attempt')
    getter = function(text.replace('static ssize_t bsle_attempts_show',
                                   'static int bsle_attempts_show', 1),
                      'bsle_attempts_show').replace('static int bsle_attempts_show',
                                                   'static ssize_t bsle_attempts_show', 1)
    assert wrapper in text and getter in text
    # Both production callers must use this wrapper,not just the test consumer.
    runtime = function(text, 'ws73_runtime_start')
    assert runtime.count('ws73_run_bsle_attempt(') == 2
    assert 'restore ? WS73_BSLE_ATTEMPT_PROTOCOL : WS73_BSLE_ATTEMPT_INITIAL' in ' '.join(runtime.split())
    assert 'custom, WS73_BSLE_ATTEMPT_WARM)' in runtime
    assert not re.search(r'\bws73_bsle_(?:start|restore)\(', runtime)
    assert '&dev_attr_bsle_attempts.attr,' in text and 'static DEVICE_ATTR_RO(bsle_attempts);' in text
    template = inputs[fixture].decode().replace('/* @@DECLARATIONS@@ */', define+'\n'+'\n'.join(definitions))
    bodies = wrapper+'\n'+getter
    def with_bodies(actual):
        # Signature-only unused-parameter annotation for the mandatory sysfs
        # ABI argument. Production function bodies remain byte-identical.
        return template.replace('/* @@ACTUAL@@ */', actual.replace(
            'struct device_attribute *attr,',
            'struct device_attribute *attr __attribute__((unused)),', 1))
    code = with_bodies(bodies)
    compiler = os.environ.get('CC', 'clang')
    if artifacts:
        artifacts.mkdir(parents=True, exist_ok=False)
    negative = []
    with tempfile.TemporaryDirectory(prefix='ws73-bsle-attempts-') as directory:
        temporary = Path(directory)
        actual, binary = temporary/'actual.c', temporary/'test'
        command = [compiler, '-std=c11', '-Wall', '-Wextra', '-Werror',
                   '-fsanitize=address,undefined', '-fno-omit-frame-pointer', '-g',
                   '-I'+str(root/'drivers/sparklink/ws73'), str(actual), '-o', str(binary)]
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1', UBSAN_OPTIONS='halt_on_error=1')
        actual.write_text(code)
        subprocess.run(command, check=True)
        child = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10, env=environment)
        if child.returncode or child.stderr:
            raise RuntimeError('actual production fixture failed: '+child.stdout+child.stderr)
        result = json.loads(child.stdout)
        assert result['status'] == 'WS73_BSLE_ATTEMPT_FUNCTIONS_PASS'
        binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
        if artifacts:
            shutil.copy2(actual, artifacts/'actual.c')
            shutil.copy2(binary, artifacts/'test')
            (artifacts/'stdout').write_text(child.stdout)
        mutations = {
            'prefix-overwritten': ('history->records[history->count++] = sample;',
                                   'history->records[0] = sample, history->count++;'),
            'warm-routed-to-initial': ('kind == WS73_BSLE_ATTEMPT_INITIAL ?',
                                      'kind != WS73_BSLE_ATTEMPT_PROTOCOL ?'),
            'original-phase-hidden': ('sample.phase = READ_ONCE(ws->stage);',
                                      'sample.phase = WS73_FAILED;'),
            'sequencer-error-hidden': ('\treturn ret;\n}', '\treturn 0;\n}'),
            'busy-reader-unlocked': ('if (!mutex_trylock(&ws->phase_lock))',
                                     'if (!mutex_trylock(&ws->phase_lock) && false)'),
            'omitted-counter-wraps': ('history->omitted != ~0U', 'true'),
        }
        for name, (before, after) in mutations.items():
            assert bodies.count(before) == 1
            changed = with_bodies(bodies.replace(before, after, 1))
            actual.write_text(changed)
            subprocess.run(command, check=True)
            child = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10, env=environment)
            assert child.returncode == -6 and 'Assertion' in child.stderr, (name, child.returncode, child.stderr)
            if artifacts:
                shutil.copy2(actual, artifacts/(name+'.c'))
                shutil.copy2(binary, artifacts/(name+'.bin'))
                (artifacts/(name+'.stderr')).write_text(child.stderr)
            negative.append(dict(case=name, rejected=True, method='COMPILED_MUTATION_ASSERTION_ABORT',
                                 stderr_sha256=hashlib.sha256(child.stderr.encode()).hexdigest()))
    assert all(p.read_bytes() == content for p, content in inputs.items())
    result.update(completed=True, negative_controls=negative,
                  sources={str(p.relative_to(root)): hashlib.sha256(content).hexdigest() for p, content in inputs.items()},
                  generated_source_sha256=hashlib.sha256(code.encode()).hexdigest(), test_binary_sha256=binary_sha,
                  fixture_parameter_annotation='Mandatory unused sysfs attr parameter only;production bodies unchanged',
                  compiler=subprocess.check_output([compiler, '--version'], text=True),
                  scope='Actual driver attempt wrapper and locked sysfs getter. Sequencer outcomes,clock,phase/sequence mutation,logger,mutex and sysfs buffer are explicit synchronous fixtures. Original per-call phase/error/time/sequence retained;first8 prefix and saturated omission,peer separation,busy/read-only behavior and page bounds. Not actual BSLE handshake,USB,allocation/probe,concurrency,attribute removal,final drain,Ready,peer delivery,recovery or formal proof.',
                  physical_acceptance=False, formal_proof=False)
    if output:
        output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--artifacts', type=Path)
    args = parser.parse_args()
    run(args.output, args.artifacts)
