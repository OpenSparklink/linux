#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual model dispatch plus actual driver chip codec; no USB or RF proof."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess


def run(args):
    here = Path(__file__).resolve().parent
    root = here.parents[4]
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('boundary', here / 'check-usb-host-boundary.py')
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    source = (here / 'usb-ws73-test.c').read_text()
    actual = '\n'.join(boundary.body(source, name) for name in
                       ['le16', 'le32', 'put16', 'put32', 'queue_frame', 'outgoing'])
    fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "wire.h"
/* Explicit dependency fixture: no QEMU scheduling or USB execution here.
 * An unexpected protocol-command branch FAILS, never succeeds via a stub. */
#define g_assert assert
#define MAX(a,b) ((a)>(b)?(a):(b))
#define ROUND_UP(a,b) (((a)+(b)-1)&~((b)-1))
#define QEMU_CLOCK_VIRTUAL 0
static uint64_t qemu_clock_get_ms(int type) { assert(type == 0); return 0; }
typedef struct { unsigned sequence, head, count, commands; bool opened, pm, custom;
    bool runtime_sle_subtypes; uint8_t packets[64][1024];
    unsigned packet_size[64]; uint64_t ready_at[64]; } USBWs73Test;
static void bsle_ack(USBWs73Test *s, unsigned msg) { (void)s; (void)msg; assert(0); }
static bool command(USBWs73Test *s, const uint8_t *p, size_t n)
{ (void)s; (void)p; (void)n; assert(0); return false; }
@@ACTUAL@@
static unsigned consumed;
static int receive_chip(void *context, unsigned service, unsigned queue,
                        const unsigned char *data, size_t size)
{
    struct ws73_chip_info *chip = context;
    assert(service == 1 && queue == 9 && !consumed++);
    return ws73_wire_chip_reply(data, size, chip);
}
int main(void)
{
    uint8_t request[128];
    const uint8_t expected[14] = { 10,0,10,0,0,0,0,0,2,0,0,0,0,0 };
    for (unsigned test = 0; test < 10; test++) {
        USBWs73Test state = { .opened=true, .pm=true, .custom=true };
        consumed = 0;
        assert(ws73_wire_chip_request(request, sizeof(request), 0) == 128);
        size_t n = sizeof(request);
        switch (test) {
        case 1: state.opened=false; break;
        case 2: state.pm=false; break;
        case 3: state.custom=false; break;
        case 4: request[70]=0; break;
        case 5: request[72]=1; break;
        case 6: request[66]=31; break;
        case 7: request[68]=17; break;
        case 8: n--; break;
        case 9: request[8]=1; break;
        }
        bool accepted = outgoing(&state, request, n);
        if (!test) {
            struct ws73_chip_info chip = { .model=255, .bus=255 };
            assert(accepted && state.count == 1 && state.packet_size[0] == 156);
            assert(!memcmp(state.packets[0] + 96, expected, sizeof(expected)));
            assert(!ws73_wire_receive(state.packets[0], state.packet_size[0], receive_chip, &chip));
            assert(consumed == 1);
            assert(chip.model == 0 && chip.bus == 0);
            /* The earlier payload-only fixture missed this exact bad subtype.
             * It must fail before calling a consumer in the actual parser. */
            consumed = 0; state.packets[0][92] = 0x10;
            assert(ws73_wire_receive(state.packets[0], state.packet_size[0], receive_chip, &chip) < 0);
            assert(!consumed);
        } else { assert(!accepted && !state.count); }
    }
    return 0;
}
'''.replace('@@ACTUAL@@', actual)
    c = args.output / 'dispatch.c'
    c.write_text(fixture)
    wire = root / 'drivers/sparklink/ws73/wire.c'
    header = wire.with_suffix('.h')
    command = shlex.split(os.environ.get('CC', 'clang')) + [
        '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(wire.parent),
        str(c), str(wire), '-o', str(args.output / 'dispatch')]
    if args.sanitize:
        command += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(command, check=True)
    subprocess.run([str(args.output / 'dispatch')], check=True,
                   env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                            UBSAN_OPTIONS='halt_on_error=1'))
    record = dict(status='MODEL_CHIP_DISPATCH_OFFLINE_PASS', cases=10, command=command,
                  sources={str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                           for p in [here / 'usb-ws73-test.c', wire, header, Path(__file__),
                                     here / 'check-usb-host-boundary.py']},
                  fixture_sha256=hashlib.sha256(c.read_bytes()).hexdigest(),
                  scope='Actual model dispatch/queue_frame and production driver full HCC/request/reply parser. Clock/state are fixtures, other command branches abort. Bad subtype counterexample retained; no QEMU scheduling, USB, firmware, real chip identification, cold ROM or RF proof.',
                  physical_acceptance=False)
    (args.output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--sanitize', action='store_true')
    run(parser.parse_args())
