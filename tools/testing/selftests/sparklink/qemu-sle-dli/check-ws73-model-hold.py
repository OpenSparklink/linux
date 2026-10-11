#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual test-model retention functions with counted dependency fixtures.

No QEMU scheduler, host USB, successful libusb transfer or physical RF proof.
Timers, wakeup and digest are counted substitutes. Queue bytes remain real.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess


def check(args):
    args.output.mkdir(parents=True, exist_ok=False)
    source = args.source.read_text()
    spec = importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('check-usb-host-boundary.py'))
    boundary = importlib.util.module_from_spec(spec); spec.loader.exec_module(boundary)
    names = ['reset', 'model_release', 'model_bounded_release', 'model_arm_get',
             'model_arm_set', 'model_held_get', 'model_armable_get', 'model_release_get',
             'model_release_set', 'model_retain_terminal']
    functions = '\n\n'.join(boundary.body(source, name) for name in names)
    structure = re.search(r'struct USBWs73Test \{.*?\n\};', source, re.S).group()
    # Audit actual call ordering, including disposal of an armed/held timer.
    transfer = boundary.body(source, 'transfer')
    assert transfer.index('if (model_retain_terminal(s))') < transfer.index('s->in_flight = false;')
    dispose = boundary.body(source, 'unrealize')
    assert 'timer_free(s->model_hold_timer); s->model_hold_timer = NULL;' in dispose
    assert 's->model_hold_once = s->model_held = false;' in dispose
    assert all(f'&s->{field}, OBJ_PROP_FLAG_READ' in source for field in [
        'model_holds','model_releases','model_bounded_releases','model_drops'])
    (args.output/'actual-functions.h').write_text(structure+'\n'+functions+'\n')
    fixture = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void Object;
typedef struct { int unused; } USBDevice;
typedef struct { int unused; } USBPacket;
typedef struct { int64_t deadline; unsigned mods, dels; } QEMUTimer;
typedef struct { int calls; } Error;
typedef struct USBWs73Test USBWs73Test;
#define USB_WS73_TEST(obj) ((USBWs73Test *)(obj))
#define USB_TOKEN_IN 1
#define QEMU_CLOCK_REALTIME 0
#define G_CHECKSUM_SHA256 0
#define g_assert assert
static unsigned wakes, digests, acks;
static void error_setg(Error **errp, const char *format, ...) { assert(errp && *errp); (*errp)->calls++; }
static void timer_del(QEMUTimer *t) { assert(t); t->dels++; }
static void timer_mod(QEMUTimer *t, int64_t deadline) { assert(t); t->deadline=deadline; t->mods++; }
static int64_t qemu_clock_get_ms(int clock) { assert(clock==QEMU_CLOCK_REALTIME); return 100; }
static void *usb_ep_get(USBDevice *dev, int token, int nr) { assert(dev && token==USB_TOKEN_IN && nr==1); return dev; }
static void usb_wakeup(void *ep, int stream) { assert(ep && !stream); wakes++; }
static char *g_compute_checksum_for_data(int type, const uint8_t *data, unsigned size) {
    assert(type==G_CHECKSUM_SHA256 && data && size==156); digests++;
    char *p=malloc(8); assert(p); memcpy(p,"fixture",8); return p;
}
#define g_free free
static unsigned le16(const uint8_t *p) { return p[0] | p[1]<<8; }
static void bsle_ack(USBWs73Test *s, unsigned message) { assert(s && message==1); acks++; }
static void bsle_close_ack(USBWs73Test *s) { assert(s); acks++; }
#include "actual-functions.h"
static USBWs73Test controller(QEMUTimer *timer) {
    USBWs73Test s={.opened=true,.runtime_discovery=true,.model_hold_timer=timer}; return s;
}
static void terminal(USBWs73Test *s) {
    assert(!s->count); s->count=1; s->packet_size[0]=156;
    s->packets[0][96]=0xa2; s->packets[0][97]=2; s->packets[0][101]=2;
    s->packets[0][102]=0x0c; s->in_flight=true;
}
int main(void) {
    QEMUTimer t={0}; Error e={0}, *err=&e; USBWs73Test s=controller(&t), peer=controller(&t);
    assert(model_armable_get(&s,&err) && !model_arm_get(&s,&err) && !model_held_get(&s,&err));
    model_release_set(&s,false,&err); assert(!wakes && !e.calls);
    model_release_set(&s,true,&err); assert(e.calls==1 && !model_release_get(&s,&err));
    terminal(&s); uint8_t bytes[384]; memcpy(bytes,s.packets[0],384);
    assert(!model_retain_terminal(&s) && !s.model_holds && !digests);
    model_arm_set(&s,true,&err); assert(e.calls==2 && !s.model_hold_once);
    s.count=0;s.in_flight=false;s.opened=false; model_arm_set(&s,true,&err); assert(e.calls==3);
    s.opened=true;s.runtime_discovery=false; model_arm_set(&s,true,&err); assert(e.calls==4);
    s.runtime_discovery=true;model_arm_set(&s,true,&err);assert(s.model_hold_once);
    model_arm_set(&s,true,&err); assert(e.calls==5);
    terminal(&s);
    /* Status, credit grant, malformed length and non-DLI frames cannot consume. */
    s.packets[0][97]=1; assert(!model_retain_terminal(&s) && s.model_hold_once);
    s.packets[0][97]=2;s.packets[0][101]=s.packets[0][102]=0;
    assert(!model_retain_terminal(&s) && s.model_hold_once);
    s.packets[0][101]=2;s.packets[0][102]=0x0c;s.packet_size[0]=104;
    assert(!model_retain_terminal(&s));s.packet_size[0]=156;s.packets[0][96]=0;
    assert(!model_retain_terminal(&s));s.packets[0][96]=0xa2;
    assert(model_retain_terminal(&s) && s.model_held && !s.model_hold_once && s.model_holds==1);
    assert(t.deadline==2100 && t.mods==1 && digests==1 && s.in_flight && s.count==1 && !s.head);
    assert(!memcmp(bytes,s.packets[0],384));
    assert(model_retain_terminal(&s) && digests==1 && t.mods==1);
    model_release_set(&peer,true,&err); assert(e.calls==6 && s.model_held);
    model_arm_set(&s,false,&err);assert(s.model_held);
    model_release_set(&s,true,&err);assert(!s.model_held && s.model_releases==1 && !s.model_bounded_releases);
    assert(s.in_flight && s.count==1 && !s.head && !memcmp(bytes,s.packets[0],384) && wakes==1);
    model_bounded_release(&s);assert(wakes==1);
    reset((USBDevice *)&s);assert(s.model_holds==1 && !s.model_drops && !s.model_held && !s.model_hold_once);
    s.opened=true;model_arm_set(&s,true,&err);assert(e.calls==7 && !s.model_hold_once && !model_armable_get(&s,&err));
    USBWs73Test bounded=controller(&t);model_arm_set(&bounded,true,&err);terminal(&bounded);
    assert(model_retain_terminal(&bounded));model_bounded_release(&bounded);
    assert(bounded.model_bounded_releases==1 && !bounded.model_releases && !bounded.model_held);
    USBWs73Test dropped=controller(&t);model_arm_set(&dropped,true,&err);terminal(&dropped);
    assert(model_retain_terminal(&dropped));reset((USBDevice *)&dropped);
    assert(dropped.model_drops==1 && dropped.model_holds==1 && !dropped.count && !dropped.model_held);
    model_bounded_release(&dropped);assert(wakes==2 && digests==5 && !acks);
    puts("MODEL_TERMINAL_HOLD_DEPENDENCY_BOUNDARIES_PASS");
}
'''
    (args.output/'check.c').write_text(fixture)
    command=[args.cc,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',
             str(args.output/'check.c'),'-o',str(args.output/'check')]
    if args.sanitize:command[1:1]=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
    subprocess.run(command,check=True);subprocess.run([str((args.output/'check').resolve())],check=True)
    (args.output/'manifest.json').write_text(json.dumps(dict(
        status='PASS_ACTUAL_MODEL_HOLD_WITH_COUNTED_DEPENDENCIES',
        scope=__doc__,actual_functions=names,source_sha256=hashlib.sha256(source.encode()).hexdigest(),
        queue_bytes_preserved=True,budget_survives_reset=True,physical_acceptance=False,
        qemu_scheduler_acceptance=False,managed_partial_live_acceptance=False,
        compile_command=command),indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,default=Path(__file__).with_name('usb-ws73-test.c'))
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default='cc');parser.add_argument('--sanitize',action='store_true')
    check(parser.parse_args())
