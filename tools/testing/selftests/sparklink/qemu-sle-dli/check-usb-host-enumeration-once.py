#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual QEMU reset budget functions with counted transport dependencies.

No live USB, enumeration scheduler or migration qualification is claimed.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


def check(args):
    args.output.mkdir(parents=True, exist_ok=False)
    spec=importlib.util.spec_from_file_location('boundary',Path(__file__).with_name('check-usb-host-boundary.py'))
    boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)
    source=args.source.read_text()
    names=['usb_host_enum_reset_mode_valid','usb_host_handle_reset','usb_host_get_test_enum_reset_used','usb_host_post_load']
    production='\n\n'.join(boundary.body(source,name) for name in names)
    (args.output/'production.h').write_text(production+'\n')
    for name in ['usb_host_open','usb_host_close','usb_host_nodev','usb_host_auto_check']:
        assert 'test_enum_reset_used' not in boundary.body(source,name),name
    assert 'VMSTATE_BOOL_V(test_enum_reset_used, USBHostDevice, 2)' in source
    assert 'test_enum_reset_once, false)' in source
    assert 'usb_host_get_test_enum_reset_used, NULL)' in source
    assert '!usb_host_enum_reset_mode_valid(s)' in boundary.body(source,'usb_host_realize')
    for name in ['usb_host_set_test_runtime_hold','usb_host_set_test_runtime_in_error']:
        assert 's->test_enum_reset_once ||' in boundary.body(source,name)
    fixture=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
typedef struct USBHostDevice USBHostDevice;
typedef struct { USBHostDevice *owner; int addr; } USBDevice;
typedef USBDevice Object;
typedef struct { int unused; } Error;
struct USBHostDevice {
    bool allow_host_reset,allow_kernel_driver_detach,allow_one_guest_reset,allow_all_guest_resets;
    bool test_enum_reset_once,test_enum_reset_used,bh_postld_pending;
    struct { unsigned vendor_id,product_id,bus_num; const char *port; } match;
    void *dh,*bh_postld; int bus_num,addr,mem_reentrancy_guard;
};
#define USB_HOST_DEVICE(v) ((v)->owner)
#define DEVICE(v) (v)
static unsigned resets,disconnects,schedules;
static int reset_result;
static void trace_usb_host_reset(int bus,int address) { assert(bus==1&&address>0); }
static int libusb_reset_device(void *dh) { assert(dh);resets++;return reset_result; }
static void usb_host_nodev(USBHostDevice *s) { disconnects++;s->dh=NULL; }
static void usb_host_post_load_bh(void *opaque) { (void)opaque; }
static void *qemu_bh_new_guarded(void (*callback)(void *),void *opaque,int *guard) {
    assert(callback&&opaque&&guard);return (void *)3;
}
static void qemu_bh_schedule(void *bh) { assert(bh);schedules++; }
#include "production.h"
static USBHostDevice qualified(void) {
    return (USBHostDevice){.dh=(void *)1,.bus_num=1,.addr=113,
        .match={.vendor_id=0xffff,.product_id=0x3733,.bus_num=1,.port="2.1.4"}};
}
int main(void) {
    USBHostDevice s=qualified(),peer=qualified();USBDevice u={.owner=&s};
    assert(usb_host_enum_reset_mode_valid(&s));
    /* Every required owner boundary, wrong identity and absent port reject. */
    bool *opts[]={&s.allow_host_reset,&s.allow_kernel_driver_detach,&s.allow_one_guest_reset,&s.allow_all_guest_resets};
    for(unsigned i=0;i<4;i++){*opts[i]=true;assert(!usb_host_enum_reset_mode_valid(&s));*opts[i]=false;}
    s.match.vendor_id=1;assert(!usb_host_enum_reset_mode_valid(&s));s.match.vendor_id=0xffff;
    s.match.product_id=1;assert(!usb_host_enum_reset_mode_valid(&s));s.match.product_id=0x3733;
    s.match.bus_num=0;assert(!usb_host_enum_reset_mode_valid(&s));s.match.bus_num=1;
    s.match.port=NULL;assert(!usb_host_enum_reset_mode_valid(&s));s.match.port="";
    assert(!usb_host_enum_reset_mode_valid(&s));s.match.port="2.1.4";
    /* Default opt-outs never reset or consume the optional budget. */
    for(unsigned i=0;i<100;i++)usb_host_handle_reset(&u);
    assert(!resets&&!s.test_enum_reset_used);
    s.test_enum_reset_once=true;
    s.dh=NULL;usb_host_handle_reset(&u);assert(!resets&&!s.test_enum_reset_used);s.dh=(void *)1;
    u.addr=7;usb_host_handle_reset(&u);assert(!resets&&!s.test_enum_reset_used);u.addr=0;
    usb_host_handle_reset(&u);assert(resets==1&&s.test_enum_reset_used);
    assert(usb_host_get_test_enum_reset_used(&u,NULL));
    /* New address/file binding on the same object cannot replenish budget. */
    s.dh=(void *)2;s.addr=117;
    for(unsigned i=0;i<100;i++)usb_host_handle_reset(&u);
    assert(resets==1&&!peer.test_enum_reset_used&&peer.dh==(void *)1);
    /* Failed reset/disconnection also consumes before another event. */
    s=qualified();s.test_enum_reset_once=true;reset_result=-1;
    usb_host_handle_reset(&u);assert(resets==2&&disconnects==1&&s.test_enum_reset_used&&!s.dh);
    s.dh=(void *)2;reset_result=0;usb_host_handle_reset(&u);assert(resets==2);
    /* Legacy opt-in semantics remain separate; this is not a new default. */
    s=qualified();s.allow_one_guest_reset=true;u.addr=0;
    usb_host_handle_reset(&u);assert(resets==2);u.addr=7;
    usb_host_handle_reset(&u);assert(resets==3);s.allow_all_guest_resets=true;u.addr=0;
    usb_host_handle_reset(&u);assert(resets==4);
    /* Actual post-load code suppresses unknown old snapshot budgets. */
    s=qualified();s.test_enum_reset_once=true;
    assert(!usb_host_post_load(&s,1)&&s.test_enum_reset_used&&s.bh_postld_pending);
    usb_host_handle_reset(&u);assert(resets==4);
    s=qualified();s.test_enum_reset_once=true;s.test_enum_reset_used=true;
    assert(!usb_host_post_load(&s,2)&&s.test_enum_reset_used);usb_host_handle_reset(&u);assert(resets==4);
    s=qualified();assert(!usb_host_post_load(&s,1)&&!s.test_enum_reset_used);
    assert(schedules==3);
    puts("ENUM_RESET_ONCE_COUNTED_DEPENDENCIES_PASS: default/guards/success/error/reattach/peer/legacy/post-load");
}
'''
    (args.output/'check.c').write_text(fixture)
    command=[args.cc,'-std=c11','-Wall','-Wextra','-Werror','-Wno-unused-parameter',str(args.output/'check.c'),'-o',str(args.output/'check')]
    subprocess.run(command,check=True)
    result=subprocess.run([str(args.output/'check')],capture_output=True,text=True,check=True)
    record=dict(status='PASS_ACTUAL_ENUM_RESET_BUDGET_WITH_COUNTED_DEPENDENCIES',
        actual_functions=names,source_sha256=hashlib.sha256(args.source.read_bytes()).hexdigest(),
        command=command,output=result.stdout,live_usb_acceptance=False,qemu_scheduler_acceptance=False,
        live_migration_acceptance=False,automatic_fault_recovery_acceptance=False,natural_fault_root_cause_closed=False)
    (args.output/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')
    print(record['status'])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--cc',default='cc');check(p.parse_args())
