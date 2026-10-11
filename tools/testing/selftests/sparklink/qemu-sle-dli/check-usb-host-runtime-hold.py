#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual QEMU hold/callback/abort/cancel code with counted dependencies.

Timers, transport, digest and USB combining are fixtures, not live USB,
QEMU scheduler, cancellation protocol or hardware recovery qualification.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


def check(args):
    args.output.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('check-usb-host-boundary.py'))
    boundary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundary)
    source = args.source.read_text()
    close = boundary.body(source, 'usb_host_close')
    assert close.index('s->test_runtime_hold_once = false;') < close.index('usb_host_abort_xfers(s);')
    assert close.index('usb_host_abort_xfers(s);') < close.index('libusb_close(s->dh);')
    names = ['usb_host_test_clear_hold', 'usb_host_test_release_hold', 'usb_host_test_hold_timeout',
             'usb_host_req_complete_data', 'usb_host_req_abort', 'usb_host_cancel_packet',
             'usb_host_get_test_runtime_hold', 'usb_host_get_test_runtime_held',
             'usb_host_set_test_runtime_hold', 'usb_host_get_test_runtime_release',
             'usb_host_set_test_runtime_release', 'usb_host_set_test_runtime_in_error']
    production = '\n\n'.join(boundary.body(source, name) for name in names)
    (args.output/'production.h').write_text(production+'\n')
    mocks = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define LIBUSB_CALL
#define LIBUSB_TRANSFER_COMPLETED 0
#define LIBUSB_TRANSFER_NO_DEVICE 5
#define LIBUSB_TRANSFER_TYPE_BULK 2
#define USB_RET_IOERROR -5
#define USB_RET_NODEV -1
#define USB_PACKET_ASYNC 1
#define QEMU_CLOCK_REALTIME 0
#define G_CHECKSUM_SHA256 0
typedef struct { int nr; } USBEndpoint;
typedef struct { int status, actual_length, state; USBEndpoint *ep; void *combined; unsigned char data[16]; } USBPacket;
typedef struct QEMUTimer { void (*cb)(void *); void *opaque; int64_t deadline; bool live; } QEMUTimer;
typedef struct USBHostRequest USBHostRequest;
typedef struct USBHostDevice {
    bool attached, allow_host_reset, allow_kernel_driver_detach;
    bool allow_one_guest_reset, allow_all_guest_resets, test_enum_reset_once;
    bool test_runtime_in_error_once, test_runtime_hold_once;
    USBHostRequest *test_runtime_held;
    QEMUTimer *test_runtime_hold_timer;
    uint64_t test_runtime_in_errors, test_runtime_holds, test_runtime_releases;
    uint64_t test_runtime_bounded_releases, test_runtime_hold_drops;
    void *dh;
    struct { unsigned idVendor, idProduct; } ddesc;
    int bus_num, addr;
} USBHostDevice;
typedef USBHostDevice Object;
typedef USBHostDevice USBDevice;
typedef struct { int calls; } Error;
#define USB_HOST_DEVICE(s) (s)
#define USB_DEVICE(s) (s)
struct libusb_transfer { void *user_data; int status, type, endpoint, actual_length; };
struct USBHostRequest { USBHostDevice *host; USBPacket *p; bool in; unsigned char *buffer; struct libusb_transfer *xfer; };
static const int status_map[] = {0,-1,-2,-3,-4,-1};
static unsigned copied, completed, combined_completed, freed, nodev, timers, timer_frees, canceled, allocated, digests;
static bool combining;
static USBHostRequest *current;
static USBEndpoint endpoint={.nr=1};
static void error_setg(Error **errp, const char *format, ...) { (*errp)->calls++; }
static void error_report(const char *format, ...) {}
static void digest_free(char **value) { free(*value); }
#define g_autofree __attribute__((cleanup(digest_free)))
static char *g_compute_checksum_for_data(int algo, const unsigned char *data, int len) {
    assert(len==4 && !memcmp(data,"\1\2\3\4",4)); digests++;
    char *value=malloc(8); assert(value); memcpy(value,"fixture",8); return value;
}
static QEMUTimer *timer_new_ms(int clock, void (*cb)(void *), void *opaque) {
    assert(clock==QEMU_CLOCK_REALTIME); QEMUTimer *t=calloc(1,sizeof(*t)); assert(t);
    *t=(QEMUTimer){.cb=cb,.opaque=opaque,.live=true}; timers++; return t;
}
static void timer_mod(QEMUTimer *t, int64_t deadline) { assert(t && t->live);t->deadline=deadline; }
static void timer_del(QEMUTimer *t) { assert(t && t->live); }
static void timer_free(QEMUTimer *t) { assert(t && t->live);t->live=false;timer_frees++;free(t); }
static int64_t qemu_clock_get_ms(int clock) { assert(clock==QEMU_CLOCK_REALTIME);return 100; }
static void usb_packet_copy(USBPacket *p, void *data, int size) {
    assert(size>=0 && p->actual_length+size<=16);
    memcpy(p->data+p->actual_length,data,size);copied+=size;p->actual_length+=size;
}
static void trace_usb_host_req_complete(int b, int a, USBPacket *p, int status, int len) {}
static void trace_usb_host_req_canceled(int b, int a, USBPacket *p) {}
static bool usb_host_use_combining(void *ep) { return combining; }
static void usb_combined_input_packet_complete(USBHostDevice *s, USBPacket *p) { completed++;combined_completed++; }
static void usb_packet_complete(USBHostDevice *s, USBPacket *p) { completed++; }
static void usb_generic_async_ctrl_complete(USBHostDevice *s, USBPacket *p) { completed++; }
static void usb_host_req_free(USBHostRequest *r) {
    assert(current==r); current=NULL;freed++;free(r->xfer);free(r->buffer);free(r);
}
static void usb_host_nodev(USBHostDevice *s) { nodev++; }
static int libusb_cancel_transfer(struct libusb_transfer *x) { canceled++;return 0; }
static USBHostRequest *usb_host_req_find(USBHostDevice *s, USBPacket *p) {
    return current && current->host==s && current->p==p ? current : NULL;
}
static void usb_host_cancel_packet(USBDevice *s, USBPacket *p);
static void usb_combined_packet_cancel(USBDevice *s, USBPacket *p) {
    /* first packet cancellation re-enters after combining identity removal */
    p->combined=NULL;usb_host_cancel_packet(s,p);
}
static void LIBUSB_CALL usb_host_req_complete_data(struct libusb_transfer *xfer);
#include "production.h"
static USBHostRequest *make(USBHostDevice *s, USBPacket *p) {
    assert(!current);USBHostRequest *r=calloc(1,sizeof(*r));assert(r);
    r->buffer=malloc(4);r->xfer=calloc(1,sizeof(*r->xfer));assert(r->buffer&&r->xfer);
    memcpy(r->buffer,"\1\2\3\4",4);r->host=s;r->p=p;r->in=true;p->ep=&endpoint;
    *r->xfer=(struct libusb_transfer){.user_data=r,.status=0,.type=2,.endpoint=0x81,.actual_length=4};
    current=r;allocated++;return r;
}
static void arm(USBHostDevice *s, Error **e) {
    usb_host_set_test_runtime_hold(s,true,e);assert(usb_host_get_test_runtime_hold(s,e));
}
int main(void) {
    Error error={0};Error *e=&error;
    USBHostDevice s={.attached=true,.dh=(void *)1,.ddesc={0xffff,0x3733}};
    USBPacket p={.state=USB_PACKET_ASYNC};USBHostRequest *r=make(&s,&p);
    /* Default disabled: unchanged payload/completion/free and no timer/digest. */
    usb_host_req_complete_data(r->xfer);
    assert(copied==4&&completed==1&&freed==1&&!timers&&!digests);
    assert(!usb_host_get_test_runtime_hold(&s,&e)&&!usb_host_get_test_runtime_held(&s,&e));
    assert(!usb_host_get_test_runtime_release(&s,&e));
    usb_host_set_test_runtime_release(&s,true,&e);assert(error.calls==1);
    /* Ignored callbacks do not consume the pulse or retain an object. */
    for (unsigned i=0;i<6;i++) {
        arm(&s,&e);p=(USBPacket){.state=USB_PACKET_ASYNC};r=make(&s,&p);
        if(i==0)r->xfer->endpoint=0x82;
        if(i==1)r->xfer->type=3;
        if(i==2)r->xfer->status=1;
        if(i==3)r->xfer->actual_length=0;
        if(i==4)r->in=false;
        if(i==5)r->p=NULL;
        usb_host_req_complete_data(r->xfer);
        assert(s.test_runtime_hold_once&&!s.test_runtime_held&&!timers);
        usb_host_set_test_runtime_hold(&s,false,&e);
    }
    /* Explicit and bounded release: retain original allocation/payload; clear
     * timer identity before exactly one ordinary callback/free. */
    for(unsigned i=0;i<3;i++) {
        unsigned c=copied,f=freed,d=completed;
        arm(&s,&e);p=(USBPacket){.state=USB_PACKET_ASYNC};r=make(&s,&p);
        usb_host_req_complete_data(r->xfer);
        assert(s.test_runtime_held==r&&!s.test_runtime_hold_once&&s.test_runtime_hold_timer->deadline==2100);
        assert(copied==c&&freed==f&&completed==d&&p.actual_length==0);
        USBHostDevice other={0};int errors=error.calls;
        usb_host_set_test_runtime_release(&other,true,&e);
        assert(error.calls==errors+1 && s.test_runtime_held==r && !other.test_runtime_releases);
        usb_host_set_test_runtime_hold(&s,true,&e);usb_host_set_test_runtime_in_error(&s,true,&e);
        assert(!s.test_runtime_hold_once&&!s.test_runtime_in_error_once);
        usb_host_set_test_runtime_hold(&s,false,&e);assert(s.test_runtime_held==r);
        combining=(i==2);
        if(i==1) { QEMUTimer *t=s.test_runtime_hold_timer;void(*cb)(void*)=t->cb;void *v=t->opaque;cb(v); }
        else usb_host_set_test_runtime_release(&s,true,&e);
        combining=false;
        assert(!s.test_runtime_held&&!s.test_runtime_hold_timer&&!current);
        assert(copied==c+4&&freed==f+1&&completed==d+1&&p.status==0&&p.actual_length==4);
        assert(!memcmp(p.data,"\1\2\3\4",4));
        usb_host_test_hold_timeout(&s);assert(freed==f+1); /* no stale replay */
    }
    assert(s.test_runtime_releases==3&&s.test_runtime_bounded_releases==1&&combined_completed==1);
    /* Cancel, live abort, already-dead abort and first combined cancellation:
     * drop the already-completed xfer without libusb cancellation/callback. */
    for(unsigned i=0;i<4;i++) {
        unsigned c=copied,f=freed,d=completed,lc=canceled;
        arm(&s,&e);p=(USBPacket){.state=USB_PACKET_ASYNC};r=make(&s,&p);usb_host_req_complete_data(r->xfer);
        if(i==0)usb_host_cancel_packet(&s,&p);
        if(i==1)usb_host_req_abort(r);
        if(i==2){p.state=0;usb_host_req_abort(r);}
        if(i==3){p.combined=(void *)1;usb_host_cancel_packet(&s,&p);}
        assert(!s.test_runtime_held&&!s.test_runtime_hold_timer&&!current&&freed==f+1&&copied==c&&canceled==lc);
        assert(completed==d+(i==1));usb_host_test_hold_timeout(&s);assert(freed==f+1&&copied==c);
    }
    assert(s.test_runtime_hold_drops==4);
    /* Unheld cancellation still belongs to libusb callback lifetime. */
    p=(USBPacket){.state=USB_PACKET_ASYNC};r=make(&s,&p);unsigned f=freed,lc=canceled;
    usb_host_cancel_packet(&s,&p);assert(r->p==NULL&&canceled==lc+1&&freed==f);
    usb_host_req_complete_data(r->xfer);assert(freed==f+1);
    /* Wrong/missing device and every reset/detach opt-in reject arming. */
    s.ddesc.idVendor=1;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);s.ddesc.idVendor=0xffff;
    s.ddesc.idProduct=1;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);s.ddesc.idProduct=0x3733;
    s.dh=NULL;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);s.dh=(void *)1;
    s.attached=false;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);s.attached=true;
    bool *opts[]={&s.allow_host_reset,&s.allow_kernel_driver_detach,&s.allow_one_guest_reset,&s.allow_all_guest_resets,&s.test_enum_reset_once};
    for(unsigned i=0;i<5;i++){*opts[i]=true;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);*opts[i]=false;}
    s.test_runtime_in_error_once=true;usb_host_set_test_runtime_hold(&s,true,&e);assert(!s.test_runtime_hold_once);s.test_runtime_in_error_once=false;
    arm(&s,&e);usb_host_set_test_runtime_in_error(&s,true,&e);
    assert(s.test_runtime_hold_once&&!s.test_runtime_in_error_once);
    usb_host_set_test_runtime_hold(&s,false,&e);
    assert(allocated==freed&&timers==timer_frees&&digests==s.test_runtime_holds&&!nodev);
    puts("RUNTIME_HOLD_DEPENDENCY_BOUNDARIES_PASS: default/guards/qualified pulse/explicit+bounded delivery/cancel+abort+combined cleanup");
}
'''
    (args.output/'check.c').write_text(mocks)
    command = [args.cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               str(args.output/'check.c'), '-o', str(args.output/'check')]
    if args.sanitize:
        command[1:1] = ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
    subprocess.run(command, check=True)
    subprocess.run([str((args.output/'check').resolve())], check=True)
    record = {'status':'PASS_ACTUAL_QEMU_HOLD_WITH_DEPENDENCY_FIXTURES',
              'scope':__doc__, 'live_usb_acceptance':False, 'live_on_wire_cancel_acceptance':False,
              'qemu_scheduler_acceptance':False, 'actual_close_routing_audit':True,
              'source_sha256':hashlib.sha256(source.encode()).hexdigest(),
              'actual_functions':names, 'production_sha256':hashlib.sha256(production.encode()).hexdigest(),
              'compile_command':command}
    (args.output/'manifest.json').write_text(json.dumps(record,indent=2)+'\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--cc',default='cc')
    parser.add_argument('--sanitize',action='store_true')
    check(parser.parse_args())
