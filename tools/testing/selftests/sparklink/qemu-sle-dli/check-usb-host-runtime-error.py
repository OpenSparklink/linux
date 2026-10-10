#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual patched libusb completion/setter with counted transport mocks.

No host USB access. These are injection-boundary tests, not hardware recovery.
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
    names = ['usb_host_get_test_runtime_in_error', 'usb_host_set_test_runtime_in_error',
             'usb_host_req_complete_data']
    production = '\n\n'.join(boundary.body(source, name) for name in names)
    (args.output / 'production.h').write_text(production + '\n')
    mocks = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <stddef.h>
#define LIBUSB_CALL
#define LIBUSB_TRANSFER_COMPLETED 0
#define LIBUSB_TRANSFER_NO_DEVICE 5
#define LIBUSB_TRANSFER_TYPE_BULK 2
#define USB_RET_IOERROR -5
typedef struct { int status, actual_length; void *ep; } USBPacket;
typedef struct USBHostDevice {
    bool attached, allow_host_reset, allow_kernel_driver_detach;
    bool allow_one_guest_reset, allow_all_guest_resets;
    bool test_runtime_in_error_once;
    uint64_t test_runtime_in_errors;
    void *dh;
    struct { unsigned idVendor, idProduct; } ddesc;
    int bus_num, addr;
} USBHostDevice;
typedef USBHostDevice Object;
typedef struct { int calls; } Error;
#define USB_HOST_DEVICE(s) (s)
#define USB_DEVICE(s) (s)
typedef struct { USBHostDevice *host; USBPacket *p; bool in; unsigned char *buffer; } USBHostRequest;
struct libusb_transfer { void *user_data; int status, type, endpoint, actual_length; };
static const int status_map[] = {0,-1,-2,-3,-4,-1};
static unsigned copied, completed, freed, nodev, injected;
static void error_setg(Error **errp, const char *format, ...) { (*errp)->calls++; }
static void error_report(const char *format, ...) { injected++; }
static void usb_packet_copy(USBPacket *p, void *data, int size) { copied+=size; p->actual_length+=size; }
static void trace_usb_host_req_complete(int b, int a, USBPacket *p, int status, int len) {}
static bool usb_host_use_combining(void *ep) { return false; }
static void usb_combined_input_packet_complete(USBHostDevice *s, USBPacket *p) { completed++; }
static void usb_packet_complete(USBHostDevice *s, USBPacket *p) { completed++; }
static void usb_host_req_free(USBHostRequest *r) { freed++; }
static void usb_host_nodev(USBHostDevice *s) { nodev++; }
#include "production.h"
int main(void) {
    Error error={0}; Error *err=&error;
    USBHostDevice s={.attached=true,.dh=(void *)1,.ddesc={0xffff,0x3733}};
    unsigned char buffer[128]={0};
    USBPacket packet={0};
    USBHostRequest request={.host=&s,.p=&packet,.in=true,.buffer=buffer};
    struct libusb_transfer x={.user_data=&request,.status=0,.type=2,.endpoint=0x81,.actual_length=128};
    /* Default disabled: ordinary successful data is delivered unchanged. */
    usb_host_req_complete_data(&x);
    assert(copied==128 && completed==1 && freed==1 && injected==0 && packet.status==0);
    assert(!usb_host_get_test_runtime_in_error(&s,&err));
    /* Explicit pulse: only next nonempty successful bulk IN81 is discarded. */
    packet=(USBPacket){0};
    usb_host_set_test_runtime_in_error(&s,true,&err);
    assert(s.test_runtime_in_error_once && error.calls==0);
    x.endpoint=0x82; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    x.endpoint=0x81; x.actual_length=0; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    x.actual_length=128; x.type=3; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    x.type=2; x.status=1; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    x.status=0; request.in=false; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    request.in=true; request.p=NULL; usb_host_req_complete_data(&x);
    assert(s.test_runtime_in_error_once && injected==0);
    request.p=&packet; packet=(USBPacket){0};
    unsigned before=copied;
    usb_host_req_complete_data(&x);
    assert(!s.test_runtime_in_error_once && s.test_runtime_in_errors==1 && injected==1);
    assert(packet.status==USB_RET_IOERROR && packet.actual_length==0 && copied==before && nodev==0);
    packet=(USBPacket){0}; usb_host_req_complete_data(&x);
    assert(packet.status==0 && packet.actual_length==128 && s.test_runtime_in_errors==1);
    /* Arming guards: wrong device, absent transport, reset/detach enabled. */
    s.ddesc.idVendor=1; usb_host_set_test_runtime_in_error(&s,true,&err); assert(!s.test_runtime_in_error_once); s.ddesc.idVendor=0xffff;
    s.ddesc.idProduct=1; usb_host_set_test_runtime_in_error(&s,true,&err); assert(!s.test_runtime_in_error_once); s.ddesc.idProduct=0x3733;
    s.dh=NULL; usb_host_set_test_runtime_in_error(&s,true,&err); assert(!s.test_runtime_in_error_once); s.dh=(void *)1;
    s.attached=false; usb_host_set_test_runtime_in_error(&s,true,&err); assert(!s.test_runtime_in_error_once); s.attached=true;
    bool *options[]={&s.allow_host_reset,&s.allow_kernel_driver_detach,&s.allow_one_guest_reset,&s.allow_all_guest_resets};
    for (unsigned i=0;i<4;i++) { *options[i]=true; usb_host_set_test_runtime_in_error(&s,true,&err); assert(!s.test_runtime_in_error_once); *options[i]=false; }
    assert(error.calls==8);
    usb_host_set_test_runtime_in_error(&s,true,&err);
    usb_host_set_test_runtime_in_error(&s,true,&err); assert(error.calls==9);
    usb_host_set_test_runtime_in_error(&s,false,&err); assert(!s.test_runtime_in_error_once && s.test_runtime_in_errors==1);
    return 0;
}
'''
    (args.output / 'check.c').write_text(mocks)
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
               str(args.output / 'check.c'), '-o', str(args.output / 'check')]
    subprocess.run(command, check=True)
    subprocess.run([str((args.output / 'check').resolve())], check=True)
    record = {'status': 'PASS_MOCKED_ACTUAL_RUNTIME_ERROR_BOUNDARY',
              'scope': 'actual callback/setter with transport mocks; no USB/hardware acceptance',
              'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
              'production_sha256': hashlib.sha256(production.encode()).hexdigest(),
              'compile_command': command}
    (args.output / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    print(record['status'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    check(parser.parse_args())
