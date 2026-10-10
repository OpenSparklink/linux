#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual autoscan/close bodies with counted USB-list/transport mocks.

Proves recursive-scan and enumeration-error isolation, not physical USB/RF.
The source bodies and their digest are preserved beside the generated test.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


def check(args):
    args.output.mkdir(parents=True, exist_ok=False)
    spec=importlib.util.spec_from_file_location('boundary', Path(__file__).with_name('check-usb-host-boundary.py'))
    boundary=importlib.util.module_from_spec(spec);spec.loader.exec_module(boundary)
    source=args.source.read_text()
    names=['usb_host_close','usb_host_port_reenumerated','usb_host_auto_check']
    production='\n\n'.join(boundary.body(source,n) for n in names)
    assert 'usb_host_auto_check(NULL);' in boundary.body(source,'usb_host_close')
    (args.output/'production.h').write_text(production+'\n')
    before=r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define LIBUSB_CLASS_HUB 9
#define QTAILQ_FOREACH(s, list, ignored) for ((s)=(list)->head; (s); (s)=(s)->next)
typedef struct { int bus, address, vendor, product; const char *port; } libusb_device;
struct libusb_device_descriptor { int bDeviceClass, idVendor, idProduct; };
struct USBAutoFilter { int bus_num, addr, vendor_id, product_id; const char *port; };
struct USBHostDevice {
    struct USBHostDevice *next;
    struct USBAutoFilter match;
    bool attached;
    unsigned seen, errcount;
    int bus_num, addr, hostfd;
    void *dh, *dev;
};
typedef struct USBHostDevice USBHostDevice;
typedef struct USBHostDevice USBDevice;
#define USB_DEVICE(s) (s)
struct { USBHostDevice *head; } hostdevs;
static void *ctx, *usb_vmstate, *usb_auto_timer;
static bool usb_auto_check_running;
static USBHostDevice a,b;
static libusb_device da={1,7,65535,14131,"2.1.1"}, db={1,8,65535,14131,"2.1.3"};
static libusb_device *devices[3];
static unsigned closed[2], opened[2], scans, schedules, requests, releases;
static int list_mode, init_error;
static bool vm_running=true;
static void usb_host_auto_check(void *unused);
static int usb_host_init(void) { return init_error; }
static bool runstate_is_running(void) { return vm_running; }
static int libusb_get_device_list(void *unused, libusb_device ***out) {
    (void)unused; scans++; *out=devices;
    if (list_mode<0) { *out=NULL; return -1; }
    if (list_mode==1) { devices[0]=&db; devices[1]=NULL; return 1; }
    devices[0]=&da; devices[1]=&db; devices[2]=NULL; return 2;
}
static int libusb_get_device_descriptor(libusb_device *d, struct libusb_device_descriptor *desc) {
    *desc=(struct libusb_device_descriptor){0,d->vendor,d->product};return 0;
}
static int libusb_get_bus_number(libusb_device *d) { return d->bus; }
static int libusb_get_device_address(libusb_device *d) { return d->address; }
static void usb_host_get_port(libusb_device *d, char *p, size_t size) { snprintf(p,size,"%s",d->port); }
static void usb_host_nodev(USBHostDevice *s) { (void)s; requests++; }
static int usb_host_open(USBHostDevice *s, libusb_device *d, int ignored) {
    (void)ignored;s->dh=d;s->dev=d;s->attached=true;opened[s==&b]++;return 0;
}
static void libusb_free_device_list(libusb_device **list, int refs) { (void)list;(void)refs; }
static void trace_usb_host_close(int bus, int address) { assert(bus==1);closed[address==8]++; }
static void usb_host_abort_xfers(USBHostDevice *s) { (void)s; }
static void usb_host_iso_free_all(USBHostDevice *s) { (void)s; }
static void usb_device_detach(USBDevice *s) { s->attached=false; }
static void usb_host_release_interfaces(USBHostDevice *s) { (void)s; releases++; }
static void usb_host_lifecycle_reset(USBHostDevice *s) { (void)s; }
static void usb_host_attach_kernel(USBHostDevice *s) { (void)s; }
static void libusb_close(void *h) { assert(h); }
static void close(int fd) { (void)fd; }
static void usb_host_vm_state(void *p, bool running, int state) { (void)p;(void)running;(void)state; }
static void *qemu_add_vm_change_state_handler(void (*f)(void *,bool,int),void *p) { (void)f;(void)p;return &usb_vmstate; }
#define QEMU_CLOCK_REALTIME 1
static void *timer_new_ms(int clock,void (*f)(void *),void *p) { (void)clock;(void)f;(void)p;return &usb_auto_timer; }
static void trace_usb_host_auto_scan_enabled(void) {}
static int64_t qemu_clock_get_ms(int clock) { (void)clock;return 100; }
static void timer_mod(void *t,int64_t deadline) { assert(t && deadline==2100);schedules++; }
'''
    after=r'''
static void reset_case(int mode) {
    a=(USBHostDevice){.match={1,0,65535,14131,"2.1.1"},.attached=true,.dh=&da,.dev=&da,.bus_num=1,.addr=7,.hostfd=-1};
    b=(USBHostDevice){.match={1,0,65535,14131,"2.1.3"},.attached=true,.dh=&db,.dev=&db,.bus_num=1,.addr=8,.hostfd=-1};
    a.next=&b;hostdevs.head=&a;list_mode=mode;init_error=0;vm_running=true;
    memset(closed,0,sizeof(closed));memset(opened,0,sizeof(opened));
    scans=schedules=requests=releases=0;usb_auto_check_running=false;
}
int main(void) {
    unsigned failures=0;
    reset_case(1);usb_host_auto_check(NULL);
    bool isolated=closed[0]==1 && !a.dh && !a.attached && !closed[1] && b.dh==&db && b.attached && !opened[1] && scans==1 && schedules==1;
    printf("AUTOSCAN_ABSENT: isolated=%d closed=%u/%u scans=%u reopened_survivor=%u\n",isolated,closed[0],closed[1],scans,opened[1]);
    failures+=!isolated;
    reset_case(-1);usb_host_auto_check(NULL);
    bool retained=!closed[0] && !closed[1] && a.dh==&da && b.dh==&db && scans==1 && schedules==1;
    printf("AUTOSCAN_LIST_ERROR: retained=%d closed=%u/%u scans=%u\n",retained,closed[0],closed[1],scans);
    failures+=!retained;
    reset_case(0);usb_host_auto_check(NULL);
    bool healthy=!closed[0] && !closed[1] && !opened[0] && !opened[1] && !a.seen && !b.seen && scans==1 && schedules==1;
    printf("AUTOSCAN_HEALTHY: retained=%d\n",healthy);failures+=!healthy;
    reset_case(0);init_error=-1;usb_host_auto_check(NULL);init_error=0;usb_host_auto_check(NULL);
    bool unlocked=!usb_auto_check_running && scans==1 && schedules==1 && !closed[0] && !closed[1];
    printf("AUTOSCAN_INIT_FAILURE: unlocked=%d\n",unlocked);failures+=!unlocked;
    reset_case(0);vm_running=false;usb_host_auto_check(NULL);vm_running=true;usb_host_auto_check(NULL);
    bool paused=scans==1 && schedules==2 && !closed[0] && !closed[1];
    printf("AUTOSCAN_PAUSED: retained=%d\n",paused);failures+=!paused;
    reset_case(0);a.errcount=2;b.errcount=3;da.address=9;usb_host_auto_check(NULL);da.address=7;
    bool reenumerated=requests==1 && !closed[0] && !closed[1] && a.errcount==2 && b.errcount==3;
    printf("AUTOSCAN_REENUMERATION: owner_request_only=%d\n",reenumerated);failures+=!reenumerated;
    return failures?1:0;
}
'''
    code=args.output/'autoscan-test.c';code.write_text(before+'\n#include "production.h"\n'+after)
    binary=args.output/'autoscan-test'
    with (args.output/'build.log').open('wb') as log:
        subprocess.run([args.cc,'-std=gnu11','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter',str(code),'-o',str(binary)],stdout=log,stderr=subprocess.STDOUT,check=True)
    result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=5)
    (args.output/'run.log').write_text(result.stdout+result.stderr)
    summary=dict(status='PASS' if result.returncode==0 else 'FAIL',exit=result.returncode,
                 scope='actual QEMU autoscan/close bodies, mocked USB list; no physical acceptance',
                 cases=6,source_sha256=hashlib.sha256(args.source.read_bytes()).hexdigest(),
                 production_sha256=hashlib.sha256(production.encode()).hexdigest())
    (args.output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(result.stdout,end='')
    return result.returncode

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default='gcc')
    raise SystemExit(check(parser.parse_args()))
