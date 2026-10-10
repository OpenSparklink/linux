#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual QEMU USB-host guard bodies against counted libusb mocks.

This checks the opt-outs and default behavior, not physical USB passthrough.
Also verify patch application, idempotence and refusal of partial source drift.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time


def body(source, name):
    match = re.search(r'static (?:void|int) '+name+r'\([^;]*?\)\n\{', source)
    if not match:
        raise ValueError('missing production function: '+name)
    depth = 1
    end = match.end()
    while depth:
        if end == len(source):
            raise ValueError('unterminated production function')
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[match.start():end]


def qmp_properties(args):
    """Paused TCG object probe. Never match a host USB device or run a guest."""
    spec=importlib.util.spec_from_file_location('ws73_boundary_lab',
                                              Path(__file__).resolve().parents[1]/'ws73-lab.py')
    lab=importlib.util.module_from_spec(spec);spec.loader.exec_module(lab)
    with tempfile.TemporaryDirectory(prefix='ws73-boundary-qmp-') as temporary:
        socket=Path(temporary)/'qmp.sock'
        command=[str(args.qemu),'-machine','q35,accel=tcg','-m','64M',
                 '-display','none','-serial','none','-monitor','none','-nodefaults',
                 '-nic','none','-device','qemu-xhci,id=boundary_xhci',
                 '-S','-qmp',f'unix:{socket},server=on,wait=off']
        (args.output/'qmp-command.json').write_text(json.dumps(command,indent=2)+'\n')
        monitor=None
        with (args.output/'qemu-stderr.log').open('w') as log:
            process=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT)
            try:
                deadline=time.monotonic()+10
                while not socket.exists():
                    if process.poll() is not None or time.monotonic()>=deadline:
                        raise ValueError('paused QMP probe did not start')
                    time.sleep(0.05)
                monitor=lab.Qmp(socket,args.output/'qmp.jsonl')
                base={'driver':'usb-host','bus':'boundary_xhci.0','hostbus':255,
                      'hostport':'255','vendorid':0xffff,'productid':0x3733}
                monitor.execute('device_add',dict(base,id='defaults',port='1'))
                for name in ['kernel-driver-detach','host-reset','guest-reset']:
                    assert monitor.execute('qom-get',{'path':'/machine/peripheral/defaults','property':name}) is True
                monitor.execute('device_add',dict(base,id='guarded',port='2',
                                **{'kernel-driver-detach':False,'host-reset':False,
                                   'guest-reset':False,'guest-resets-all':False}))
                for name in ['kernel-driver-detach','host-reset','guest-reset','guest-resets-all','attached']:
                    assert monitor.execute('qom-get',{'path':'/machine/peripheral/guarded','property':name}) is False
                for name,value in [('hostbus',255),('hostport','255'),('vendorid',0xffff),('productid',0x3733)]:
                    assert monitor.execute('qom-get',{'path':'/machine/peripheral/guarded','property':name})==value
                path='/machine/peripheral/guarded'
                assert monitor.execute('qom-get',{'path':path,'property':'host-retry'}) is False
                monitor.execute('qom-set',{'path':path,'property':'host-retry','value':True})
                assert monitor.execute('qom-get',{'path':path,'property':'host-retry'}) is False
                assert monitor.execute('qom-get',{'path':path,'property':'attached'}) is False
                assert monitor.execute('query-status')['status']=='prelaunch'
                monitor.execute('quit');assert process.wait(timeout=10)==0
            finally:
                if monitor:monitor.close()
                if process.poll() is None:process.kill();process.wait()
    print('USB_HOST_QMP: PASS defaults preserved, opt-outs/filter values read back; paused/unattached, not physical USB')


def check(args):
    args.output.mkdir(parents=True, exist_ok=False)
    host = args.source/'hw/usb/host-libusb.c'
    source = host.read_text()
    maximum = re.search(r'^#define USB_MAX_INTERFACES (\d+)$',
                        (args.source/'include/hw/usb.h').read_text(), re.M)[1]
    functions = ['usb_host_detach_kernel', 'usb_host_attach_kernel', 'usb_host_lifecycle_reset',
                 'usb_host_set_retry', 'usb_host_port_reenumerated']
    production = '\n\n'.join(body(source, name) for name in functions)
    (args.output/'production.h').write_text(production+'\n')
    for name in ['usb_host_open','usb_host_close','usb_host_exit_notifier']:
        function = body(source, name)
        assert 'usb_host_lifecycle_reset(s);' in function
        assert 'libusb_reset_device(' not in function
    assert source.count('libusb_reset_device(s->dh)') == 2  # helper and guest-reset path
    assert source.count('usb_host_lifecycle_reset(s);') == 3
    guest = body(source, 'usb_host_handle_reset')
    assert '!s->allow_one_guest_reset && !s->allow_all_guest_resets' in guest
    autoscan = body(source, 'usb_host_auto_check')
    assert autoscan.count('usb_host_port_reenumerated(s, devs[i])') == 1
    assert autoscan.index('usb_host_port_reenumerated(s, devs[i])') < autoscan.index('if (s->dh != NULL)')
    assert re.search(r'if \(usb_host_port_reenumerated\(s, devs\[i\]\)\) \{\s+usb_host_nodev\(s\);\s+continue;', autoscan)
    code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
struct libusb_config_descriptor { int unused; };
typedef struct { int bus, address; } libusb_device;
typedef struct {
    bool allow_kernel_driver_detach, allow_host_reset;
    bool attached, needs_autoscan;
    int errcount;
    void *dh, *dev;
    int bus_num, addr;
    struct { int bus_num; const char *port; } match;
    struct { bool detached; } ifs[USB_MAX_INTERFACES];
} USBHostDevice;
typedef USBHostDevice Object;
typedef struct { int unused; } Error;
#define USB_HOST_DEVICE(obj) (obj)
#define USB_DEVICE(obj) (obj)
static int errors;
static void error_setg(Error **errp, const char *message)
{ (void)errp; assert(strstr(message, "auto-scan filter")); errors++; }
static int queries, active, detached, attached, resets, freed, config_error;
static struct libusb_config_descriptor config;
static int libusb_get_active_config_descriptor(void *dev, struct libusb_config_descriptor **out)
{ (void)dev; queries++; *out=&config; return config_error; }
static int libusb_kernel_driver_active(void *handle, int interface)
{ (void)handle; (void)interface; active++; return 1; }
static int libusb_detach_kernel_driver(void *handle, int interface)
{ (void)handle; (void)interface; detached++; return 0; }
static int libusb_attach_kernel_driver(void *handle, int interface)
{ (void)handle; (void)interface; attached++; return 0; }
static int libusb_reset_device(void *handle)
{ (void)handle; resets++; return 0; }
static int libusb_get_bus_number(libusb_device *dev) { return dev->bus; }
static int libusb_get_device_address(libusb_device *dev) { return dev->address; }
static void libusb_free_config_descriptor(struct libusb_config_descriptor *out)
{ assert(out==&config); freed++; }
static void usb_host_libusb_error(const char *name, int result)
{ (void)name; (void)result; }
#define trace_usb_host_detach_kernel(...) ((void)0)
#define trace_usb_host_attach_kernel(...) ((void)0)
#include "production.h"
int main(void)
{
    USBHostDevice s={0};
    usb_host_detach_kernel(&s);
    assert(!queries && !active && !detached && !freed);
    for (int i=0;i<USB_MAX_INTERFACES;i++) s.ifs[i].detached=true;
    usb_host_attach_kernel(&s);
    assert(!queries && !attached && !freed);
    usb_host_lifecycle_reset(&s);
    assert(!resets);
    s.allow_kernel_driver_detach=true;
    usb_host_detach_kernel(&s);
    assert(queries==1 && active==USB_MAX_INTERFACES && detached==USB_MAX_INTERFACES && freed==1);
    usb_host_attach_kernel(&s);
    assert(queries==2 && attached==USB_MAX_INTERFACES && freed==2);
    for (int i=0;i<USB_MAX_INTERFACES;i++) assert(!s.ifs[i].detached);
    s.allow_host_reset=true;
    usb_host_lifecycle_reset(&s);
    assert(resets==1);
    config_error=-1;
    usb_host_detach_kernel(&s);
    assert(queries==3 && active==USB_MAX_INTERFACES && detached==USB_MAX_INTERFACES && freed==2);
    puts("USB_HOST_GUARDS: PASS 7 cases (production bodies, counted mocks, no physical USB)");
    USBHostDevice retry={.errcount=3}, other={.errcount=3};
    usb_host_set_retry(&retry, false, NULL);
    assert(retry.errcount==3 && errors==0);
    retry.dh=&retry;
    usb_host_set_retry(&retry, true, NULL);
    assert(retry.errcount==3 && errors==0 && retry.dh==&retry);
    retry.dh=NULL; retry.attached=true;
    usb_host_set_retry(&retry, true, NULL);
    assert(retry.errcount==3 && errors==0 && retry.attached);
    retry.attached=false;
    usb_host_set_retry(&retry, true, NULL);
    assert(retry.errcount==3 && errors==1);
    retry.needs_autoscan=true;
    usb_host_set_retry(&retry, true, NULL);
    assert(retry.errcount==0 && other.errcount==3 && errors==1);
    assert(queries==3 && active==USB_MAX_INTERFACES && detached==USB_MAX_INTERFACES &&
           attached==USB_MAX_INTERFACES && resets==1 && freed==2);
    puts("USB_HOST_RETRY: PASS 5 cases (production setter, no libusb calls, no physical USB)");
    libusb_device original={.bus=1,.address=84}, replacement={.bus=1,.address=88};
    USBHostDevice fixed={.dh=&original,.bus_num=1,.addr=84,.match={.bus_num=1,.port="2.1.1"}};
    assert(!usb_host_port_reenumerated(&fixed,&original));
    assert(usb_host_port_reenumerated(&fixed,&replacement));
    fixed.dh=NULL; assert(!usb_host_port_reenumerated(&fixed,&replacement)); fixed.dh=&original;
    fixed.match.port=NULL; assert(!usb_host_port_reenumerated(&fixed,&replacement)); fixed.match.port="2.1.1";
    fixed.match.bus_num=0; assert(!usb_host_port_reenumerated(&fixed,&replacement)); fixed.match.bus_num=1;
    replacement.bus=2; assert(!usb_host_port_reenumerated(&fixed,&replacement));
    assert(queries==3 && active==USB_MAX_INTERFACES && detached==USB_MAX_INTERFACES &&
           attached==USB_MAX_INTERFACES && resets==1 && freed==2);
    puts("USB_HOST_REENUMERATION: PASS 6 cases (production predicate/autoscan routing, no physical USB)");
}
'''
    (args.output/'guards.c').write_text('#define USB_MAX_INTERFACES '+maximum+'\n'+code)
    with (args.output/'compile.log').open('w') as log:
        subprocess.run([args.cc,'-std=c11','-Wall','-Wextra','-Werror',
                        str(args.output/'guards.c'),'-o',str(args.output/'guards')],
                       stdout=log,stderr=subprocess.STDOUT,check=True)
    result=subprocess.check_output([str(args.output/'guards')],text=True)
    (args.output/'guards.log').write_text(result)
    print(result,end='')
    patches = [Path(__file__).with_name(name).resolve() for name in
               ['usb-host-boundary.patch','usb-host-retry.patch','usb-host-reenumeration.patch']]
    apply = Path(__file__).with_name('apply-usb-host-boundary.py').resolve()
    tree=args.output/'patch-tree';(tree/'hw/usb').mkdir(parents=True)
    copy=tree/'hw/usb/host-libusb.c';shutil.copy2(host,copy)
    commands=[['patch','--batch','--fuzz=0','--reverse','-p1','-i',str(patch)]
              for patch in reversed(patches)]
    commands += [['python3',str(apply),str(tree.resolve())]] * 2
    with (args.output/'patch.log').open('w') as log:
        for command in commands:
            subprocess.run(command,cwd=tree,stdout=log,stderr=subprocess.STDOUT,check=True)
        assert copy.read_bytes()==host.read_bytes()
        copy.write_text(copy.read_text().replace('allow_host_reset, true','unexpected_drift, true',1))
        drift=copy.read_bytes()
        denied=subprocess.run(commands[-1],cwd=tree,stdout=log,stderr=subprocess.STDOUT)
        assert denied.returncode!=0 and copy.read_bytes()==drift
        copy.write_text(host.read_text().replace('s->addr != libusb_get_device_address(dev)',
                                                's->addr == libusb_get_device_address(dev)',1))
        drift=copy.read_bytes()
        denied=subprocess.run(commands[-1],cwd=tree,stdout=log,stderr=subprocess.STDOUT)
        assert denied.returncode!=0 and copy.read_bytes()==drift
        copy.write_text(host.read_text().replace('object_property_add_bool(obj, "host-retry"',
                                                'object_property_add_bool(obj, "unexpected-retry"',1))
        drift=copy.read_bytes()
        denied=subprocess.run(commands[-1],cwd=tree,stdout=log,stderr=subprocess.STDOUT)
        assert denied.returncode!=0 and copy.read_bytes()==drift
    summary={'status':'PASS','scope':'QEMU production guard bodies and patch mechanics only',
             'physical_acceptance':False,'guard_cases':7,'retry_cases':5,'reenumeration_cases':6,
             'host_lifecycle_sites':3,'patch_cases':5,
             'source_sha256':hashlib.sha256(host.read_bytes()).hexdigest(),
             'production_sha256':hashlib.sha256(production.encode()).hexdigest()}
    if args.qemu:
        qmp_properties(args)
        summary['qmp']='PASS paused/unattached property probe; not physical passthrough'
        summary['qemu_sha256']=hashlib.sha256(args.qemu.read_bytes()).hexdigest()
    (args.output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print('USB_HOST_PATCH: PASS fresh, idempotent, boundary/retry source-drift refusal')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--cc',default='gcc')
    parser.add_argument('--qemu',type=Path,help='also probe actual patched binary in a paused TCG VM with no host device match')
    args=parser.parse_args();args.source=args.source.resolve();args.output=args.output.resolve()
    if args.qemu:args.qemu=args.qemu.resolve()
    check(args)
