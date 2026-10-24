/* SPDX-License-Identifier: GPL-2.0-only */
/* Actual probe/disconnect/PM; transport/Core/USB dependencies controlled. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
typedef uint16_t u16;typedef uint64_t u64;typedef int pm_message_t;
struct sparklink_native_identity{u16 id;u64 generation;};
struct sle_usb_dev{u16 id;u64 generation;};
struct usb_interface{void*data;};struct usb_device_id{int unused;};
#define SPARKLINK_BACKEND_USB 1
#define SPARKLINK_NATIVE_STANDARD_DLI 0
static struct sle_usb_dev context;
static int reserve_ret,create_ret,init_ret,install_ret,refs,events[16],count,cases;
static void event(int e){assert(count<16);events[count++]=e;}
static int sparklink_backend_reserve(int bus,int profile,struct sparklink_native_identity*out){assert(bus==1&&profile==0);event(1);if(!reserve_ret)*out=(struct sparklink_native_identity){3,99};return reserve_ret;}
static int sle_usb_dev_register(int id,void*i,u64 gen,struct sle_usb_dev**out){assert(id==3&&gen==99&&i);event(2);if(!create_ret){context=(struct sle_usb_dev){3,99};*out=&context;refs=1;}return create_ret;}
static int sle_usb_dev_init_controller(struct sle_usb_dev*c){assert(c==&context&&refs==1);event(3);return init_ret;}
static int sle_usb_dev_install_provider(struct sle_usb_dev*c){assert(c==&context&&refs==1);event(4);return install_ret;}
static void sparklink_native_unregister(u16 id,u64 gen){assert(id==3&&gen==99);assert(refs==1||create_ret);event(5);}
static void sle_usb_dev_unregister(struct sle_usb_dev*c){assert(c==&context&&refs==1);event(6);}
static void sle_usb_dev_put(struct sle_usb_dev*c){assert(c==&context&&refs==1);event(7);refs--;}
static void sparklink_backend_cancel(u16 id,u64 gen){assert(id==3&&gen==99);event(8);}
static void usb_set_intfdata(struct usb_interface*i,void*p){i->data=p;}
static void*usb_get_intfdata(struct usb_interface*i){return i->data;}
/* @@PROBE@@ */
/* @@DISCONNECT@@ */
/* @@SUSPEND@@ */
static void reset(void){reserve_ret=create_ret=init_ret=install_ret=refs=count=0;}
static void order(const int*expected,int n){assert(count==n&&!memcmp(events,expected,(size_t)n*sizeof(int)));}
int main(void){struct usb_interface intf={0};
 reset();reserve_ret=-ENOMEM;assert(sparklink_standard_usb_probe(&intf,NULL)==-ENOMEM&&!refs&&!intf.data);order((int[]){1},1);cases++;
 reset();create_ret=-ENODEV;assert(sparklink_standard_usb_probe(&intf,NULL)==-ENODEV&&!refs&&!intf.data);order((int[]){1,2,5,8},4);cases++;
 reset();init_ret=-ETIMEDOUT;assert(sparklink_standard_usb_probe(&intf,NULL)==-ETIMEDOUT&&!refs&&!intf.data);order((int[]){1,2,3,5,6,7,8},7);cases++;
 reset();install_ret=-EIO;assert(sparklink_standard_usb_probe(&intf,NULL)==-EIO&&!refs&&!intf.data);order((int[]){1,2,3,4,5,6,7,8},8);cases++;
 reset();install_ret=1;assert(sparklink_standard_usb_probe(&intf,NULL)==-EIO&&!refs&&!intf.data);order((int[]){1,2,3,4,5,6,7,8},8);cases++;
 reset();assert(!sparklink_standard_usb_probe(&intf,NULL)&&refs==1&&intf.data==&context);order((int[]){1,2,3,4},4);assert(sparklink_standard_usb_suspend(&intf,0)==-EBUSY&&refs==1&&count==4);sparklink_standard_usb_disconnect(&intf);order((int[]){1,2,3,4,5,6,7},7);assert(!refs&&!intf.data);sparklink_standard_usb_disconnect(&intf);assert(count==7);cases++;
 printf("{\"status\":\"ACTUAL_STANDARD_DRIVER_BINDING_PASS\",\"cases\":%d}\n",cases);return 0;}
