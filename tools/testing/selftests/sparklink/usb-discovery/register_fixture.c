// SPDX-License-Identifier: GPL-2.0-only
// Actual generic register/unregister with allocation/descriptor/URB dependencies.
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int spinlock_t;
#define spin_lock_init(x) (*(x)=0)
struct usb_device { int unused; };
struct usb_endpoint_descriptor {u8 bEndpointAddress,bInterval;u16 maxp;};
struct usb_host_interface {int unused;};
struct usb_interface {struct usb_host_interface *cur_altsetting;struct usb_device *device;};
struct sle_urb_ctx {int registration_id;u64 registration_generation;int size;};
/* @@STRUCT@@ */
/* @@DEFINES@@ */
static struct sle_usb_dev usb_dev_table[SLE_USB_MAX_DEVS];
static struct usb_device device;
static struct usb_host_interface alt;
static struct usb_interface intf={.cur_altsetting=&alt,.device=&device};
static struct usb_endpoint_descriptor endpoints[3];
static int find_ret,find_calls,allocs,live,fail_alloc,kills,frees,cases;
static struct usb_device *interface_to_usbdev(struct usb_interface *i) {assert(i==&intf);return i->device;}
static int usb_endpoint_maxp(const struct usb_endpoint_descriptor *e) {return e->maxp;}
static int usb_find_common_endpoints(struct usb_host_interface *a,struct usb_endpoint_descriptor **in,
 struct usb_endpoint_descriptor **out,struct usb_endpoint_descriptor **intr,void *other) {
 assert(a==&alt && other==NULL);find_calls++;
 if(find_ret)return find_ret;
 *in=&endpoints[0];*out=&endpoints[1];*intr=&endpoints[2];return 0;
}
static struct sle_urb_ctx *sle_usb_alloc_ctx(int size) {
 allocs++;if(allocs==fail_alloc)return NULL;
 assert(size>0);struct sle_urb_ctx *p=calloc(1,sizeof(*p));assert(p);p->size=size;live++;return p;
}
static void sle_usb_kill_ctx(struct sle_urb_ctx *p) {assert(p);kills++;}
static void sle_usb_free_ctx(struct sle_urb_ctx *p) {assert(p);live--;frees++;free(p);}
/* @@REGISTER@@ */
/* @@UNREGISTER@@ */
static void reset(void) {
 assert(live==0);memset(usb_dev_table,0,sizeof(usb_dev_table));
 // Stale inactive metadata and a distinct peer prove atomic failure/reuse.
 usb_dev_table[0].fw_version=0xaabbccdd;usb_dev_table[0].command_credits=3;
 usb_dev_table[0].suspended=true;memset(usb_dev_table[0].mac_addr,0x69,6);
 usb_dev_table[1].active=true;usb_dev_table[1].fw_version=0x8899aabb;
 endpoints[0]=(struct usb_endpoint_descriptor){.bEndpointAddress=0x85,.maxp=512};
 endpoints[1]=(struct usb_endpoint_descriptor){.bEndpointAddress=0x03,.maxp=512};
 endpoints[2]=(struct usb_endpoint_descriptor){.bEndpointAddress=0x89,.maxp=32,.bInterval=7};
 find_ret=find_calls=allocs=fail_alloc=kills=frees=0;
}
static void rejected(int id,void *ptr,u64 gen,int expected) {
 struct sle_usb_dev before[SLE_USB_MAX_DEVS];memcpy(before,usb_dev_table,sizeof(before));
 assert(sle_usb_dev_register(id,ptr,gen)==expected);
 assert(memcmp(before,usb_dev_table,sizeof(before))==0 && live==0);cases++;
}
static void accepted(u64 generation) {
 struct sle_usb_dev peer=usb_dev_table[1];
 assert(sle_usb_dev_register(0,&intf,generation)==0);
 struct sle_usb_dev *d=&usb_dev_table[0];
 assert(d->active && !d->suspended && d->intf==&intf && d->udev==&device);
 assert(d->ep_bulk_in==0x85 && d->ep_bulk_out==0x03 && d->ep_intr_in==0x89);
 assert(d->ep_bulk_in_size==512 && d->ep_intr_in_size==32 && d->ep_intr_in_interval==7);
 assert(d->evt_urb->size==32 && d->rx_urb->size==512);
 assert(d->evt_urb->registration_id==0 && d->rx_urb->registration_id==0);
 assert(d->evt_urb->registration_generation==generation && d->rx_urb->registration_generation==generation);
 assert(d->fw_version==0 && d->command_credits==0 && memcmp(d->mac_addr,"\0\0\0\0\0\0",6)==0);
 assert(memcmp(&peer,&usb_dev_table[1],sizeof(peer))==0 && live==2 && kills==0);
 // Register allocates but never submits. Production unregister joins/frees.
 sle_usb_dev_unregister(0);assert(!d->active && !d->intf && !d->udev && !d->evt_urb && !d->rx_urb);
 assert(live==0 && kills==2 && frees==2);sle_usb_dev_unregister(0);assert(kills==2 && frees==2);
 assert(memcmp(&peer,&usb_dev_table[1],sizeof(peer))==0);cases++;
}
int main(void) {
 reset();rejected(-1,&intf,1,-EINVAL);assert(find_calls==0);
 reset();rejected(SLE_USB_MAX_DEVS,&intf,1,-EINVAL);assert(find_calls==0);
 reset();rejected(0,NULL,1,-EINVAL);assert(find_calls==0);
 reset();rejected(0,&intf,0,-EINVAL);assert(find_calls==0);
 reset();rejected(1,&intf,1,-EBUSY);assert(find_calls==0);
 int errors[]={-ENXIO,-ENODEV,-EINVAL};
 for(unsigned i=0;i<sizeof(errors)/sizeof(errors[0]);i++){reset();find_ret=errors[i];rejected(0,&intf,1,errors[i]);assert(find_calls==1 && allocs==0);}
 for(int i=0;i<3;i++){reset();endpoints[i].maxp=0;rejected(0,&intf,1,-EPROTO);assert(allocs==0);}
 reset();endpoints[2].bInterval=0;rejected(0,&intf,1,-EPROTO);assert(allocs==0);
 for(int n=1;n<=2;n++){reset();fail_alloc=n;rejected(0,&intf,1,-ENOMEM);assert(allocs==n && frees==n-1 && kills==0);}
 reset();accepted(1);reset();accepted(UINT64_MAX);
 reset();fail_alloc=2;rejected(0,&intf,1,-ENOMEM);fail_alloc=0;frees=0;accepted(2);
 printf("{\"status\":\"REGISTER_SOURCE_BOUNDARIES_PASS\",\"c_cases\":%d}\n",cases);return 0;
}
