// SPDX-License-Identifier: GPL-2.0-only
// Actual C allocation/get/put/retire/wrappers, dependency USB/ref/Mutex fixtures.
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sched.h>
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef atomic_uint refcount_t;
struct mutex{pthread_mutex_t lock;};
static void mutex_init(struct mutex*m){assert(!pthread_mutex_init(&m->lock,NULL));}
static atomic_int mutex_waits;
static void mutex_lock(struct mutex*m){int r=pthread_mutex_trylock(&m->lock);if(r==EBUSY){atomic_fetch_add(&mutex_waits,1);r=pthread_mutex_lock(&m->lock);}assert(!r);}
static void mutex_unlock(struct mutex*m){assert(!pthread_mutex_unlock(&m->lock));}
static void refcount_set(refcount_t*r,unsigned n){atomic_init(r,n);}
static void refcount_inc(refcount_t*r){atomic_fetch_add(r,1);}
static bool refcount_dec_and_test(refcount_t*r){return atomic_fetch_sub(r,1)==1;}
#define GFP_KERNEL 0
#define USB_TYPE_CLASS 0x20
#define USB_RECIP_DEVICE 0
#define USB_RECIP_INTERFACE 1
struct usb_device_descriptor{u8 bDeviceClass,bDeviceSubClass,bDeviceProtocol;};
struct usb_device{int refs;struct usb_device_descriptor descriptor;};
struct usb_endpoint_descriptor{u8 bEndpointAddress,bInterval;u16 maxp;};
struct usb_interface_descriptor{u8 bInterfaceNumber;};
struct usb_host_interface{struct usb_interface_descriptor desc;};
struct usb_interface{struct usb_host_interface*cur_altsetting;struct usb_device*device;int refs;};
struct sle_urb_ctx{u32 registration_id;u64 registration_generation;};
static struct usb_device device;
static struct usb_host_interface alt;
static struct usb_interface intf={&alt,&device,0};
static struct usb_endpoint_descriptor endpoints[3];
static int find_ret,find_calls,allocs,fail_alloc,frees,kills,contexts,fail_context,cases,transfers;
static struct usb_device*interface_to_usbdev(struct usb_interface*i){return i->device;}
static struct usb_device*usb_get_dev(struct usb_device*d){d->refs++;return d;}
static void usb_put_dev(struct usb_device*d){assert(d->refs>0);d->refs--;}
static struct usb_interface*usb_get_intf(struct usb_interface*i){i->refs++;return i;}
static void usb_put_intf(struct usb_interface*i){assert(i->refs>0);i->refs--;}
static void*kzalloc(size_t n,int flags){(void)flags;if(fail_context)return NULL;contexts++;return calloc(1,n);}
static void kfree(void*p){contexts--;free(p);}
static int usb_find_common_endpoints(struct usb_host_interface*a,struct usb_endpoint_descriptor**in,struct usb_endpoint_descriptor**out,struct usb_endpoint_descriptor**intr,void*x){assert(a==&alt&&!x);find_calls++;if(find_ret)return find_ret;*in=&endpoints[0];*out=&endpoints[1];*intr=&endpoints[2];return 0;}
static unsigned usb_endpoint_maxp(struct usb_endpoint_descriptor*e){return e->maxp;}
static struct sle_urb_ctx*sle_usb_alloc_ctx(int size){assert(size>0);allocs++;if(allocs==fail_alloc)return NULL;return calloc(1,sizeof(struct sle_urb_ctx));}
static void sle_usb_kill_ctx(struct sle_urb_ctx*c){assert(c);kills++;}
static void sle_usb_free_ctx(struct sle_urb_ctx*c){assert(c);frees++;free(c);}
/* @@DEFINES@@ */
/* @@STRUCT@@ */
/* @@RELEASE@@ */
/* @@GET@@ */
/* @@PUT@@ */
/* @@REGISTER@@ */
/* @@UNREGISTER@@ */
static pthread_mutex_t barrier_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_cond=PTHREAD_COND_INITIALIZER;
static struct sle_usb_dev*blocked_context;
static bool entered,release_io;
static u32 sle_usb_dev_get_fw_version_locked(struct sle_usb_dev*d){assert(d->active);
 if(d==blocked_context){pthread_mutex_lock(&barrier_lock);entered=true;pthread_cond_broadcast(&barrier_cond);while(!release_io)pthread_cond_wait(&barrier_cond,&barrier_lock);pthread_mutex_unlock(&barrier_lock);}
 return d->fw_version;
}
/* @@GET_VERSION@@ */
static void reset(void){device.descriptor=(struct usb_device_descriptor){0};alt.desc.bInterfaceNumber=2;assert(!contexts&&!device.refs&&!intf.refs);find_ret=find_calls=allocs=fail_alloc=frees=kills=fail_context=transfers=0;endpoints[0]=(struct usb_endpoint_descriptor){0x92,0,512};endpoints[1]=(struct usb_endpoint_descriptor){0x12,0,512};endpoints[2]=(struct usb_endpoint_descriptor){0x91,1,64};}
static void rejected(int id,void*i,u64 gen,int error){struct sle_usb_dev*out=NULL;assert(sle_usb_dev_register(id,i,gen,&out)==error&&!out);assert(!contexts&&!device.refs&&!intf.refs);cases++;}
static void*getter_thread(void*p){assert(sle_usb_dev_get_fw_version(p)==33);return NULL;}
static void*retire_thread(void*p){sle_usb_dev_unregister(p);return NULL;}
int main(void){
 reset();rejected(-1,&intf,1,-EINVAL);reset();rejected(SLE_USB_MAX_DEVS,&intf,1,-EINVAL);reset();rejected(0,NULL,1,-EINVAL);reset();rejected(0,&intf,0,-EINVAL);assert(sle_usb_dev_register(0,&intf,1,NULL)==-EINVAL);cases++;
 int errors[]={-ENXIO,-ENODEV,-EINVAL};for(unsigned n=0;n<3;n++){reset();find_ret=errors[n];rejected(0,&intf,1,errors[n]);assert(allocs==0);}
 for(unsigned n=0;n<3;n++){reset();endpoints[n].maxp=0;rejected(0,&intf,1,-EPROTO);}
 reset();endpoints[2].bInterval=0;rejected(0,&intf,1,-EPROTO);
 for(int n=1;n<=2;n++){reset();fail_alloc=n;rejected(0,&intf,1,-ENOMEM);assert(frees==n-1&&kills==0);}
 reset();fail_context=1;rejected(0,&intf,1,-ENOMEM);assert(frees==2);
 reset();struct sle_usb_dev*a=NULL,*b=NULL;assert(!sle_usb_dev_register(0,&intf,1,&a));assert(!sle_usb_dev_register(0,&intf,2,&b));assert(a!=b&&a->generation==1&&b->generation==2);assert(a->evt_urb->registration_generation==1&&b->rx_urb->registration_generation==2);assert(a->command_request_type==0x21&&a->command_index==2);a->fw_version=11;b->fw_version=22;
 sle_usb_dev_get(a);assert(sle_usb_dev_get_fw_version(a)==11);sle_usb_dev_unregister(a);assert(!a->active&&b->active&&kills==2);sle_usb_dev_unregister(a);assert(kills==2);sle_usb_dev_put(a);assert(sle_usb_dev_get_fw_version(a)==0&&transfers==0);assert(sle_usb_dev_get_fw_version(b)==22);assert(contexts==2&&device.refs==2&&intf.refs==2);sle_usb_dev_put(a);assert(contexts==1);sle_usb_dev_unregister(b);sle_usb_dev_put(b);assert(!contexts&&!device.refs&&!intf.refs&&kills==4&&frees==4);cases++;
 reset();device.descriptor=(struct usb_device_descriptor){0xe0,1,5};assert(!sle_usb_dev_register(0,&intf,99,&a));assert(a->command_request_type==0x20&&a->command_index==0);sle_usb_dev_put(a);cases++;
 reset();assert(!sle_usb_dev_register(0,&intf,UINT64_MAX,&a));sle_usb_dev_put(a);assert(kills==2&&frees==2&&!contexts);cases++;
 reset();assert(!sle_usb_dev_register(0,&intf,3,&a));assert(!sle_usb_dev_register(0,&intf,4,&b));a->fw_version=33;b->fw_version=44;blocked_context=a;entered=release_io=false;atomic_store(&mutex_waits,0);
 pthread_t reader,retirer;assert(!pthread_create(&reader,NULL,getter_thread,a));pthread_mutex_lock(&barrier_lock);while(!entered)pthread_cond_wait(&barrier_cond,&barrier_lock);pthread_mutex_unlock(&barrier_lock);
 assert(!pthread_create(&retirer,NULL,retire_thread,a));while(!atomic_load(&mutex_waits))sched_yield();assert(sle_usb_dev_get_fw_version(b)==44);assert(kills==0);
 pthread_mutex_lock(&barrier_lock);release_io=true;pthread_cond_broadcast(&barrier_cond);pthread_mutex_unlock(&barrier_lock);assert(!pthread_join(reader,NULL));assert(!pthread_join(retirer,NULL));assert(!a->active&&b->active);blocked_context=NULL;
 assert(sle_usb_dev_get_fw_version(a)==0);sle_usb_dev_put(a);sle_usb_dev_unregister(b);sle_usb_dev_put(b);assert(!contexts&&!device.refs&&!intf.refs);cases++;
 printf("{\"status\":\"CONTEXT_SOURCE_BOUNDARIES_PASS\",\"c_cases\":%d}\n",cases);return 0;
}
