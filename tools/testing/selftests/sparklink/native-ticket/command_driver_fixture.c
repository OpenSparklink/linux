// SPDX-License-Identifier: GPL-2.0-only
/* Actual driver bodies and wire codec; USB/locks/time are explicit dependencies.
 * No hardware, controller completion or peer delivery qualification. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "wire.h"
#include "dli.h"
typedef uint8_t u8;
typedef uint16_t u16;
#define GFP_KERNEL 1
#define GFP_ATOMIC 2
#define READ_ONCE(x) (x)
#define msecs_to_jiffies(x) (x)
/* @@DEFINES@@ */
struct mutex { bool held; };
struct completion { bool done; };
struct urb { void *context; int status; unsigned int actual_length, length;
    void (*callback)(struct urb *); bool queued, idle; const u8 *data; };
struct sparklink_native_command_ticket { int deny; };
struct ws73_usb { struct mutex tx_lock; bool stopping, broken, streaming;
    unsigned int tx_sequence; unsigned char tx[32768]; void *udev; unsigned int bulk_out;
    u16 native_id; uint64_t native_generation; struct {unsigned int acb_length;} info; };
static bool allocation_fails, no_completion, inside_commit;
static int submit_error, completion_error, material_error;
static bool revoke_after_copy;
static unsigned int material_calls;
static void memzero_explicit(void *p,size_t n){volatile unsigned char *q=p;while(n--)*q++=0;}
static int sparklink_native_command_materialize(struct sparklink_native_command_ticket *t,u16 id,uint64_t generation,u8 *params,size_t length){
 assert(id==1&&generation==2&&!inside_commit&&(length==20||length==21));material_calls++;
 if(material_error)return material_error;
 /* Explicit cryptographic dependency fixture, not a real candidate or RF evidence. */
 memset(params+2,0x5a,16);if(revoke_after_copy)t->deny=-EACCES;return 0;
}
static unsigned int shortened, submit_calls, kill_calls, callback_calls, failures;
static unsigned int deadline=3000;
static void mutex_lock(struct mutex *m) { assert(!m->held);m->held=true; }
static void mutex_unlock(struct mutex *m) { assert(m->held);m->held=false; }
static void init_completion(struct completion *c) { c->done=false; }
static void complete(struct completion *c) { assert(!c->done);c->done=true;callback_calls++; }
static struct urb *usb_alloc_urb(int packets,int flags) {
    assert(!inside_commit && packets==0 && flags==GFP_KERNEL);
    return allocation_fails ? NULL : calloc(1,sizeof(struct urb));
}
static unsigned int usb_sndbulkpipe(void *device,unsigned int endpoint) { (void)device;return endpoint; }
static void usb_fill_bulk_urb(struct urb *u,void *device,unsigned int pipe,void *bytes,
                             unsigned int length,void (*callback)(struct urb *),void *context) {
    (void)device;(void)pipe;u->data=bytes;u->length=length;u->callback=callback;u->context=context;u->idle=true;
}
static int usb_submit_urb(struct urb *u,int flags) {
    assert(inside_commit && flags==GFP_ATOMIC && u->idle);submit_calls++;
    if ((u->data[69]==3 || u->data[69]==5) && u->data[70]==0x1c) {
        for(unsigned int n=75;n<91;n++)assert(u->data[n]==0x5a);
        assert(u->data[91]==1 && u->data[92]==1);
    }
    if (submit_error)return submit_error;
    u->queued=true;u->idle=false;
    if (!no_completion) {
        u->status=completion_error;u->actual_length=u->length-shortened;u->idle=true;u->callback(u);
    }
    return 0;
}
static int sparklink_native_command_commit(struct sparklink_native_command_ticket *t, u16 id, uint64_t generation,
                                    int (*submit)(void *),void *context) {
    assert(id==1 && generation==2);assert(!inside_commit);if(t->deny)return t->deny;
    inside_commit=true;int result=submit(context);inside_commit=false;return result;
}
static unsigned long wait_for_completion_timeout(struct completion *c,unsigned long timeout) {
    assert(!inside_commit && timeout>0);return c->done ? 1:0;
}
static void usb_kill_urb(struct urb *u) {
    assert(!inside_commit && u->queued && !u->idle);kill_calls++;
    u->status=-ENOENT;u->actual_length=0;u->idle=true;u->callback(u);
}
static void usb_free_urb(struct urb *u) { assert(!inside_commit && u->idle);free(u); }
static unsigned int ws73_io_timeout(struct ws73_usb *ws,unsigned int requested) { (void)ws;return deadline<requested?deadline:requested; }
static void ws73_async_failure(struct ws73_usb *ws,int error) { (void)ws;assert(error<0);failures++; }
static void sparklink_native_snoop_tx(u16 id,uint64_t generation,u16 opcode,const u8 *data,size_t length,int status) {(void)opcode;(void)data;(void)length;(void)status;assert(id==1 && generation==2);}
/* @@DRIVER@@ */
static void reset(void) {
    allocation_fails=no_completion=inside_commit=false;
    submit_error=completion_error=material_error=0;material_calls=0;revoke_after_copy=false;shortened=0;submit_calls=kill_calls=callback_calls=failures=0;deadline=3000;
}
static int exercise(int deny) {
    struct ws73_usb ws={.streaming=true,.tx_sequence=4,.native_id=1,.native_generation=2,.info={.acb_length=254}};
    struct sparklink_native_command_ticket ticket={.deny=deny};
    int result=ws73_native_command(&ws,&ticket,0x0404,NULL,0);
    assert(!ws.tx_lock.held && !inside_commit);
    assert(ws.tx_sequence==(submit_calls && !submit_error ? 5U:4U));
    return result;
}
static int installation(unsigned int opcode,int deny) {
 struct ws73_usb ws={.streaming=true,.tx_sequence=4,.native_id=1,.native_generation=2};
 struct sparklink_native_command_ticket t={.deny=deny};u8 params[21]={0};
 params[18]=params[19]=1;size_t size=opcode==0x1c03?21:20;
 int ret=ws73_native_command(&ws,&t,opcode,params,size);
 for(size_t n=0;n<sizeof(ws.tx);n++)assert(ws.tx[n]==0);
 for(size_t n=2;n<18;n++)assert(params[n]==0);
 assert(!ws.tx_lock.held&&!inside_commit);return ret;
}
static void installations(void){
 for(unsigned int opcode=0x1c03;opcode<=0x1c05;opcode+=2){
  reset();assert(installation(opcode,0)==0&&material_calls==1&&submit_calls==1);
  reset();material_error=-ESTALE;assert(installation(opcode,0)==-ESTALE&&material_calls==1&&submit_calls==0);
  reset();revoke_after_copy=true;assert(installation(opcode,0)==-EACCES&&material_calls==1&&submit_calls==0);
  reset();allocation_fails=true;assert(installation(opcode,0)==-ENOMEM&&submit_calls==0);
  reset();no_completion=true;assert(installation(opcode,0)==-ETIMEDOUT&&kill_calls==1);
 }
}

int main(void) {
    reset();assert(exercise(0)==0);assert(submit_calls==1 && callback_calls==1 && kill_calls==0);
    reset();allocation_fails=true;assert(exercise(0)==-ENOMEM);assert(submit_calls==0 && failures==0);
    reset();deadline=0;assert(exercise(0)==-ETIMEDOUT);assert(submit_calls==0 && failures==0);
    for(unsigned int i=0;i<4;i++) {
        const int denied[]={-EAGAIN,-ESTALE,-EACCES,-ECANCELED};reset();assert(exercise(denied[i])==denied[i]);
        assert(submit_calls==0 && callback_calls==0 && failures==0);
    }
    reset();submit_error=-ENODEV;assert(exercise(0)==-ENODEV);assert(callback_calls==0 && kill_calls==0 && failures==0);
    reset();completion_error=-EPIPE;assert(exercise(0)==-EPIPE);assert(callback_calls==1 && failures==1);
    reset();shortened=1;assert(exercise(0)==-EREMOTEIO);assert(callback_calls==1 && failures==1);
    reset();no_completion=true;assert(exercise(0)==-ETIMEDOUT);assert(kill_calls==1 && callback_calls==1 && failures==1);
    installations();
    puts("WS73_ACTUAL_COMMAND_TICKET_DRIVER_FAULTS_PASS cases=21; dependency fixtures, not RF");
    return 0;
}
