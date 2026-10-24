/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <linux/sparklink_backend.h>
#define READ_ONCE(x) (x)
#define dev_warn(dev,fmt,...) do { (void)(dev); (void)(fmt); } while(0)
struct mutex { int held; };
static void mutex_lock(struct mutex *m){assert(!m->held);m->held=1;}
static void mutex_unlock(struct mutex *m){assert(m->held);m->held=0;}
struct usb_interface {int dev;};
struct ws73_usb {struct mutex backend_lock;struct sparklink_native_identity reservation;bool backend_reserved,stopping;struct usb_interface *intf;};
static unsigned int reserve_calls,query_calls,update_calls,cancel_calls;
static int query_error,reserve_error;static u64 next_generation;
static struct sparklink_native_identity server;
static struct sparklink_backend_pending status;
int sparklink_backend_reserve(u32 bus,u32 profile,struct sparklink_native_identity *out){assert(bus==1&&profile==1);reserve_calls++;if(reserve_error)return reserve_error;server.id=3;server.generation=++next_generation;*out=server;query_error=0;memset(&status,0,sizeof(status));return 0;}
int sparklink_backend_pending_query(u16 id,u64 gen,struct sparklink_backend_pending *out){query_calls++;if(query_error)return query_error;if(id!=server.id||gen!=server.generation)return -ENODEV;*out=status;return 0;}
int sparklink_backend_pending_update(u16 id,u64 gen,u32 phase,int error){assert(id==server.id&&gen==server.generation);update_calls++;status.phase=phase;status.error=error;return 0;}
void sparklink_backend_cancel(u16 id,u64 gen){assert(id==server.id&&gen==server.generation);cancel_calls++;}
/* @@HELPERS@@ */
int main(void){
 struct usb_interface intf={};struct ws73_usb ws={.intf=&intf};unsigned int tests=0;
 assert(ws73_reserve_backend(&ws)==0&&ws.backend_reserved&&ws.reservation.generation==1);tests++;
 assert(ws73_reserve_backend(&ws)==0&&reserve_calls==1);tests++;
 ws73_pending_status(&ws,10,-110);assert(update_calls==1&&status.phase==10&&status.error==-110);tests++;
 query_error=-EBUSY;assert(ws73_reserve_backend(&ws)==-EBUSY&&reserve_calls==1&&ws.backend_reserved);tests++;
 query_error=-ENODEV;assert(ws73_reserve_backend(&ws)==0&&reserve_calls==2&&ws.reservation.generation==2);tests++;
 ws.stopping=true;ws73_pending_status(&ws,0,0);assert(update_calls==1);tests++;
 ws73_cancel_backend(&ws);assert(!ws.backend_reserved&&cancel_calls==1);ws73_cancel_backend(&ws);assert(cancel_calls==1);tests++;
 ws.stopping=false;ws73_pending_status(&ws,12,-5);assert(reserve_calls==2&&update_calls==1&&!ws.backend_reserved);ws.stopping=true;
 assert(ws73_reserve_backend(&ws)==-ENODEV&&reserve_calls==2);tests++;
 ws.stopping=false;reserve_error=-ENOSPC;assert(ws73_reserve_backend(&ws)==-ENOSPC&&!ws.backend_reserved);tests++;
 reserve_error=0;assert(ws73_reserve_backend(&ws)==0);ws73_pending_status(&ws,11,0);assert(status.phase==11&&status.error==0);ws73_cancel_backend(&ws);assert(cancel_calls==2);tests++;
 assert(!ws.backend_lock.held);printf("ACTUAL_WS73_PENDING_HELPERS_PASS cases=%u\n",tests);return 0;
}
