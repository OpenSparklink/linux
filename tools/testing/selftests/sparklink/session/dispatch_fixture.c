// SPDX-License-Identifier: GPL-2.0-only
/* Actual route/submit bodies. Kernel allocations/locks/wakeups are dependencies,
 * not a running-kernel, callback-UAF or physical acceptance proof. */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sle_channel_wire.h"
#include "sle_channel_state.h"
typedef uint8_t u8;typedef uint16_t u16;typedef uint32_t u32;typedef uint64_t u64;
typedef struct {bool held;} spinlock_t;
static bool irq_disabled;
#define spin_lock_irqsave(l,f) do{(f)=irq_disabled;irq_disabled=true;assert(!(l)->held);(l)->held=true;}while(0)
#define spin_unlock_irqrestore(l,f) do{assert((l)->held);(l)->held=false;irq_disabled=(f);}while(0)
static void spin_lock(spinlock_t *l){assert(irq_disabled&&!l->held);l->held=true;}
static void spin_unlock(spinlock_t *l){assert(l->held);l->held=false;}
#define min(a,b) ((a)<(b)?(a):(b))
#define min_t(t,a,b) ((t)min(a,b))
#define GFP_KERNEL 0
#define SPARKLINK_SOCKET_USER_PI 241
/* @@LIMITS@@ */
struct sock;
struct sk_buff {struct sock *owner;struct sk_buff *next;unsigned int len,truesize;u8 data[2047];};
struct sk_buff_head {spinlock_t lock;unsigned int qlen;struct sk_buff *head,*tail;};
struct sock {unsigned int refs,wakes;int sk_rmem_alloc,sk_rcvbuf;void (*sk_data_ready)(struct sock *);};
struct kref {unsigned int refs;};
struct delayed_work {int unused;};
static unsigned int allocations,submitted;
static struct sk_buff *alloc_skb(unsigned int length,int flags){(void)flags;assert(length<=2047);allocations++;struct sk_buff *skb=calloc(1,sizeof(struct sk_buff));skb->truesize=512;return skb;}
static void *skb_put(struct sk_buff *skb,unsigned int length){assert(length<=sizeof(skb->data));skb->len=length;return skb->data;}
static void kfree_skb(struct sk_buff *skb){if(skb){allocations--;if(skb->owner)skb->owner->sk_rmem_alloc-=skb->truesize;free(skb);}}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *skb){assert(q->lock.held);if(q->tail)q->tail->next=skb;else q->head=skb;q->tail=skb;q->qlen++;}
static void sock_hold(struct sock *s){s->refs++;}
static void sock_put(struct sock *s){assert(s->refs>0);s->refs--;}
/* @@STRUCTS@@ */
static void data_ready(struct sock *sk){sk->wakes++;}
#define READ_ONCE(v) (v)
static int atomic_read(int *value){return *value;}
static int sk_rmem_schedule(struct sock *sk,struct sk_buff *skb,unsigned int size){(void)sk;(void)skb;(void)size;return 1;}
static void skb_set_owner_r(struct sk_buff *skb,struct sock *sk){skb->owner=sk;sk->sk_rmem_alloc+=skb->truesize;}
static struct sl_channel_progress sl_snapshot(struct sl_connection_session *s){return s->progress;}
static void sl_progress_event(struct sl_connection_session *s,unsigned int event,unsigned int mtu){(void)s;(void)event;(void)mtu;assert(!"capability-reply integration covered separately");}
static void sl_fault(struct sl_connection_session *s,int error){assert(error<0);sl_channel_fail(&s->progress);}
/* @@FUNCTIONS@@ */
static int atomic_submit(void *context){struct sl_connection_session *s=context;assert(irq_disabled&&s->lock.held);submitted++;return 0;}
static void route(struct sl_connection_session *s,unsigned int tcid,unsigned int pi,const char *message){u8 wire[300];int n=sl_channel_frame_encode(wire,sizeof(wire),tcid,pi,(const u8 *)message,strlen(message));assert(n>0);sl_route(s,wire,n);assert(!s->lock.held&&!irq_disabled);}
int main(void){
 struct sl_connection_session s={0};struct sock sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready};
 sl_channel_start(&s.progress,249);sl_channel_request_submitted(&s.progress,0);sl_channel_peer_capability(&s.progress,249,0);sl_channel_response_submitted(&s.progress,0);
 s.channel.local_tcid=SL_CHANNEL_CUTC;s.channel.remote_tcid=SL_CHANNEL_CUTC;s.channel.pi=241;s.channel.mtu=249;s.channel.sk=&sk;
 assert(sl_binding_attach(&s.channel.binding));
 route(&s,SL_CHANNEL_CUTC,241,"real codec");assert(s.channel.rx.qlen==1&&sk.wakes==1&&sk.refs==1);
 route(&s,32,241,"wrong TCID");route(&s,SL_CHANNEL_CUTC,242,"wrong PI");assert(s.channel.rx.qlen==1&&s.channel.rx_dropped==2);
 for(unsigned int i=1;i<SL_CHANNEL_RX;i++)route(&s,SL_CHANNEL_CUTC,241,"bounded");
 route(&s,SL_CHANNEL_CUTC,241,"full queue");assert(s.channel.rx.qlen==SL_CHANNEL_RX&&s.channel.rx_dropped==3);
 struct sl_submit_scope scope={&s,true};irq_disabled=true;
 assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==1);

 irq_disabled=false;
 for(unsigned i=0;i<SL_CHANNEL_TX;i++) {
  struct sl_admission admission={&s,alloc_skb(1,0),1};
  assert(sl_admit(&admission)==0&&admission.skb==NULL);
 }
 struct sl_admission extra={&s,alloc_skb(1,0),1};
 assert(sl_admit(&extra)==-EAGAIN&&extra.skb);kfree_skb(extra.skb);
 struct sl_admission large={&s,alloc_skb(250,0),250};
 assert(sl_admit(&large)==-EMSGSIZE&&large.skb);kfree_skb(large.skb);
 irq_disabled=true;
 sl_binding_retire(&s.channel.binding);
 assert(sl_session_submit(&scope,atomic_submit,&s)==-ECANCELED&&submitted==1);
 irq_disabled=false;
 struct sl_admission closed={&s,alloc_skb(1,0),1};
 assert(sl_admit(&closed)==-ENOTCONN&&closed.skb);kfree_skb(closed.skb);
 irq_disabled=true;
 scope.application=false;assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==2);
 sl_channel_close(&s.progress);assert(sl_session_submit(&scope,atomic_submit,&s)==-ECANCELED&&submitted==2);irq_disabled=false;
 route(&s,SL_CHANNEL_CUTC,241,"after detach");assert(s.channel.rx.qlen==SL_CHANNEL_RX&&s.channel.rx_dropped==4);
 while(s.channel.rx.head){struct sk_buff *skb=s.channel.rx.head;s.channel.rx.head=skb->next;kfree_skb(skb);}
 while(s.channel.tx.head){struct sk_buff *skb=s.channel.tx.head;s.channel.tx.head=skb->next;kfree_skb(skb);}assert(allocations==0);
 puts("ACTUAL_SESSION_ROUTE_SUBMIT_PASS; explicit kernel dependencies, no RF");return 0;
}
