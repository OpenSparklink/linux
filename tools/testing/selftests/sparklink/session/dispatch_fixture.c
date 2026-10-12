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
#include <sys/socket.h>
#include <sys/epoll.h>
#define msghdr fixture_msghdr
#define MSG_CMSG_COMPAT 0x40000000
#include "sle_channel_wire.h"
#include "sle_channel_state.h"
#include "sle_channel_grant.h"
#include <stddef.h>
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
struct sk_buff {struct sock *owner;struct sk_buff *next;unsigned int len,truesize,users;u8 data[2047];};
struct sk_buff_head {spinlock_t lock;unsigned int qlen;struct sk_buff *head,*tail,*prev;};
struct sock {unsigned int refs,wakes;int sk_rmem_alloc,sk_rcvbuf,sk_err,sk_state;void (*sk_data_ready)(struct sock *);};
struct kref {unsigned int refs;};
struct delayed_work {int unused;};
static unsigned int allocations,submitted;
static struct sk_buff *alloc_skb(unsigned int length,int flags){(void)flags;assert(length<=2047);allocations++;struct sk_buff *skb=calloc(1,sizeof(struct sk_buff));skb->truesize=512;skb->users=1;return skb;}
static void *skb_put(struct sk_buff *skb,unsigned int length){assert(length<=sizeof(skb->data));skb->len=length;return skb->data;}
static void kfree_skb(struct sk_buff *skb){if(skb){assert(skb->users);if(--skb->users)return;allocations--;if(skb->owner)skb->owner->sk_rmem_alloc-=skb->truesize;free(skb);}}
static void __skb_queue_tail(struct sk_buff_head *q,struct sk_buff *skb){assert(q->lock.held);if(q->tail)q->tail->next=skb;else q->head=skb;q->tail=skb;q->prev=skb;q->qlen++;}
static void sock_hold(struct sock *s){s->refs++;}
static void sock_put(struct sock *s){assert(s->refs>0);s->refs--;}
/* @@STRUCTS@@ */
static struct sl_socket_binding *sl_sk(struct sock *sk){return (struct sl_socket_binding *)((char *)sk - offsetof(struct sl_socket_binding,sk));}
static void data_ready(struct sock *sk){sk->wakes++;}
#define READ_ONCE(v) (v)
static int atomic_read(int *value){return *value;}
static int sk_rmem_schedule(struct sock *sk,struct sk_buff *skb,unsigned int size){(void)sk;(void)skb;(void)size;return 1;}
static void skb_set_owner_r(struct sk_buff *skb,struct sock *sk){skb->owner=sk;sk->sk_rmem_alloc+=skb->truesize;}
static struct sl_channel_progress sl_snapshot(struct sl_connection_session *s){return s->progress;}
static void sl_progress_event(struct sl_connection_session *s,unsigned int event,unsigned int mtu){(void)s;(void)event;(void)mtu;assert(!"capability-reply integration covered separately");}
static void sl_fault(struct sl_connection_session *s,int error){assert(error<0);sl_channel_fail(&s->progress);}

struct socket {struct sock *sk;int state;};
#define SS_CONNECTED 1
#define TCP_ESTABLISHED 1
#define WRITE_ONCE(x,v) ((x)=(v))
struct msghdr {int msg_flags;u8 bytes[2047];};
typedef u32 __poll_t;typedef int poll_table;struct file {int unused;};
static void sock_poll_wait(struct file *file,struct socket *sock,poll_table *wait){(void)file;(void)sock;(void)wait;}
static int skb_queue_empty(struct sk_buff_head *q){return !q->qlen;}
static unsigned int skb_queue_len(struct sk_buff_head *q){return q->qlen;}
static struct sl_connection_session *current_session;
static bool authority=true,host_locked,copy_fault;
static long receive_timeout;
static int status_error;
static unsigned int wait_calls,wait_case;
static struct sk_buff *skb_peek(struct sk_buff_head *q){assert(q->lock.held);return q->head;}
static void skb_get(struct sk_buff *skb){assert(skb->users);skb->users++;}
static void __skb_unlink(struct sk_buff *skb,struct sk_buff_head *q){
 assert(q->lock.held&&q->head==skb&&q->qlen);q->head=skb->next;skb->next=NULL;q->qlen--;
 if(!q->head){q->tail=NULL;q->prev=(struct sk_buff *)q;}
}
static int sock_error(struct sock *sk){int ret=sk->sk_err;sk->sk_err=0;return -ret;}
static long sock_rcvtimeo(struct sock *sk,int nonblock){(void)sk;return nonblock?0:receive_timeout;}
static struct sl_connection_session *sl_binding_session(struct sock *sk){assert(current_session->channel.sk==sk);current_session->refs.refs++;return current_session;}
static void sl_connection_session_put(struct sl_connection_session *s){assert(s->refs.refs>1);s->refs.refs--;}
static int sparklink_native_session_status(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch){
 assert(id==1&&generation==7&&lifetime==11&&handle==3&&epoch==1);return authority?status_error:-EACCES;
}
static int sparklink_native_session_admit(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch,int (*callback)(void *),void *context){
 int ret=sparklink_native_session_status(id,generation,lifetime,handle,epoch);if(ret)return ret;
 assert(!host_locked&&!irq_disabled);host_locked=true;irq_disabled=true;
 ret=callback(context);assert(!current_session->lock.held&&!current_session->channel.rx.lock.held);
 irq_disabled=false;host_locked=false;return ret;
}
static void route(struct sl_connection_session *,unsigned int,unsigned int,const char *);
static int __skb_wait_for_more_packets(struct sock *sk,struct sk_buff_head *queue,int *error,long *timeout,struct sk_buff *last){
 assert(!host_locked&&!irq_disabled&&!current_session->lock.held&&!queue->lock.held);assert(sk==current_session->channel.sk);
 assert(last==queue->prev);assert(++wait_calls==1);
 switch(wait_case){
 case 1:authority=false;route(current_session,31,241,"late after revoke");return 0;
 case 2:route(current_session,31,241,"wake data");return 0;
 case 3:*error=-EINTR;return -EINTR;
 case 5:status_error=-EAGAIN;route(current_session,31,241,"unknown after wake");return 0;
 case 4:authority=false;*error=0;return 1;
 default:*timeout=0;return 0;
 }
}
static int skb_copy_datagram_msg(struct sk_buff *skb,int offset,struct msghdr *msg,int length){
 assert(!host_locked&&!irq_disabled&&!current_session->lock.held);assert(offset==0&&length>=0);
 if(copy_fault)return -EFAULT;memcpy(msg->bytes,skb->data,length);return 0;
}
static void skb_free_datagram(struct sock *sk,struct sk_buff *skb){assert(!host_locked&&sk==current_session->channel.sk);kfree_skb(skb);}
/* @@FUNCTIONS@@ */
static int atomic_submit(void *context){struct sl_connection_session *s=context;assert(irq_disabled&&s->lock.held);submitted++;return 0;}
static void route(struct sl_connection_session *s,unsigned int tcid,unsigned int pi,const char *message){u8 wire[300];int n=sl_channel_frame_encode(wire,sizeof(wire),tcid,pi,(const u8 *)message,strlen(message));assert(n>0);sl_route(s,wire,n);assert(!s->lock.held&&!irq_disabled);}
static void init_grant(struct sl_connection_session *s,struct sock *sk,unsigned int directions){
 struct sl_grant_scope scope={.controller=s->controller,.generation=s->generation,.lifetime=s->lifetime,.epoch=s->epoch,.handle=s->handle,.local_tcid=s->channel.local_tcid,.remote_tcid=s->channel.remote_tcid,.pi=s->channel.pi};
 assert(sl_grant_init(&sl_sk(sk)->grant,scope,directions,0));
}
static void init_receive(struct sl_connection_session *s,struct sock *sk){
 memset(s,0,sizeof(*s));s->controller=1;s->generation=7;s->lifetime=11;s->handle=3;s->epoch=1;s->refs.refs=1;
 sl_channel_start(&s->progress,249);sl_channel_request_submitted(&s->progress,0);sl_channel_peer_capability(&s->progress,249,0);sl_channel_response_submitted(&s->progress,0);
 s->channel.local_tcid=31;s->channel.pi=241;s->channel.mtu=249;s->channel.sk=sk;assert(sl_binding_attach(&s->channel.binding));
 init_grant(s,sk,SL_GRANT_TX|SL_GRANT_RX);
 s->channel.rx.prev=(struct sk_buff *)&s->channel.rx;current_session=s;authority=true;copy_fault=false;receive_timeout=5;wait_calls=0;status_error=0;
}
static void receive_tests(void){
 struct sl_connection_session s;struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;struct socket sock={.sk=sk};struct msghdr msg={0};
 init_receive(&s,sk);assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EAGAIN&&wait_calls==0);
 route(&s,31,241,"peek");assert(sl_recvmsg(&sock,&msg,2,MSG_PEEK)==2&&s.channel.rx.qlen==1&&(msg.msg_flags&MSG_TRUNC));
 assert(sl_recvmsg(&sock,&msg,2,MSG_TRUNC)==4&&s.channel.rx.qlen==0);
 route(&s,31,241,"");assert(sl_recvmsg(&sock,&msg,1,MSG_PEEK)==0&&s.channel.rx.qlen==1);
 assert(sl_recvmsg(&sock,&msg,1,0)==0&&s.channel.rx.qlen==0);
 route(&s,31,241,"fault");copy_fault=true;assert(sl_recvmsg(&sock,&msg,100,0)==-EFAULT&&s.channel.rx.qlen==0);copy_fault=false;
 assert(sl_recvmsg(&sock,&msg,1,MSG_OOB)==-EOPNOTSUPP);
 status_error=-EAGAIN;assert(sl_recvmsg(&sock,&msg,100,0)==-EAGAIN&&wait_calls==0);status_error=0;
 for(unsigned int kind=0;kind<=5;kind++){
  init_receive(&s,sk);wait_case=kind;
  int ret=sl_recvmsg(&sock,&msg,100,0);
  if(kind==0)assert(ret==-EAGAIN);
  else if(kind==1){assert(ret==-EACCES&&s.channel.rx.qlen==1);assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);}
  else if(kind==2)assert(ret==9&&!memcmp(msg.bytes,"wake data",9));
  else if(kind==3)assert(ret==-EINTR);
  else if(kind==4)assert(ret==-EACCES);
  else assert(ret==-EAGAIN&&s.channel.rx.qlen==1);
  assert(wait_calls==1&&s.refs.refs==1);
  while(s.channel.rx.head){struct sk_buff *skb=s.channel.rx.head;s.channel.rx.head=skb->next;kfree_skb(skb);}
 }
 assert(allocations==0&sk->sk_rmem_alloc==0);
}
static void direction_tests(void){
 struct sl_connection_session s;struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;struct socket sock={.sk=sk};struct msghdr msg={0};
 init_receive(&s,sk);init_grant(&s,sk,SL_GRANT_TX);
 assert(sl_poll(NULL,&sock,NULL)==(EPOLLOUT|EPOLLWRNORM));
 route(&s,31,241,"forbidden RX");assert(s.channel.rx.qlen==0&&s.channel.rx_dropped==1);
 assert(sl_recvmsg(&sock,&msg,100,0)==-EACCES&&wait_calls==0);
 init_grant(&s,sk,SL_GRANT_RX);
 assert(sl_tx_access(&s)==-EACCES);
 assert(sl_poll(NULL,&sock,NULL)==0);
 struct sl_admission admission={&s,alloc_skb(1,0),1};assert(sl_admit(&admission)==-EACCES&&admission.skb);kfree_skb(admission.skb);
 struct sl_submit_scope scope={&s,true};unsigned int before=submitted;irq_disabled=true;
 assert(sl_session_submit(&scope,atomic_submit,&s)==-EACCES&&submitted==before);
 scope.application=false;assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==before+1);irq_disabled=false;
 route(&s,31,241,"allowed RX");assert(sl_poll(NULL,&sock,NULL)==(EPOLLIN|EPOLLRDNORM));assert(sl_recvmsg(&sock,&msg,100,0)==10);
 for(unsigned int field=0;field<8;field++){
  init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);struct sl_grant_scope *g=&socket_binding.grant.scope;
  switch(field){case 0:g->controller++;break;case 1:g->generation++;break;case 2:g->lifetime++;break;case 3:g->epoch++;break;case 4:g->handle++;break;case 5:g->local_tcid++;break;case 6:g->remote_tcid++;break;default:g->pi++;break;}
  assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);
  assert(sl_poll(NULL,&sock,NULL)==(EPOLLERR|EPOLLHUP));
  irq_disabled=true;scope.application=true;assert(sl_session_submit(&scope,atomic_submit,&s)==-EACCES);irq_disabled=false;
 }
 init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);socket_binding.grant.security=1;
 assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);
 assert(allocations==0&&sk->sk_rmem_alloc==0);
}
static void publication_tests(void){
 struct sl_connection_session s;struct sl_socket_binding b={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct socket sock={.sk=&b.sk};
 init_receive(&s,&b.sk);s.channel.sk=NULL;s.channel.binding=(struct sl_binding_progress){0};
 struct sl_bind_admission admission={.sock=&sock,.binding=&b,.session=&s,.grant=b.grant};
 struct sl_channel_grant before=b.grant;authority=false;
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EACCES);
 assert(!b.session&&!s.channel.binding.bound&&b.sk.refs==1&&b.grant.directions==before.directions);
 authority=true;assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==0);
 assert(b.session==&s&&s.channel.sk==&b.sk&&s.channel.binding.bound&&b.sk.refs==2&&sock.state==SS_CONNECTED);
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EINVAL);
 b.session=NULL;s.channel.binding.bound=0;s.channel.binding.retired=1;
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EOPNOTSUPP);
 s.channel.sk=NULL;sock_put(&b.sk);
}
int main(void){
 struct sl_connection_session s={.controller=1,.generation=7,.lifetime=11,.epoch=1,.handle=3};struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;
 sl_channel_start(&s.progress,249);sl_channel_request_submitted(&s.progress,0);sl_channel_peer_capability(&s.progress,249,0);sl_channel_response_submitted(&s.progress,0);
 s.channel.local_tcid=SL_CHANNEL_CUTC;s.channel.remote_tcid=SL_CHANNEL_CUTC;s.channel.pi=241;s.channel.mtu=249;s.channel.sk=sk;
 assert(sl_binding_attach(&s.channel.binding));
 init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);
 route(&s,SL_CHANNEL_CUTC,241,"real codec");assert(s.channel.rx.qlen==1&sk->wakes==1&sk->refs==1);
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
 receive_tests();direction_tests();publication_tests();
 puts("ACTUAL_SESSION_ROUTE_SUBMIT_PASS; explicit kernel dependencies, no RF");return 0;
}
