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
static unsigned long jiffies = 42;
#define msecs_to_jiffies(value) (value)
#include "sle_channel_state.h"
#include "sle_channel_grant.h"
#include "sle_channel_table.h"
#include "sle_fragment_cursor.h"
#include "sparklink_socket.h"
#define __user
#define ENOIOCTLCMD 515
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
struct sk_buff {struct sock *owner;struct sk_buff *next;unsigned int len,truesize,users;unsigned long cb[6];u8 data[2047];};
struct sk_buff_head {spinlock_t lock;unsigned int qlen;struct sk_buff *head,*tail,*prev;};
struct sock {unsigned int refs,wakes;int sk_rmem_alloc,sk_rcvbuf,sk_err,sk_state,sk_shutdown;void (*sk_data_ready)(struct sock *);void (*sk_error_report)(struct sock *);void (*sk_state_change)(struct sock *);};
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
#define TCP_CLOSE 7
#define SHUTDOWN_MASK 3
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
static struct sl_connection_session *sl_binding_session(struct sock *sk){assert(sl_sk(sk)->channel_slot < SL_SESSION_CHANNELS);current_session->refs.refs++;return current_session;}
static void sl_connection_session_put(struct sl_connection_session *s){assert(s->refs.refs>1);s->refs.refs--;}
static int sparklink_native_session_status(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch){
 assert(id==1&&generation==7&&lifetime==11&&handle==3&&epoch==1);return authority?status_error:-EACCES;
}
static int sparklink_native_session_admit(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch,int (*callback)(void *),void *context){
 int ret=sparklink_native_session_status(id,generation,lifetime,handle,epoch);if(ret)return ret;
 assert(!host_locked&&!irq_disabled);host_locked=true;irq_disabled=true;
 ret=callback(context);assert(!current_session->lock.held&&!current_session->channels[0].rx.lock.held);
 irq_disabled=false;host_locked=false;return ret;
}
static int sparklink_native_session_inspect(u16 id,u64 generation,u64 lifetime,u16 handle,u64 epoch,
 int (*callback)(const struct sparklink_credit_snapshot *,void *),void *context){
 int ret=sparklink_native_session_status(id,generation,lifetime,handle,epoch);if(ret)return ret;
 const struct sparklink_credit_snapshot snapshot={.maximum=254,.capacity=5,.outstanding=3,
  .connection_debt=2,.peak_reserved=5,.pool_exhaustions=17};
 assert(!host_locked&&!irq_disabled);host_locked=true;irq_disabled=true;
 ret=callback(&snapshot,context);assert(!current_session->lock.held);
 irq_disabled=false;host_locked=false;return ret;
}
static void route(struct sl_connection_session *,unsigned int,unsigned int,const char *);
static int __skb_wait_for_more_packets(struct sock *sk,struct sk_buff_head *queue,int *error,long *timeout,struct sk_buff *last){
 assert(!host_locked&&!irq_disabled&&!current_session->lock.held&&!queue->lock.held);assert(sk==current_session->channels[sl_sk(sk)->channel_slot].sk);
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
static void skb_free_datagram(struct sock *sk,struct sk_buff *skb){assert(!host_locked&&sk==current_session->channels[sl_sk(sk)->channel_slot].sk);kfree_skb(skb);}
static unsigned int copy_limit = 40;
static unsigned long copy_to_user(void *out,const void *in,unsigned long size){
 assert(!host_locked&&!irq_disabled&&!current_session->lock.held);
 unsigned long copied=copy_limit<size?copy_limit:size;memcpy(out,in,copied);return size-copied;
}
static int time_after_eq(unsigned long a,unsigned long b){return a>=b;}
static void sl_wake(struct sl_connection_session *s){(void)s;}
static struct sk_buff *skb_dequeue(struct sk_buff_head *q){
 unsigned long flags;struct sk_buff *skb;
 spin_lock_irqsave(&q->lock,flags);skb=q->head;
 if(skb){q->head=skb->next;if(!q->head)q->tail=NULL;q->qlen--;skb->next=NULL;}
 spin_unlock_irqrestore(&q->lock,flags);return skb;
}
static void skb_queue_purge(struct sk_buff_head *q){struct sk_buff *skb;while((skb=skb_dequeue(q)))kfree_skb(skb);}
static void skb_queue_head(struct sk_buff_head *q,struct sk_buff *skb){
 spin_lock(&q->lock);skb->next=q->head;q->head=skb;if(!q->tail)q->tail=skb;q->qlen++;spin_unlock(&q->lock);
}
static unsigned int packet_budget,fragment_count,fragment_pb[16],fragment_size[16];
static u8 fragment_bytes[4096];static unsigned int fragment_bytes_count;
static int fragment_failure;static bool retire_after_fragment, retire_before_fragment;
static int fragment_submit(void *context){
 (void)context;assert(irq_disabled);if(!packet_budget)return -EAGAIN;
 if(fragment_failure)return fragment_failure;
 packet_budget--;return 0;
}
static int sparklink_native_acb_fragment_guarded(u16 id,u64 generation,u64 lifetime,u16 handle,u8 boundary,
 const u8 *bytes,size_t length,u64 epoch,int (*consent)(void *,int (*)(void *),void *),void *scope){
 struct sl_submit_scope *permission=scope;int result;unsigned long flags;
 assert(id==permission->session->controller&&generation==permission->session->generation);
 assert(lifetime==permission->session->lifetime&&handle==permission->session->handle&&epoch==permission->session->epoch);
 assert(!permission->session->lock.held&&length<=254&&boundary<=3);
 if(retire_before_fragment){sl_binding_retire(&permission->channel->binding);permission->channel->sk=NULL;}
 /* Host/data/gate and credit are dependencies here, separately tested in Rust.
  * Invoke the actual Session consent before accepting a fragment. */
 flags=irq_disabled;irq_disabled=true;result=consent(scope,fragment_submit,NULL);irq_disabled=flags;
 if(!result){assert(fragment_count<16&&fragment_bytes_count+length<=sizeof(fragment_bytes));
  fragment_pb[fragment_count]=boundary;fragment_size[fragment_count++]=length;
  memcpy(fragment_bytes+fragment_bytes_count,bytes,length);fragment_bytes_count+=length;
  if(retire_after_fragment){spin_lock_irqsave(&permission->session->lock,flags);
   sl_binding_retire(&permission->channel->binding);permission->channel->sk=NULL;spin_unlock_irqrestore(&permission->session->lock,flags);}
 }
 return result;
}
/* @@FUNCTIONS@@ */
static int atomic_submit(void *context){struct sl_connection_session *s=context;assert(irq_disabled&&s->lock.held);submitted++;return 0;}
static void route(struct sl_connection_session *s,unsigned int tcid,unsigned int pi,const char *message){u8 wire[300];int n=sl_channel_frame_encode(wire,sizeof(wire),tcid,pi,(const u8 *)message,strlen(message));assert(n>0);sl_route(s,wire,n);assert(!s->lock.held&&!irq_disabled);}
static void init_grant(struct sl_connection_session *s,struct sock *sk,unsigned int directions){
 struct sl_basic_channel *c=&s->channels[sl_sk(sk)->channel_slot];
 struct sl_grant_scope scope={.controller=s->controller,.generation=s->generation,.lifetime=s->lifetime,.epoch=s->epoch,.handle=s->handle,.local_tcid=c->local_tcid,.remote_tcid=c->remote_tcid,.pi=c->pi};
 assert(sl_grant_init(&sl_sk(sk)->grant,scope,directions,0));
}
static void init_receive(struct sl_connection_session *s,struct sock *sk){
 memset(s,0,sizeof(*s));s->controller=1;s->generation=7;s->lifetime=11;s->handle=3;s->epoch=1;s->refs.refs=1;
 sl_channel_start(&s->progress,249);sl_channel_request_submitted(&s->progress,0);sl_channel_peer_capability(&s->progress,249,0);sl_channel_response_submitted(&s->progress,0);
 s->channels[0].local_tcid=31;s->channels[0].remote_tcid=31;s->channels[0].pi=241;s->channels[0].mtu=249;s->channels[0].sk=sk;assert(sl_binding_attach(&s->channels[0].binding));
 init_grant(s,sk,SL_GRANT_TX|SL_GRANT_RX);
 s->channels[0].rx.prev=(struct sk_buff *)&s->channels[0].rx;current_session=s;authority=true;copy_fault=false;receive_timeout=5;wait_calls=0;status_error=0;
}
static void receive_tests(void){
 struct sl_connection_session s;struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;struct socket sock={.sk=sk};struct msghdr msg={0};
 init_receive(&s,sk);assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EAGAIN&&wait_calls==0);
 route(&s,31,241,"peek");assert(sl_recvmsg(&sock,&msg,2,MSG_PEEK)==2&&s.channels[0].rx.qlen==1&&(msg.msg_flags&MSG_TRUNC));
 assert(sl_recvmsg(&sock,&msg,2,MSG_TRUNC)==4&&s.channels[0].rx.qlen==0);
 route(&s,31,241,"");assert(sl_recvmsg(&sock,&msg,1,MSG_PEEK)==0&&s.channels[0].rx.qlen==1);
 assert(sl_recvmsg(&sock,&msg,1,0)==0&&s.channels[0].rx.qlen==0);
 route(&s,31,241,"fault");copy_fault=true;assert(sl_recvmsg(&sock,&msg,100,0)==-EFAULT&&s.channels[0].rx.qlen==0);copy_fault=false;
 assert(sl_recvmsg(&sock,&msg,1,MSG_OOB)==-EOPNOTSUPP);
 status_error=-EAGAIN;assert(sl_recvmsg(&sock,&msg,100,0)==-EAGAIN&&wait_calls==0);status_error=0;
 for(unsigned int kind=0;kind<=5;kind++){
  init_receive(&s,sk);wait_case=kind;
  int ret=sl_recvmsg(&sock,&msg,100,0);
  if(kind==0)assert(ret==-EAGAIN);
  else if(kind==1){assert(ret==-EACCES&&s.channels[0].rx.qlen==1);assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);}
  else if(kind==2)assert(ret==9&&!memcmp(msg.bytes,"wake data",9));
  else if(kind==3)assert(ret==-EINTR);
  else if(kind==4)assert(ret==-EACCES);
  else assert(ret==-EAGAIN&&s.channels[0].rx.qlen==1);
  assert(wait_calls==1&&s.refs.refs==1);
  while(s.channels[0].rx.head){struct sk_buff *skb=s.channels[0].rx.head;s.channels[0].rx.head=skb->next;kfree_skb(skb);}
 }
 assert(allocations==0&sk->sk_rmem_alloc==0);
}
static void direction_tests(void){
 struct sl_connection_session s;struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;struct socket sock={.sk=sk};struct msghdr msg={0};
 init_receive(&s,sk);init_grant(&s,sk,SL_GRANT_TX);
 assert(sl_poll(NULL,&sock,NULL)==(EPOLLOUT|EPOLLWRNORM));
 route(&s,31,241,"forbidden RX");assert(s.channels[0].rx.qlen==0&&s.channels[0].rx_dropped==1);
 assert(sl_recvmsg(&sock,&msg,100,0)==-EACCES&&wait_calls==0);
 init_grant(&s,sk,SL_GRANT_RX);
 struct sl_admission access={.session=&s,.channel=&s.channels[0]};assert(sl_tx_access(&access)==-EACCES);
 assert(sl_poll(NULL,&sock,NULL)==0);
 struct sl_admission admission={&s,&s.channels[0],alloc_skb(1,0),1};assert(sl_admit(&admission)==-EACCES&&admission.skb);kfree_skb(admission.skb);
 struct sl_submit_scope scope={.session=&s,.channel=&s.channels[0]};unsigned int before=submitted;irq_disabled=true;
 assert(sl_session_submit(&scope,atomic_submit,&s)==-EACCES&&submitted==before);
 scope.channel=NULL;assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==before+1);irq_disabled=false;
 route(&s,31,241,"allowed RX");assert(sl_poll(NULL,&sock,NULL)==(EPOLLIN|EPOLLRDNORM));assert(sl_recvmsg(&sock,&msg,100,0)==10);
 for(unsigned int field=0;field<8;field++){
  init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);struct sl_grant_scope *g=&socket_binding.grant.scope;
  switch(field){case 0:g->controller++;break;case 1:g->generation++;break;case 2:g->lifetime++;break;case 3:g->epoch++;break;case 4:g->handle++;break;case 5:g->local_tcid++;break;case 6:g->remote_tcid++;break;default:g->pi++;break;}
  assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);
  assert(sl_poll(NULL,&sock,NULL)==(EPOLLERR|EPOLLHUP));
  irq_disabled=true;scope.channel=&s.channels[0];assert(sl_session_submit(&scope,atomic_submit,&s)==-EACCES);irq_disabled=false;
 }
 init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);socket_binding.grant.security=1;
 assert(sl_recvmsg(&sock,&msg,100,MSG_DONTWAIT)==-EACCES);
 assert(allocations==0&&sk->sk_rmem_alloc==0);
}
static void publication_tests(void){
 struct sl_connection_session s;struct sl_socket_binding b={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct socket sock={.sk=&b.sk};
 init_receive(&s,&b.sk);s.channels[0].sk=NULL;s.channels[0].binding=(struct sl_binding_progress){0};
 s.progress=(struct sl_channel_progress){.phase=SL_CH_UNBOUND,.maximum=249};s.deadline=0;jiffies=10000;
 struct sl_bind_admission admission={.sock=&sock,.binding=&b,.session=&s,.grant=b.grant};
 struct sl_channel_grant before=b.grant;authority=false;
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EACCES);
 assert(!b.session&&!s.channels[0].binding.bound&&b.sk.refs==1&&b.grant.directions==before.directions);
 assert(s.progress.phase==SL_CH_UNBOUND&&s.deadline==0); /* revoked never starts CMTC */
 authority=true;assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==0);
 assert(s.progress.phase==SL_CH_NEGOTIATING&&s.deadline==15000);
 assert(b.session==&s&&s.channels[0].sk==&b.sk&&s.channels[0].binding.bound&&b.sk.refs==2&&sock.state==SS_CONNECTED);
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EINVAL);
 jiffies=20000;assert(s.deadline==15000); /* physical birth/second fd cannot refresh */
 b.session=NULL;s.channels[0].binding.bound=0;s.channels[0].binding.retired=1;
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EOPNOTSUPP);
 s.channels[0].sk=NULL;sock_put(&b.sk);
}
static void two_channel_tests(void)
{
 struct sl_connection_session s;
 struct sl_socket_binding user={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};
 struct sl_socket_binding service={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready},.channel_slot=1};
 struct socket us={.sk=&user.sk},ss={.sk=&service.sk};struct msghdr msg={0};
 init_receive(&s,&user.sk);
 s.channels[1].local_tcid=s.channels[1].remote_tcid=10;s.channels[1].pi=0;
 s.channels[1].mtu=249;s.channels[1].sk=&service.sk;s.channels[1].rx.prev=(void *)&s.channels[1].rx;
 assert(sl_binding_attach(&s.channels[1].binding));init_grant(&s,&service.sk,3);
 u8 bytes[]={2,3,254,0,1,2},wire[10];
 assert(sl_channel_frame_encode(wire,sizeof(wire),10,0,bytes,sizeof(bytes))==10);
 sl_route(&s,wire,sizeof(wire));route(&s,31,241,"user first");
 assert(s.channels[0].rx.qlen==1&&s.channels[1].rx.qlen==1);
 assert(sl_recvmsg(&ss,&msg,100,0)==6&&!memcmp(msg.bytes,bytes,6));
 assert(s.channels[0].rx.qlen==1&&s.channels[1].rx.qlen==0);
 for(unsigned int i=0;i<SL_CHANNEL_RX;i++)sl_route(&s,wire,sizeof(wire));
 sl_route(&s,wire,sizeof(wire));assert(s.channels[1].rx.qlen==SL_CHANNEL_RX&&s.channels[1].rx_dropped==1);
 route(&s,31,241,"user second");assert(s.channels[0].rx.qlen==2);
 assert(sl_recvmsg(&us,&msg,100,0)==10&&!memcmp(msg.bytes,"user first",10));
 assert(sl_recvmsg(&us,&msg,100,0)==11&&!memcmp(msg.bytes,"user second",11));
 struct sl_submit_scope service_scope={.session=&s,.channel=&s.channels[1]},user_scope={.session=&s,.channel=&s.channels[0]};
 sl_binding_retire(&s.channels[1].binding);s.channels[1].sk=NULL;
 irq_disabled=true;
 assert(sl_session_submit(&service_scope,atomic_submit,&s)==-ECANCELED);
 assert(sl_session_submit(&user_scope,atomic_submit,&s)==0);
 irq_disabled=false;
 sl_route(&s,wire,sizeof(wire));assert(s.channels[1].rx_dropped==2);
 route(&s,31,241,"after service close");
 assert(sl_recvmsg(&us,&msg,100,0)==19&&!memcmp(msg.bytes,"after service close",19));
 assert(sl_poll(NULL,&us,NULL)==(EPOLLOUT|EPOLLWRNORM));
 assert(sl_poll(NULL,&ss,NULL)==(EPOLLERR|EPOLLHUP));
 struct sl_socket_binding replacement={.sk={.refs=1}};struct socket replacement_socket={.sk=&replacement.sk};
 struct sl_bind_admission admission={.sock=&replacement_socket,.binding=&replacement,.session=&s,.grant=service.grant,.channel_slot=1};
 assert(sparklink_native_session_admit(1,7,11,3,1,sl_publish_binding,&admission)==-EOPNOTSUPP);
 while(s.channels[1].rx.head){struct sk_buff *skb=s.channels[1].rx.head;s.channels[1].rx.head=skb->next;kfree_skb(skb);}
 assert(allocations==0&&service.sk.sk_rmem_alloc==0&&user.sk.sk_rmem_alloc==0);
}
static void capability_tests(void)
{
 struct sl_connection_session s;struct sl_socket_binding b={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};
 struct socket sock={.sk=&b.sk};init_receive(&s,&b.sk);s.channels[0].mps=249;
 struct sparklink_channel_info out,good;memset(&out,0xa5,sizeof(out));
 assert(sizeof(out)==40&&_Alignof(struct sparklink_channel_info)==8);
 assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_INFO,(unsigned long)&out)==0);
 assert(out.version==1&&out.size==40&&out.controller==1&&out.handle==3&&out.generation==7&&out.lifetime==11);
 assert(out.mtu==249&&out.mps==249&&out.local_tcid==31&&out.remote_tcid==31&&out.pi==241&&out.mode==0&&out.directions==3&&out.reserved==0);
 good=out;struct sl_channel_progress before=s.progress;unsigned int refs=s.refs.refs;
 route(&s,31,241,"not consumed");
 copy_limit=20;memset(&out,0xa5,sizeof(out));
 assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_INFO,(unsigned long)&out)==-EFAULT);
 assert(!memcmp(&out,&good,20)&&memcmp(&out,&good,sizeof(out)));
 assert(!memcmp(&before,&s.progress,sizeof(before))&&s.refs.refs==refs&&s.channels[0].rx.qlen==1);
 copy_limit=40;assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_INFO,(unsigned long)&out)==0&&!memcmp(&out,&good,40));
 for(unsigned int kind=0;kind<4;kind++){
  s.progress=before;init_grant(&s,&b.sk,3);authority=true;
  if(kind==0)s.progress.phase=SL_CH_NEGOTIATING;
  if(kind==1)authority=false;
  if(kind==2)b.grant.scope.lifetime++;
  if(kind==3)sl_binding_retire(&s.channels[0].binding);
  memset(&out,0xa5,40);unsigned char bytes[40];memcpy(bytes,&out,40);
  assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_INFO,(unsigned long)&out)==(kind==0?-EAGAIN:kind==3?-ENOTCONN:-EACCES));
  assert(!memcmp(bytes,&out,40));
 }
 assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_INFO^1,0)==-ENOIOCTLCMD);
 struct sk_buff *skb=s.channels[0].rx.head;kfree_skb(skb);assert(allocations==0);authority=true;
}
static void enqueue_fragment_test(struct sl_basic_channel *c,unsigned int length){
 struct sk_buff *skb=alloc_skb(length,0);unsigned long flags;
 u8 *data=skb_put(skb,length);for(unsigned int i=0;i<length;i++)data[i]=(i*37+11)&255;
 ((struct sl_fragment_cursor *)skb->cb)->deadline=jiffies+5000;
 spin_lock_irqsave(&c->tx.lock,flags);__skb_queue_tail(&c->tx,skb);spin_unlock_irqrestore(&c->tx.lock,flags);
}
static void fragment_worker_tests(void){
 struct sl_connection_session s;struct sl_socket_binding bindings[2]={0};
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;
 s.channels[1].local_tcid=10;s.channels[1].remote_tcid=10;s.channels[1].sk=&bindings[1].sk;
 bindings[1].channel_slot=1;assert(sl_binding_attach(&s.channels[1].binding));init_grant(&s,&bindings[1].sk,SL_GRANT_TX);
 fragment_count=fragment_bytes_count=0;packet_budget=2;fragment_failure=0;retire_after_fragment=false;jiffies=42;
 enqueue_fragment_test(&s.channels[0],2047);enqueue_fragment_test(&s.channels[1],4);
 assert(!sl_transmit_channel(&s,&s.channels[0]));assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(fragment_count==2&&s.fragment_slot==0&&!s.channels[0].tx.qlen&&s.tx_inflight&&s.channels[0].binding.busy);
 assert(!sl_transmit_channel(&s,&s.channels[0]));assert(fragment_count==2);
 assert(!sl_transmit_channel(&s,&s.channels[1]));assert(s.channels[1].tx.qlen==1);
 packet_budget=7;for(unsigned int i=0;i<7;i++)assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(fragment_count==9&&fragment_bytes_count==2047&&s.fragment_slot==-1&&!s.channels[0].tx.qlen);
 assert(fragment_pb[0]==1&&fragment_pb[8]==3&&fragment_size[8]==15);
 for(unsigned int i=1;i<8;i++)assert(fragment_pb[i]==2);
 for(unsigned int i=0;i<2047;i++)assert(fragment_bytes[i]==((i*37+11)&255));
 packet_budget=1;assert(!sl_transmit_channel(&s,&s.channels[1]));assert(fragment_pb[9]==0);
 /* Successful first fragment followed by last-fd retirement: do not allow
  * another PDU to replace the controller's uncompleted stream. */
 enqueue_fragment_test(&s.channels[0],255);packet_budget=1;retire_after_fragment=true;
 assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(!s.channels[0].sk&&s.tx_inflight&&s.tx_started&&s.channels[0].binding.busy);
 retire_after_fragment=false;packet_budget=1;
 assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(!s.tx_inflight&&!s.channels[0].binding.busy&&s.progress.phase==SL_CH_OPEN);
 assert(sl_binding_live(s.channels[1].binding));assert(!allocations);
 /* Last close wins before first atomic submit: actual consent denies it. */
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;packet_budget=1;
 enqueue_fragment_test(&s.channels[0],255);retire_before_fragment=true;
 unsigned int before=fragment_count;
 assert(!sl_transmit_channel(&s,&s.channels[0]));assert(fragment_count==before&&!s.tx_inflight&&!allocations);
 retire_before_fragment=false;
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;packet_budget=1;
 enqueue_fragment_test(&s.channels[0],255);assert(!sl_transmit_channel(&s,&s.channels[0]));
 jiffies+=5000;packet_budget=1;
 assert(sl_transmit_channel(&s,&s.channels[0])==-ETIMEDOUT);assert(!allocations);
 /* Even a started operation's frozen authority must match its Session. */
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;packet_budget=1;jiffies=42;
 enqueue_fragment_test(&s.channels[0],255);assert(!sl_transmit_channel(&s,&s.channels[0]));
 s.tx_grant.scope.lifetime++;packet_budget=1;before=fragment_count;
 assert(sl_transmit_channel(&s,&s.channels[0])==-EACCES);
 assert(fragment_count==before&&!s.tx_inflight&&!allocations);
 /* Deadline also rechecked at the actual commit callback after preparation. */
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;packet_budget=0;
 enqueue_fragment_test(&s.channels[0],255);assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(!s.tx_inflight&&s.channels[0].tx.qlen==1);
 struct sk_buff *deadline_skb=skb_dequeue(&s.channels[0].tx);
 s.tx_inflight=deadline_skb;s.fragment_slot=0;s.tx_grant=bindings[0].grant;
 assert(sl_binding_start_tx(&s.channels[0].binding));
 struct sl_submit_scope expired_scope={.session=&s,.channel=&s.channels[0],.operation=deadline_skb};
 jiffies=5042;irq_disabled=true;before=submitted;
 assert(sl_session_submit(&expired_scope,atomic_submit,&s)==-ETIMEDOUT&&submitted==before);
 irq_disabled=false;sl_retire_tx(&s);assert(!allocations);
 /* A queue-only timeout uses actual socket error publication and retains the
  * second Channel/Session. Deadline comes from actual admission, not dequeue. */
 init_receive(&s,&bindings[0].sk);s.acb_maximum=254;s.fragment_slot=-1;jiffies=42;
 bindings[0].sk.sk_error_report=data_ready;bindings[0].sk.sk_state_change=data_ready;
 s.channels[1].sk=&bindings[1].sk;assert(sl_binding_attach(&s.channels[1].binding));
 struct sk_buff *queued=alloc_skb(4,0);skb_put(queued,4);
 struct sl_admission admission={&s,&s.channels[0],queued,4};
 assert(!sl_admit(&admission));
 assert(((struct sl_fragment_cursor *)queued->cb)->deadline==5042);
 jiffies=5042;assert(!sl_transmit_channel(&s,&s.channels[0]));
 assert(bindings[0].sk.sk_err==ETIMEDOUT&&bindings[0].sk.sk_shutdown==SHUTDOWN_MASK);
 assert(sl_binding_live(s.channels[1].binding)&&s.progress.phase==SL_CH_OPEN&&!allocations);
}
static void tx_status_tests(void){
 struct sl_connection_session s;struct sl_socket_binding binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};
 struct socket sock={.sk=&binding.sk};struct sparklink_channel_tx_status value;
 _Static_assert(sizeof(value)==64,"fixed TX status UAPI");
 init_receive(&s,&binding.sk);copy_limit=64;memset(&value,0xcc,sizeof(value));
 assert(!sl_ioctl(&sock,SPARKLINK_CHANNEL_TX_STATUS,(unsigned long)&value));
 assert(value.size==64&&value.version==1&&value.capacity==5&&value.outstanding==3&&value.connection_debt==2);
 assert(value.pool_exhaustions==17&&value.peak_reserved==5&&value.queue_limit==8&&!value.reserved&&!value.flags);
 s.tx_inflight=alloc_skb(2047,0);skb_put(s.tx_inflight,2047);s.fragment_slot=0;s.tx_started=true;
 ((struct sl_fragment_cursor *)s.tx_inflight->cb)->offset=254;s.channels[0].binding.busy=1;
 assert(!sl_ioctl(&sock,SPARKLINK_CHANNEL_TX_STATUS,(unsigned long)&value));
 assert(value.active_pdu_bytes==2047&&value.active_pdu_offset==254&&value.busy==1&&value.flags==3);
 copy_limit=17;assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_TX_STATUS,(unsigned long)&value)==-EFAULT);
 copy_limit=64;assert(!sl_ioctl(&sock,SPARKLINK_CHANNEL_TX_STATUS,(unsigned long)&value));
 assert(value.active_pdu_offset==254);authority=false;memset(&value,0x5a,sizeof(value));
 assert(sl_ioctl(&sock,SPARKLINK_CHANNEL_TX_STATUS,(unsigned long)&value)==-EACCES);
 for(unsigned int i=0;i<sizeof(value);i++)assert(((u8 *)&value)[i]==0x5a);
 authority=true;sl_retire_tx(&s);assert(!allocations);copy_limit=40;
}
int main(void){
 struct sl_connection_session s={.controller=1,.generation=7,.lifetime=11,.epoch=1,.handle=3};struct sl_socket_binding socket_binding={.sk={.refs=1,.sk_rcvbuf=100000,.sk_data_ready=data_ready}};struct sock *sk=&socket_binding.sk;
 sl_channel_start(&s.progress,249);sl_channel_request_submitted(&s.progress,0);sl_channel_peer_capability(&s.progress,249,0);sl_channel_response_submitted(&s.progress,0);
 s.channels[0].local_tcid=SL_CHANNEL_CUTC;s.channels[0].remote_tcid=SL_CHANNEL_CUTC;s.channels[0].pi=241;s.channels[0].mtu=249;s.channels[0].sk=sk;
 assert(sl_binding_attach(&s.channels[0].binding));
 init_grant(&s,sk,SL_GRANT_TX|SL_GRANT_RX);
 route(&s,SL_CHANNEL_CUTC,241,"real codec");assert(s.channels[0].rx.qlen==1&sk->wakes==1&sk->refs==1);
 route(&s,32,241,"wrong TCID");route(&s,SL_CHANNEL_CUTC,242,"wrong PI");assert(s.channels[0].rx.qlen==1&&s.channels[0].rx_dropped==0);
 for(unsigned int i=1;i<SL_CHANNEL_RX;i++)route(&s,SL_CHANNEL_CUTC,241,"bounded");
 route(&s,SL_CHANNEL_CUTC,241,"full queue");assert(s.channels[0].rx.qlen==SL_CHANNEL_RX&&s.channels[0].rx_dropped==1);
 struct sl_submit_scope scope={.session=&s,.channel=&s.channels[0]};irq_disabled=true;
 assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==1);

 irq_disabled=false;
 for(unsigned i=0;i<SL_CHANNEL_TX;i++) {
  struct sl_admission admission={&s,&s.channels[0],alloc_skb(1,0),1};
  assert(sl_admit(&admission)==0&&admission.skb==NULL);
 }
 struct sl_admission extra={&s,&s.channels[0],alloc_skb(1,0),1};
 assert(sl_admit(&extra)==-EAGAIN&&extra.skb);kfree_skb(extra.skb);
 struct sl_admission large={&s,&s.channels[0],alloc_skb(250,0),250};
 assert(sl_admit(&large)==-EMSGSIZE&&large.skb);kfree_skb(large.skb);
 irq_disabled=true;
 sl_binding_retire(&s.channels[0].binding);
 assert(sl_session_submit(&scope,atomic_submit,&s)==-ECANCELED&&submitted==1);
 irq_disabled=false;
 struct sl_admission closed={&s,&s.channels[0],alloc_skb(1,0),1};
 assert(sl_admit(&closed)==-ENOTCONN&&closed.skb);kfree_skb(closed.skb);
 irq_disabled=true;
 scope.channel=NULL;assert(sl_session_submit(&scope,atomic_submit,&s)==0&&submitted==2);
 sl_channel_close(&s.progress);assert(sl_session_submit(&scope,atomic_submit,&s)==-ECANCELED&&submitted==2);irq_disabled=false;
 route(&s,SL_CHANNEL_CUTC,241,"after detach");assert(s.channels[0].rx.qlen==SL_CHANNEL_RX&&s.channels[0].rx_dropped==2);
 while(s.channels[0].rx.head){struct sk_buff *skb=s.channels[0].rx.head;s.channels[0].rx.head=skb->next;kfree_skb(skb);}
 while(s.channels[0].tx.head){struct sk_buff *skb=s.channels[0].tx.head;s.channels[0].tx.head=skb->next;kfree_skb(skb);}assert(allocations==0);
 receive_tests();direction_tests();publication_tests();two_channel_tests();capability_tests();fragment_worker_tests();tx_status_tests();
 puts("ACTUAL_SESSION_ROUTE_SUBMIT_PASS; explicit kernel dependencies, no RF");return 0;
}
