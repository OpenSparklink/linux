// SPDX-License-Identifier: GPL-2.0-only
/* Real ioctl/last-file-close gate, only launched in the explicit VM fixture. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

#define CHECK(x) do { if (!(x)) { fprintf(stderr,"line %d: %s errno=%d\n",__LINE__,#x,errno); exit(1); } } while (0)
static uint64_t wall_ns(void) {struct timespec t;CHECK(!clock_gettime(CLOCK_REALTIME,&t));return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;}
static void pause_ms(unsigned ms) {struct timespec t={ms/1000,(long)(ms%1000)*1000000};while(nanosleep(&t,&t))CHECK(errno==EINTR);}
static int selected(unsigned index) {int fd=open("/dev/sparklink",O_RDWR|O_CLOEXEC);short n=(short)index;CHECK(fd>=0);CHECK(!ioctl(fd,SL_IOCTL_DEV_SELECT,&n));return fd;}
static void hex(const void *data,size_t len) {const unsigned char *p=data;putchar('"');for(size_t i=0;i<len;i++)printf("%02x",p[i]);putchar('"');}
static struct sle_controller_snapshot snapshot(int fd,uint64_t generation) {
 struct sle_controller_snapshot s={.version=1,.generation=generation};CHECK(!ioctl(fd,SL_IOCTL_CONTROLLER_SNAPSHOT,&s));
 CHECK(s.generation==generation&&s.profile==1&&s.flags==SLE_CONTROLLER_SETUP&&s.valid_fields==1&&!s.error);return s;
}
static struct sle_discovery_result radio(int fd,uint64_t generation) {
 struct sle_discovery_result s={.version=1,.generation=generation};CHECK(!ioctl(fd,SL_IOCTL_DISCOVERY_RESULT,&s));
 CHECK(s.generation==generation&&!s.radio_adv&&!s.radio_scan&&!s.error);return s;
}
static struct sle_management_query query(int fd,uint64_t generation,unsigned state) {
 struct sle_management_query q={.version=1,.generation=generation};CHECK(!ioctl(fd,SL_IOCTL_MANAGEMENT_QUERY,&q));
 CHECK(q.state==state&&q.mode==(state==SLE_MANAGEMENT_HELD?SLE_MANAGEMENT_MANAGED:0)&&!q.lease&&!q.flags&&!q.error&&!q.status&&!q.opcode);return q;
}
static void closed(int fd) {CHECK(!close(fd));errno=0;CHECK(fcntl(fd,F_GETFD)==-1&&errno==EBADF);}
int main(int argc,char **argv) {
 CHECK(argc==3);uint64_t generations[2];unsigned long long parsed;char tail;
 CHECK(sscanf(argv[1],"%llu%c",&parsed,&tail)==1);generations[0]=parsed;
 CHECK(sscanf(argv[2],"%llu%c",&parsed,&tail)==1);generations[1]=parsed;
 CHECK(generations[0]&&generations[1]&&generations[0]!=generations[1]);
 int observe[2]={selected(0),selected(1)};
 for(unsigned target=0;target<2;target++)for(unsigned kind=0;kind<3;kind++) {
  unsigned peer=1-target;uint64_t start=wall_ns();
  struct sle_controller_snapshot before=snapshot(observe[target],generations[target]),pb=snapshot(observe[peer],generations[peer]);
  struct sle_discovery_result rb=radio(observe[target],generations[target]);query(observe[target],generations[target],SLE_MANAGEMENT_FREE);
  int writer=selected(target),duplicate=-1,wrong_errno=0;
  struct sle_management_request lease={.version=1,.generation=generations[target],.mode=SLE_MANAGEMENT_MANAGED};
  CHECK(!ioctl(writer,SL_IOCTL_MANAGEMENT_ACQUIRE,&lease)&&lease.lease);
  struct sle_management_query held=query(observe[target],generations[target],SLE_MANAGEMENT_HELD),first={0};
  pause_ms(100);
  if(!kind) {
   struct sle_management_request wrong=lease;wrong.lease++;
   errno=0;CHECK(ioctl(writer,SL_IOCTL_MANAGEMENT_RELEASE,&wrong)==-1&&errno==EPERM);wrong_errno=errno;
   query(observe[target],generations[target],SLE_MANAGEMENT_HELD);
   CHECK(!ioctl(writer,SL_IOCTL_MANAGEMENT_RELEASE,&lease));
  } else if(kind==1) closed(writer);
  else {
   duplicate=dup(writer);CHECK(duplicate>=0);closed(writer);
   first=query(observe[target],generations[target],SLE_MANAGEMENT_HELD);pause_ms(100);
   query(observe[target],generations[target],SLE_MANAGEMENT_HELD);closed(duplicate);
  }
  pause_ms(250);
  struct sle_management_query free=query(observe[target],generations[target],SLE_MANAGEMENT_FREE);
  struct sle_controller_snapshot after=snapshot(observe[target],generations[target]),pa=snapshot(observe[peer],generations[peer]);
  struct sle_discovery_result ra=radio(observe[target],generations[target]);
  query(observe[peer],generations[peer],SLE_MANAGEMENT_FREE);
  CHECK(!memcmp(&before,&after,sizeof(before))&&!memcmp(&pb,&pa,sizeof(pb))&&!memcmp(&rb,&ra,sizeof(rb)));
  uint64_t end=wall_ns();
  printf("{\"case\":\"%s\",\"index\":%u,\"generation\":%llu,\"peer_index\":%u,\"peer_generation\":%llu,\"start_wall_ns\":%llu,\"end_wall_ns\":%llu,\"writer_fd\":%d,\"duplicate_fd\":%d,\"wrong_token_errno\":%d,\"snapshot_before\":",kind==0?"explicit-release":kind==1?"last-fd-close":"dup-last-fd-close",target,(unsigned long long)generations[target],peer,(unsigned long long)generations[peer],(unsigned long long)start,(unsigned long long)end,writer,duplicate,wrong_errno);
  hex(&before,sizeof(before));printf(",\"snapshot_after\":");hex(&after,sizeof(after));printf(",\"peer_before\":");hex(&pb,sizeof(pb));printf(",\"peer_after\":");hex(&pa,sizeof(pa));
  printf(",\"radio_before\":");hex(&rb,sizeof(rb));printf(",\"radio_after\":");hex(&ra,sizeof(ra));printf(",\"held\":");hex(&held,sizeof(held));printf(",\"after_first_close\":");hex(&first,sizeof(first));printf(",\"free\":");hex(&free,sizeof(free));printf("}\n");fflush(stdout);
  if(!kind)closed(writer);
 }
 closed(observe[0]);closed(observe[1]);return 0;
}
