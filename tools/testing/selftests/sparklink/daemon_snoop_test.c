// SPDX-License-Identifier: GPL-2.0-only
/* Native privileged snoop syscalls and portable captures in the NO-RF guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
_Static_assert(sizeof(struct sle_snoop_record)==376,"snoop record ABI");
_Static_assert(sizeof(struct sle_snoop_query)==408,"snoop query ABI");
_Static_assert(SL_IOCTL_SNOOP_GET==0xc198538eU,"snoop ioctl ABI");
static int fail(const char *why) {fprintf(stderr,"SNOOP_FAILURE: %s errno=%d\n",why,errno);return 1;}
static int bind(const char *path, unsigned long long *generation, unsigned int *index) {
    char tail;
    if (sscanf(path,"/org/sparklink/slk%u_g%llu%c",index,generation,&tail)!=2 || *index>=16 || !*generation) return -1;
    int fd=open("/dev/sparklink",O_RDWR|O_CLOEXEC); short selected=*index;
    if (fd<0 || ioctl(fd,SL_IOCTL_DEV_SELECT,&selected)) {if(fd>=0)close(fd);return -1;}
    return fd;
}
static int record_valid(const struct sle_snoop_record *r, unsigned long long generation,unsigned int index,unsigned long long after) {
    if (r->generation!=generation || r->dev_index!=index || r->seq<=after || r->lost!=r->seq-after-1 || !r->timestamp_ns ||
        r->profile!=1 || r->format!=1 || (r->direction!=1 && r->direction!=2) || r->status>0 ||
        r->captured_length<5 || r->captured_length>320 || r->captured_length!=r->original_length || r->flags || r->reserved ||
        r->payload[0]!=(r->direction==1?0xa2:0xa1) ||
        (unsigned int)(r->payload[3]|(r->payload[4]<<8))!=(unsigned int)r->captured_length-5) return 0;
    for (unsigned int i=r->captured_length;i<320;i++) if(r->payload[i]) return 0;
    return 1;
}
static int contract(const char *path) {
    unsigned long long generation; unsigned int index;
    int a=bind(path,&generation,&index),b=bind(path,&generation,&index),ev=bind(path,&generation,&index);
    if (a<0 || b<0 || ev<0) return fail("bind");
    struct sle_mgmt_stats before,after;
    if(ioctl(a,SL_IOCTL_MGMT_STATS,&before))return fail("before");
    struct sle_snoop_query q={.version=1,.generation=generation},same=q;
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&q) || ioctl(b,SL_IOCTL_SNOOP_GET,&same) ||
        memcmp(&q.record,&same.record,sizeof(q.record)) || !record_valid(&q.record,generation,index,0))return fail("independent identical record");
    struct sle_snoop_query bad={.version=2,.generation=generation};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&bad)!=-1 || errno!=EOPNOTSUPP)return fail("version");
    bad=(struct sle_snoop_query){.version=1,.generation=generation,.flags=1};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&bad)!=-1 || errno!=EINVAL)return fail("flags");
    bad=(struct sle_snoop_query){.version=1,.generation=0};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&bad)!=-1 || errno!=EINVAL)return fail("generation zero");
    bad=(struct sle_snoop_query){.version=1,.generation=generation+100};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&bad)!=-1 || errno!=ENODEV)return fail("stale generation");
    bad=(struct sle_snoop_query){.version=1,.generation=generation,.after_seq=~0ULL};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&bad)!=-1 || errno!=EINVAL)return fail("future cursor");
    struct sle_controller_event_query event={.version=1,.generation=generation};
    if(ioctl(a,SL_IOCTL_CONTROLLER_EVENT_GET,&event)!=-1 || errno!=EBUSY)return fail("snoop/event mixing");
    if(ioctl(ev,SL_IOCTL_CONTROLLER_EVENT_GET,&event)!=-1 || errno!=EAGAIN ||
       ioctl(ev,SL_IOCTL_SNOOP_GET,&same)!=-1 || errno!=EBUSY)return fail("event/snoop mixing");
    for(int n=0;n<64;n++) {
        q.after_seq=q.record.seq;
        if(ioctl(a,SL_IOCTL_SNOOP_GET,&q)) {if(errno!=EAGAIN)return fail("drain");break;}
    }
    struct sle_snoop_query last={.version=1,.generation=generation,.after_seq=q.after_seq-1};
    if(ioctl(b,SL_IOCTL_SNOOP_GET,&last))return fail("last reference");
    long page=sysconf(_SC_PAGESIZE);
    struct sle_snoop_query *readonly=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(readonly==MAP_FAILED)return fail("mmap");
    *readonly=(struct sle_snoop_query){.version=1,.generation=generation,.after_seq=last.record.seq-1};
    if(mprotect(readonly,page,PROT_READ) || ioctl(a,SL_IOCTL_SNOOP_GET,readonly)!=-1 || errno!=EFAULT)return fail("copyout");
    struct pollfd p={.fd=a,.events=POLLIN};
    if(poll(&p,1,0)!=1 || !(p.revents&POLLIN))return fail("EFAULT remains readable");
    q=(struct sle_snoop_query){.version=1,.generation=generation,.after_seq=last.record.seq-1};
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&q) || memcmp(&q.record,&last.record,sizeof(q.record)))return fail("copyout retry");
    munmap(readonly,page);
    pid_t child=fork();if(child<0)return fail("fork");
    if(!child) {
        struct __user_cap_header_struct h={.version=_LINUX_CAPABILITY_VERSION_3};struct __user_cap_data_struct caps[2]={{0}};
        int ok=!setgroups(0,NULL) && !setgid(1001) && !setuid(1001) && !syscall(SYS_capset,&h,caps);
        errno=0;ok&=ioctl(a,SL_IOCTL_SNOOP_GET,NULL)==-1 && errno==EPERM;
        p.revents=0;ok&=poll(&p,1,0)==1 && p.revents==POLLERR;_exit(ok?0:1);
    }
    int status;if(waitpid(child,&status,0)!=child || !WIFEXITED(status) || WEXITSTATUS(status))return fail("inherited capability/poll");
    if(ioctl(a,SL_IOCTL_MGMT_STATS,&after) || memcmp(&before,&after,sizeof(before)))return fail("no command admission");
    printf("SNOOP_CONTRACT: index=%u generation=%llu readers=2 schema=5 copyout=1 mixed=2 inherited_uid1001=1 cap_denied=1 poll_denied=1 no_admission=1\n",index,generation);
    close(a);close(b);close(ev);return 0;
}
static int files(const char *path,const char *left,const char *right) {
    unsigned long long generation;unsigned int index;int fd=bind(path,&generation,&index);if(fd<0)return fail("files bind");
    FILE *a=fopen(left,"rb"),*b=fopen(right,"rb");unsigned char x[16],y[16];
    if(!a || !b || fread(x,1,16,a)!=16 || fread(y,1,16,b)!=16 || memcmp(x,y,16) ||
       memcmp(x,"SLKSNP01\x01\0\0\0\x40\x01\0\0",16))return fail("capture header");
    unsigned long long seq=0,time=0;unsigned int tx=0,rx=0,reports=0;
    for(int n=0;n<32;n++) {
        struct sle_snoop_record r,s;
        if(fread(&r,1,sizeof(r),a)!=sizeof(r) || fread(&s,1,sizeof(s),b)!=sizeof(s) || memcmp(&r,&s,sizeof(r)) ||
           !record_valid(&r,generation,index,seq) || r.lost || r.timestamp_ns<time)return fail("identical complete captures");
        seq=r.seq;time=r.timestamp_ns;tx+=r.direction==2;rx+=r.direction==1;
        reports+=r.direction==1 && r.payload[1]==0x0b && r.payload[2]==0x18;
    }
    if(fgetc(a)!=EOF || fgetc(b)!=EOF || !tx || !rx || !reports)return fail("capture count/directions/report");
    fclose(a);fclose(b);close(fd);
    printf("SNOOP_TOOLS: index=%u generation=%llu records=32 identical=1 tx=1 rx=1 report=1 loss=0\n",index,generation);return 0;
}
static int slow(const char *path) {
    unsigned long long generation;unsigned int index;int a=bind(path,&generation,&index),b=bind(path,&generation,&index);if(a<0 || b<0)return fail("slow bind");
    struct sle_snoop_query q={.version=1,.generation=generation},same=q;
    if(ioctl(a,SL_IOCTL_SNOOP_GET,&q) || ioctl(b,SL_IOCTL_SNOOP_GET,&same) || !q.record.lost ||
       memcmp(&q.record,&same.record,sizeof(q.record)) || !record_valid(&q.record,generation,index,0))return fail("slow loss/reopen");
    printf("SNOOP_SLOW: index=%u generation=%llu lost=%llu reopen=1 independent=1\n",index,generation,q.record.lost);
    close(a);close(b);return 0;
}
static int watch(const char *path) {
    unsigned long long generation; unsigned int index;
    int fd=bind(path,&generation,&index); if(fd<0)return fail("watch bind");
    struct sle_snoop_query q={.version=1,.generation=generation};
    while(!ioctl(fd,SL_IOCTL_SNOOP_GET,&q))q.after_seq=q.record.seq;
    if(errno!=EAGAIN)return fail("watch subscribe");
    printf("SNOOP_ARMED: index=%u generation=%llu\n",index,generation);fflush(stdout);
    for(int n=0;n<64;n++) {
        struct pollfd p={.fd=fd,.events=POLLIN};
        if(poll(&p,1,20000)!=1)return fail("watch wake timeout");
        if(p.revents&(POLLERR|POLLHUP)) {
            if(p.revents!=(POLLERR|POLLHUP) || ioctl(fd,SL_IOCTL_SNOOP_GET,&q)!=-1 || errno!=ENODEV)return fail("retired poll/query");
            printf("SNOOP_RETIRED: index=%u generation=%llu poll=ERR_HUP query=ENODEV\n",index,generation);
            close(fd);return 0;
        }
        while(!ioctl(fd,SL_IOCTL_SNOOP_GET,&q))q.after_seq=q.record.seq;
        if(errno!=EAGAIN && errno!=ENODEV)return fail("watch drain");
    }
    return fail("watch excessive wakes");
}
int main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"contract"))return contract(argv[2]);
    if(argc==3 && !strcmp(argv[1],"slow"))return slow(argv[2]);
    if(argc==3 && !strcmp(argv[1],"watch"))return watch(argv[2]);
    if(argc==5 && !strcmp(argv[1],"files"))return files(argv[2],argv[3],argv[4]);
    return 2;
}
