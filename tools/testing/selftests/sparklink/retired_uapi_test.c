// SPDX-License-Identifier: GPL-2.0-only
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/* Passive VM-only syscall retirement and unchanged current file-affinity gates. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
#include "retired_ioctl_cases.h"
#include "file_affinity_probe.h"

static int retired_uapi_probe(int fd)
{
    if (explicit_affinity_probe(fd)) return 1;
    unsigned char buffer[1024], before[sizeof(buffer)];
    unsigned int count=0, checks=0;
    for (unsigned int i=0;i<sizeof(sl_test_retired_commands)/sizeof(sl_test_retired_commands[0]);i++) {
        memset(buffer,0xa5,sizeof(buffer)); memcpy(before,buffer,sizeof(buffer));
        /* Invalid kernel user addresses are valid syscall inputs,not C FFI UB.
         * A retired command must fail before copying or checking an owner. */
        void *arguments[]={buffer,NULL,(void *)(uintptr_t)1};
        for (unsigned int j=0;j<3;j++) {
            errno=0;
            if (ioctl(fd,sl_test_retired_commands[i],arguments[j])!=-1 || errno!=ENOTTY ||
                memcmp(buffer,before,sizeof(buffer))) {
                fprintf(stderr,"RETIRED_UAPI_FAIL uid=%u command=%08x argument=%u errno=%d\n",getuid(),sl_test_retired_commands[i],j,errno);
                return 1;
            }
            checks++;
        }
        count++;
    }
    struct sle_mgmt_stats stats={0},before_stats=stats;
    errno=0;
    if (ioctl(fd,SL_IOCTL_MGMT_STATS ^ (1U << _IOC_SIZESHIFT),&stats)!=-1 ||
        errno!=ENOTTY || memcmp(&stats,&before_stats,sizeof(stats))) return 1;
    printf("RETIRED_UAPI_ENOTTY_PASS: uid=%u cases=%u unchanged=%u checks=%u invalid_user_address=1 mixed_stats=ENOTTY\n",getuid(),count,count,checks);
    return 0;
}
#ifndef RETIRED_UAPI_EMBEDDED
int main(int argc,char **argv)
{
    char *end=NULL;long index;
    if (argc!=2 || (index=strtol(argv[1],&end,10))<0 || index>=16 || !end || *end) return 2;
    int fd=open("/dev/sparklink",O_RDWR|O_CLOEXEC);if(fd<0) return 1;
    int16_t selected=index;
    int result=ioctl(fd,SL_IOCTL_DEV_SELECT,&selected) ? 1 : retired_uapi_probe(fd);
    close(fd);return result;
}
#endif
