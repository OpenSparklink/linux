// SPDX-License-Identifier: GPL-2.0-only
/* Passive VM syscall rejection; no injection, firmware or service actions. */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"
/* Real per-File binding: no implicit default, dup shares clear/rebind. */
static int explicit_affinity_probe(int selected_fd)
{
    uint16_t id = UINT16_MAX, unset = 0;
    struct sle_controller_snapshot selected = { .version = 1 };
    if (ioctl(selected_fd, SL_IOCTL_DEV_GET_ACTIVE, &id) || id >= 16 ||
        ioctl(selected_fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &selected)) return 1;
    int fd = open("/dev/sparklink", O_RDWR);
    if (fd < 0) return 1;
    int alias = -1, rc = 1, stage = 1;
    struct sle_controller_snapshot query = { .version = 1 }, before = query;
    if (ioctl(fd, SL_IOCTL_DEV_GET_ACTIVE, &unset) || unset != UINT16_MAX) goto done;
    stage = 2; errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &query) != -1 || errno != EINVAL ||
        memcmp(&query, &before, sizeof(query))) goto done;
    stage = 3;
    struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
    if (poll(&poll_fd, 1, 0) != 1 || !(poll_fd.revents & POLLERR)) goto done;
    stage = 4;
    int16_t index = id;
    if (ioctl(fd, SL_IOCTL_DEV_SELECT, &index)) goto done;
    query = before;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &query) || query.generation != selected.generation) goto done;
    stage = 5; alias = dup(fd);
    if (alias < 0) goto done;
    index = -1;
    if (ioctl(alias, SL_IOCTL_DEV_SELECT, &index) || ioctl(fd, SL_IOCTL_DEV_GET_ACTIVE, &unset) || unset != UINT16_MAX) goto done;
    stage = 6; query = before; errno = 0;
    if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &query) != -1 || errno != EINVAL ||
        memcmp(&query, &before, sizeof(query))) goto done;
    stage = 7;
    /* Another open File on this controller is unaffected by dup's clear. */
    query = before;
    if (ioctl(selected_fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &query) || query.generation != selected.generation) goto done;
    index = id;
    if (ioctl(alias, SL_IOCTL_DEV_SELECT, &index)) goto done;
    stage = 8; index = -2; errno = 0;
    if (ioctl(fd, SL_IOCTL_DEV_SELECT, &index) != -1 || errno != EINVAL) goto done;
    stage = 9; if (close(fd)) goto done;
    fd = -1; query = before;
    if (ioctl(alias, SL_IOCTL_CONTROLLER_SNAPSHOT, &query) || query.generation != selected.generation) goto done;
    rc = 0;
done:
    if (rc) fprintf(stderr, "EXPLICIT_AFFINITY_FAIL: uid=%u stage=%d errno=%d\n", getuid(), stage, errno);
    if (alias >= 0) close(alias);
    if (fd >= 0) close(fd);
    return rc;
}

static int protocol_state_probe(int fd) {
    if (explicit_affinity_probe(fd)) return 1;
    const struct { unsigned long cmd; int observe; } cases[] = {
    { SL_IOCTL_AFH_CLASSIFY, 0 },
    { SL_IOCTL_AFH_GET_MAP, 1 },
    { SL_IOCTL_AFH_HOP_NEXT, 0 },
    { SL_IOCTL_AFH_REPORT_RETX, 0 },
    { SL_IOCTL_AFH_REPORT_RSSI, 0 },
    { SL_IOCTL_AFH_SET_MAP, 0 },
    { SL_IOCTL_CLEAR_SCAN_FILTER, 0 },
    { SL_IOCTL_CONNECT, 0 },
    { SL_IOCTL_CONN_COUNT, 1 },
    { SL_IOCTL_CONN_INFO, 1 },
    { SL_IOCTL_CONN_LIST, 1 },
    { SL_IOCTL_CONN_PHY_UPDATE, 0 },
    { SL_IOCTL_CONN_READ_PEER_FEATURES, 0 },
    { SL_IOCTL_CONN_READ_PEER_VERSION, 0 },
    { SL_IOCTL_CONN_RECV, 0 },
    { SL_IOCTL_CONN_SEND, 0 },
    { SL_IOCTL_CONN_UPDATE_PARAMS, 0 },
    { SL_IOCTL_DEV_SWITCH, 0 },
    { SL_IOCTL_DISCONNECT, 0 },
    { SL_IOCTL_DLI_INFO, 1 },
    { SL_IOCTL_DLI_RESET, 0 },
    { SL_IOCTL_EXT_ADV_CONFIGURE, 0 },
    { SL_IOCTL_EXT_ADV_DISABLE, 0 },
    { SL_IOCTL_EXT_ADV_ENABLE, 0 },
    { SL_IOCTL_EXT_ADV_ENABLE_EX, 0 },
    { SL_IOCTL_EXT_ADV_INFO, 1 },
    { SL_IOCTL_EXT_ADV_REMOVE, 0 },
    { SL_IOCTL_EXT_ADV_SET_DATA, 0 },
    { SL_IOCTL_EXT_ADV_SET_SCAN_RSP, 0 },
    { SL_IOCTL_EXT_ADV_TICK, 0 },
    { SL_IOCTL_GET_ROLE, 1 },
    { SL_IOCTL_INJECT_CONN_DATA, 0 },
    { SL_IOCTL_INJECT_CONN_RESP, 0 },
    { SL_IOCTL_RAL_ADD, 0 },
    { SL_IOCTL_RAL_CLEAR, 0 },
    { SL_IOCTL_RAL_READ_LOCAL_RPA, 0 },
    { SL_IOCTL_RAL_READ_PEER_RPA, 0 },
    { SL_IOCTL_RAL_REMOVE, 0 },
    { SL_IOCTL_RAL_SIZE, 1 },
    { SL_IOCTL_RPA_ENABLE, 0 },
    { SL_IOCTL_RPA_SET_TIMEOUT, 0 },
    { SL_IOCTL_SCAN_RESULT_COUNT, 1 },
    { SL_IOCTL_SEC_CONFIRM_PASSKEY, 0 },
    { SL_IOCTL_SEC_ENCRYPT_ON, 0 },
    { SL_IOCTL_SEC_GET_PASSKEY, 0 },
    { SL_IOCTL_SEC_HMAC_TEST, 1 },
    { SL_IOCTL_SEC_INFO, 1 },
    { SL_IOCTL_SEC_INPUT_PASSKEY, 0 },
    { SL_IOCTL_SEC_PAIR, 0 },
    { SL_IOCTL_SEC_REJECT_PASSKEY, 0 },
    { SL_IOCTL_SEC_RESET, 0 },
    { SL_IOCTL_SEC_SET_OOB, 0 },
    { SL_IOCTL_SEC_SET_PASSWORD, 0 },
    { SL_IOCTL_SEC_SET_PSK, 0 },
    { SL_IOCTL_SEC_SM3_TEST, 1 },
    { SL_IOCTL_SEC_SM4_BLOCK_TEST, 1 },
    { SL_IOCTL_SEC_SM4_DEC_TEST, 1 },
    { SL_IOCTL_SEC_SM4_ENC_TEST, 1 },
    { SL_IOCTL_SET_CONN_MTU, 0 },
    { SL_IOCTL_SET_ROLE, 0 },
    { SL_IOCTL_SET_SCAN_FILTER, 0 },
    { SL_IOCTL_START_ADV, 0 },
    { SL_IOCTL_START_SCAN, 0 },
    { SL_IOCTL_STOP_ADV, 0 },
    { SL_IOCTL_STOP_SCAN, 0 },
    { SL_IOCTL_SYNC_DATAPATH_CFG, 0 },
    { SL_IOCTL_SYNC_DATAPATH_REMOVE, 0 },
    { SL_IOCTL_SYNC_DATA_SEND, 0 },
    { SL_IOCTL_SYNC_INFO, 1 },
    { SL_IOCTL_SYNC_MCAST_ACCEPT, 0 },
    { SL_IOCTL_SYNC_MCAST_CREATE, 0 },
    { SL_IOCTL_SYNC_MCAST_PARAM, 0 },
    { SL_IOCTL_SYNC_MCAST_REJECT, 0 },
    { SL_IOCTL_SYNC_MCAST_REMOVE, 0 },
    { SL_IOCTL_SYNC_UCAST_ACCEPT, 0 },
    { SL_IOCTL_SYNC_UCAST_CREATE, 0 },
    { SL_IOCTL_SYNC_UCAST_PARAM, 0 },
    { SL_IOCTL_SYNC_UCAST_REJECT, 0 },
    { SL_IOCTL_SYNC_UCAST_REMOVE, 0 },
    };
    unsigned count=sizeof(cases)/sizeof(cases[0]);
    for (unsigned i=0;i<count;i++) {
        unsigned char data[512], original[512];memset(data,0xa5,sizeof(data));memcpy(original,data,sizeof(data));
        if (ioctl(fd,cases[i].cmd,data)!=-1 || errno != (getuid() && !cases[i].observe ? EPERM:EOPNOTSUPP) || memcmp(data,original,sizeof(data))) {
            fprintf(stderr,"PROTOCOL_STATE_REFUSAL_FAIL: uid=%u case=%u cmd=%lx errno=%d\n",getuid(),i,cases[i].cmd,errno);return 1;
        }
    }
    unsigned char data[36];memset(data,0xa5,sizeof(data));
    if(ioctl(fd,_IOR(SL_MAGIC,0x86,unsigned char[36]),data)!=-1 || errno!=ENOTTY)return 1;
    for(unsigned i=0;i<sizeof(data);i++)if(data[i]!=0xa5)return 1;
    printf("PROTOCOL_STATE_REFUSAL_PASS: uid=%u cases=%u unchanged=%u mixed_stats=ENOTTY\n",getuid(),count,count);return 0;
}
#ifndef PROTOCOL_STATE_EMBEDDED
int main(int argc, char **argv)
{
    char *end;
    if (argc != 2) return 2;
    long id = strtol(argv[1], &end, 10);
    if (*end || id < 0 || id > 15) return 2;
    int fd = open("/dev/sparklink", O_RDWR);
    if (fd < 0) return 1;
    int16_t index = id;
    if (ioctl(fd, SL_IOCTL_DEV_SELECT, &index)) { close(fd); return 1; }
    int rc = protocol_state_probe(fd);
    close(fd);
    return rc;
}
#endif
