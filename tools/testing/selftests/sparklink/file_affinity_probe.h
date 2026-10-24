/* SPDX-License-Identifier: GPL-2.0-only */
/* Exact current per-File affinity checks retained while old raw ABI retires. */
#ifndef SL_SELFTEST_FILE_AFFINITY_H
#define SL_SELFTEST_FILE_AFFINITY_H
#include <poll.h>
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

#endif
