// SPDX-License-Identifier: GPL-2.0-only
/* No transport I/O. Execute only against the experimental kernel in the VM. */
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#define LAB_AF_SPARKLINK 46
int main(void)
{
    int fd, type;
    socklen_t size = sizeof(type);
    errno = 0;
    fd = socket(LAB_AF_SPARKLINK, SOCK_SEQPACKET, 0);
    if (fd >= 0 || errno != EPROTONOSUPPORT) {
        if (fd >= 0) close(fd);
        fprintf(stderr, "unqualified reliable socket accepted or wrong errno %d\n", errno);
        return 1;
    }
    fd = socket(LAB_AF_SPARKLINK, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) { perror("basic socket"); return 1; }
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) || size != sizeof(type) || type != SOCK_DGRAM) {
        close(fd); return 1;
    }
    close(fd);
    puts("SPARKLINK_BASIC_SOCKET_TYPE_PASS DGRAM=accepted SEQPACKET=unsupported");
    return 0;
}
