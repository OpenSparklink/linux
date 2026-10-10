// SPDX-License-Identifier: GPL-2.0-only
/* Observer of actual daemon ownership and radio cleanup in the NO-RF guest. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "../../../../include/uapi/linux/sparklink_ioctl.h"

int main(int argc, char **argv)
{
    unsigned int index;
    unsigned long long generation;
    char tail;
    if (argc != 4 || sscanf(argv[1], "/org/sparklink/slk%u_g%llu%c", &index, &generation, &tail) != 2 ||
        index >= 16 || !generation || (strcmp(argv[2], "held") && strcmp(argv[2], "free") && strcmp(argv[2], "seed")))
        return 2;
    int fd = open("/dev/sparklink", O_RDWR | O_CLOEXEC);
    short selected = index;
    if (fd < 0 || ioctl(fd, SL_IOCTL_DEV_SELECT, &selected)) {
        perror("management observer select"); return 1;
    }
    struct sle_management_query q = { .version = 1, .generation = generation };
    struct sle_discovery_result radio = { .version = 1, .generation = generation };
    struct sle_controller_snapshot controller = { .version = 1, .generation = generation };
    unsigned int expected_adv = !strcmp(argv[3], "advertising") ? 2 : 1;
    unsigned int expected_scan = !strcmp(argv[3], "scanning") ? 2 : 1;
    if (strcmp(argv[3], "advertising") && strcmp(argv[3], "scanning") && strcmp(argv[3], "off")) return 2;
    if (ioctl(fd, SL_IOCTL_MANAGEMENT_QUERY, &q) || ioctl(fd, SL_IOCTL_DISCOVERY_RESULT, &radio) ||
        ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &controller)) {
        perror("management observer query"); return 1;
    }
    unsigned int expected = !strcmp(argv[2], "held") ? SLE_MANAGEMENT_HELD : SLE_MANAGEMENT_FREE;
    if (q.state != expected || q.lease || q.flags || q.error || q.status || q.opcode ||
        q.mode != (expected == SLE_MANAGEMENT_HELD ? SLE_MANAGEMENT_MANAGED : 0) ||
        radio.radio_adv != expected_adv || radio.radio_scan != expected_scan ||
        controller.flags != SLE_CONTROLLER_READY || controller.error || controller.profile != 1 ||
        controller.dev_index != index || controller.generation != generation) {
        fprintf(stderr, "management observer state=%u mode=%u flags=%u error=%d adv=%u scan=%u\n",
                q.state, q.mode, q.flags, q.error, radio.radio_adv, radio.radio_scan);
        return 1;
    }
    if (!strcmp(argv[2], "seed")) {
        struct sle_management_request claim = { .version = 1, .generation = generation, .mode = SLE_MANAGEMENT_DIAGNOSTIC };
        struct sle_dli_cmd cmd = { .opcode = 0x0406, .param_len = 1 };
        if (ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &claim)) {
            perror("diagnostic seed"); return 1;
        }
        /* Establish a controlled empty baseline after previous typed recipes. */
        int drained=0;
        for (;;) {
            struct sle_dli_event old={0};
            if (ioctl(fd, SL_IOCTL_DLI_POLL_EVENT, &old)) {
                if (errno==EAGAIN) break;
                perror("diagnostic seed drain"); return 1;
            }
            if (++drained>256) return 1;
        }
        if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &cmd)) { perror("diagnostic seed send"); return 1; }
        int quiet = 0;
        for (int n=0; n<600; n++) {
            struct sle_mgmt_stats stats = {0};
            if (ioctl(fd, SL_IOCTL_MGMT_STATS, &stats)) return 1;
            if (!stats.pending) { quiet=1; break; }
            usleep(10000);
        }
        if (!quiet || ioctl(fd, SL_IOCTL_MANAGEMENT_RELEASE, &claim)) return 1;
        /* Deliberately leave the completed MAC reply unread across handoff. */
        printf("TOOL_DIAGNOSTIC_SEED: index=%u generation=%llu baseline_empty=1 unread_query=1\n",index,generation);
        close(fd); return 0;
    }
    printf("DAEMON_MANAGEMENT_OBSERVE: index=%u generation=%llu state=%s token_hidden=1 adv=%u scan=%u\n",
           index, generation, argv[2], radio.radio_adv, radio.radio_scan);
    close(fd);
    return 0;
}
