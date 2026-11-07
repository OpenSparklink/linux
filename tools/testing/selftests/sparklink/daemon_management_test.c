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
#include <time.h>

static double now(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) exit(1);
    return t.tv_sec + t.tv_nsec / 1e9;
}


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
        struct sle_diagnostic_submit cmd = { .version = 1, .generation = generation,
            .request_id = 1, .timeout_ms = 5000, .opcode = 0x0406, .action = 1 };
        if (ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &claim) ||
            ioctl(fd, SL_IOCTL_DIAGNOSTIC_SUBMIT, &cmd) || !cmd.seq) {
            perror("typed diagnostic seed admission"); return 1;
        }
        double deadline = now() + 5;
        struct sle_diagnostic_result result;
        do {
            result = (struct sle_diagnostic_result){ .version = 1, .generation = generation, .seq = cmd.seq };
            if (ioctl(fd, SL_IOCTL_DIAGNOSTIC_RESULT, &result)) return 1;
            if (result.state != 1) break;
            usleep(1000);
        } while (now() < deadline);
        if (result.state != 2 || result.error || result.status || result.opcode != 0x0406 ||
            result.seq != cmd.seq || result.generation != generation || result.data_len != 6 ||
            memcmp(result.data, controller.address, 6) ||
            ioctl(fd, SL_IOCTL_MANAGEMENT_RELEASE, &claim)) return 1;
        /* The completed result is retained under its author, never a shared
         * event to drain. A different current Diagnostic owner cannot read it. */
        int other = open("/dev/sparklink", O_RDWR | O_CLOEXEC);
        struct sle_management_request next = { .version = 1, .generation = generation,
            .mode = SLE_MANAGEMENT_DIAGNOSTIC };
        if (other < 0 || ioctl(other, SL_IOCTL_DEV_SELECT, &selected) ||
            ioctl(other, SL_IOCTL_MANAGEMENT_ACQUIRE, &next)) return 1;
        result = (struct sle_diagnostic_result){ .version = 1, .generation = generation, .seq = cmd.seq };
        struct sle_diagnostic_result unchanged = result;
        if (ioctl(other, SL_IOCTL_DIAGNOSTIC_RESULT, &result) != -1 || errno != EPERM ||
            memcmp(&result, &unchanged, sizeof(result)) ||
            ioctl(other, SL_IOCTL_MANAGEMENT_RELEASE, &next)) return 1;
        close(other);
        printf("TOOL_DIAGNOSTIC_SEED: index=%u generation=%llu typed_complete=1 previous_author=EPERM\n", index, generation);
        close(fd); return 0;
    }
    printf("DAEMON_MANAGEMENT_OBSERVE: index=%u generation=%llu state=%s token_hidden=1 adv=%u scan=%u\n",
           index, generation, argv[2], radio.radio_adv, radio.radio_scan);
    close(fd);
    return 0;
}
