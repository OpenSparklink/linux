// SPDX-License-Identifier: GPL-2.0-only
/* Native API fixture plus a synthetic WS73 survivor; never physical evidence. */
#define main ws73_native_lifecycle_main
#include "ws73_native_runtime_test.c"
#undef main
#include "native-open/native_open_fixture.h"

static int control;
static int retained[4] = { -1, -1, -1, -1 };
static struct native_open_probe retired[4];

static int fixture(unsigned long operation, struct native_open_probe *p)
{
	return ioctl(control, operation, p) ? fail("fixture ioctl") : 0;
}

static int fixture_wait(struct native_open_probe *p, unsigned int flags)
{
	double deadline = now() + 4;

	do {
		if (fixture(NATIVE_OPEN_QUERY, p))
			return -1;
		if ((p->flags & flags) == flags)
			return 0;
		usleep(1000);
	} while (now() < deadline);
	return fail("fixture state deadline");
}

static int fixture_bind(const struct native_open_probe *p)
{
	int fd = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	uint16_t id = p->id;

	if (fd < 0 || ioctl(fd, SL_IOCTL_DEV_SELECT, &id))
		return fail("select fixture Runtime");
	return fd;
}

static int fixture_snapshot(int fd, const struct native_open_probe *p)
{
	struct sle_controller_snapshot s = { .version = 1, .generation = p->generation };

	if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &s) ||
	    s.dev_index != p->id || s.generation != p->generation ||
	    s.profile != 1 || s.flags != SLE_CONTROLLER_SETUP || s.error ||
	    s.valid_fields != 1 || s.command_credits != 1 || s.acb_length || s.icb_length ||
	    s.acb_count || s.icb_count ||
	    memcmp(s.version_tuple, "\1\2\3\4\5", 5) ||
	    memcmp(s.address, "\2\117\120\105\116", 5) || s.address[5] != 1 + p->slot ||
	    memcmp(s.features, "\1\2\3\4\5\6\7\10\11\12", 10))
		return fail("fixture SETUP snapshot");
	return 0;
}

static int opening_observe(int fd, struct native_open_probe *p)
{
	struct sle_management_request request = { .version = 1,
		.generation = p->generation, .mode = SLE_MANAGEMENT_DIAGNOSTIC };
	struct sle_management_query q = { .version = 1, .generation = p->generation };
	double begin = now();

	int snapshot_result = fixture_snapshot(fd, p);
	double elapsed = now() - begin;
	printf("NATIVE_OPEN_SNAPSHOT: slot=%u elapsed_ms=%.3f\n", p->slot, elapsed * 1000);
	if (snapshot_result)
		return -1;
	if (elapsed >= 0.2)
		return fail("open held Runtime snapshot mutex");
	for (unsigned int i = 0; i < 10; i++) {
		if (ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &request) != -1 || errno != EAGAIN || request.lease)
			return fail("opening lease counter or premature admission");
	}
	struct sle_dli_cmd raw = { .opcode = 0x0403 };
	if (ioctl(fd, SL_IOCTL_DLI_SEND_CMD, &raw) != -1 || errno != EPERM ||
	    ioctl(fd, SL_IOCTL_MANAGEMENT_QUERY, &q) || q.state != SLE_MANAGEMENT_FREE ||
	    q.lease || q.flags || q.error || fixture(NATIVE_OPEN_QUERY, p) ||
	    p->flags != 1 || p->gets != 1 || p->puts || p->closes || p->sends)
		return fail("opening admission or transport lifetime");
	printf("NATIVE_OPEN_PENDING: slot=%u id=%u generation=%llu snapshot_ms=%.3f lease_eagain=1 refs=1 sends=0\n",
	       p->slot, p->id, (unsigned long long)p->generation, elapsed * 1000);
	return 0;
}

static int retire_wait(int fd, struct native_open_probe *p, int during_open)
{
	if (fixture(NATIVE_OPEN_RETIRE, p))
		return -1;
	double deadline = now() + 2;
	while (now() < deadline) {
		struct sle_controller_snapshot s = { .version = 1, .generation = p->generation };
		if (ioctl(fd, SL_IOCTL_CONTROLLER_SNAPSHOT, &s) == -1 && errno == ENODEV)
			break;
		usleep(1000);
	}
	if (now() >= deadline)
		return fail("retirement did not close admission before joining open");
	if (during_open) {
		if (fixture(NATIVE_OPEN_QUERY, p) || p->flags != 9 || p->puts || p->closes || p->sends)
			return fail("teardown failed to join open");
		printf("NATIVE_OPEN_RETIRING: slot=%u blocked=1 admission_closed=1 close=0 put=0\n", p->slot);
	} else if (fixture_wait(p, 16)) {
		return -1;
	}
	return 0;
}

static int one_case(unsigned int slot, unsigned int mode, int retire_during,
		    int survivor, const struct sci_dev_info *survivor_info)
{
	struct native_open_probe p = { .slot = slot, .mode = mode };

	if (fixture(NATIVE_OPEN_START, &p) || fixture_wait(&p, 1))
		return -1;
	int fd = fixture_bind(&p);
	for (unsigned int old = 0; old < slot; old++) {
		if (fixture(NATIVE_OPEN_STALE, &retired[old]) || stale(retained[old]))
			return fail("stale identity affected reused index during open");
	}
	if (fd < 0 || opening_observe(fd, &p) || query(survivor, survivor_info, 0x0403, 0))
		return -1;
	struct native_open_probe replacement = { .slot = slot + 4, .mode = 2 };
	int fresh = -1;
	if (retire_during) {
		if (retire_wait(fd, &p, 1) ||
		    fixture(NATIVE_OPEN_START, &replacement) || fixture_wait(&replacement, 5))
			return -1;
		fresh = fixture_bind(&replacement);
		if (fresh < 0 || replacement.result || replacement.id == p.id ||
		    fixture_snapshot(fresh, &replacement))
			return fail("opening retirement released reserved index too early");
	}
	if (fixture(NATIVE_OPEN_RELEASE, &p) || fixture_wait(&p, 4))
		return -1;
	if (!mode && !retire_during) {
		struct sle_management_request claim = { .version = 1, .generation = p.generation,
			.mode = SLE_MANAGEMENT_DIAGNOSTIC };
		if (p.result || fixture_snapshot(fd, &p) ||
		    ioctl(fd, SL_IOCTL_MANAGEMENT_ACQUIRE, &claim) || claim.lease != 1 ||
		    ioctl(fd, SL_IOCTL_MANAGEMENT_RELEASE, &claim) || retire_wait(fd, &p, 0))
			return fail("successful open first lease or retirement");
	} else {
		if (p.result != (mode ? -EIO : -ENODEV))
			return fail("late native open result");
		if (retire_during && fixture_wait(&p, 16))
			return -1;
	}
	if (fixture(NATIVE_OPEN_QUERY, &p) || p.gets != 1 || p.puts != 1 ||
	    p.closes != (mode ? 0U : 1U) || p.sends || stale(fd))
		return fail("open close/reference exactly once");
	if (retire_during) {
		if (fixture(NATIVE_OPEN_STALE, &p) || fixture_snapshot(fresh, &replacement) ||
		    retire_wait(fresh, &replacement, 0) || fixture(NATIVE_OPEN_QUERY, &replacement) ||
		    replacement.closes != 1 || replacement.puts != 1 || replacement.sends)
			return fail("stale unregister or replacement lifecycle");
		close(fresh);
	}
	if (query(survivor, survivor_info, 0x0403, 0))
		return -1;
	if (!(p.flags & 16) && (fixture(NATIVE_OPEN_RETIRE, &p) || fixture_wait(&p, 16)))
		return -1;
	printf("NATIVE_OPEN_CASE: slot=%u mode=%u retiring=%u result=%d close=%u get=1 put=1 sends=0 survivor=1 stale=1\n",
	       slot, mode, retire_during, p.result, p.closes);
	retained[slot] = fd;
	retired[slot] = p;
	return 0;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	control = open("/dev/sparklink-native-open-test", O_RDWR);
	int probe = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	if (control < 0 || probe < 0 || mask_wait(probe, 1))
		return 1;
	struct sci_dev_info info;
	unsigned long long generation;
	int survivor = bind_owner(0, &info, &generation);
	if (survivor < 0)
		return 1;
	for (unsigned int slot = 0; slot < 4; slot++)
		if (one_case(slot, slot & 1, slot >= 2, survivor, &info) || same(survivor, &info, generation))
			return 1;
	if (exercise(survivor, &info))
		return 1;
	for (unsigned int i = 0; i < 4; i++) {
		if (stale(retained[i]))
			return 1;
		close(retained[i]);
	}
	close(survivor);
	close(probe);
	close(control);
	puts("NATIVE_OPEN_LIFECYCLE: PASS synthetic_only=1 cases=4");
	return failed;
}
