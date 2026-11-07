// SPDX-License-Identifier: GPL-2.0-only
/* Kernel-origin usercopy fault gate in an isolated guest. No hardware/RF. */
#define main ws73_native_open_main
#include "ws73_native_open_test.c"
#undef main
#include <linux/userfaultfd.h>
#include <pthread.h>
#include <stdatomic.h>

struct rpc_job {
	int fd;
	unsigned long operation;
	void *buffer;
	int result, error;
	atomic_int tid, done;
};

static void *rpc_thread(void *pointer)
{
	struct rpc_job *job = pointer;

	atomic_store(&job->tid, syscall(SYS_gettid));
	errno = 0;
	job->result = ioctl(job->fd, job->operation, job->buffer);
	job->error = errno;
	atomic_store(&job->done, 1);
	return NULL;
}

static int start_rpc(pthread_t *thread, struct rpc_job *job)
{
	atomic_init(&job->tid, 0);
	atomic_init(&job->done, 0);
	return pthread_create(thread, NULL, rpc_thread, job) ? fail("RPC thread") : 0;
}

static int job_wait(struct rpc_job *job, double seconds)
{
	double deadline = now() + seconds;

	while (now() < deadline) {
		if (atomic_load(&job->done)) return 0;
		usleep(1000);
	}
	return -1;
}

static int arm_observers(struct native_open_probe *p, int readers[2])
{
	int epoll = epoll_create1(EPOLL_CLOEXEC);
	if (epoll < 0) return fail("fault observer epoll");
	for (unsigned int i = 0; i < 2; i++) {
		readers[i] = fixture_bind(p);
		if (readers[i] < 0) return -1;
		if (!i) {
			if (events_subscribe(readers[i], p->generation)) return -1;
		} else {
			struct sle_snoop_query q = { .version = 1, .generation = p->generation };
			if (ioctl(readers[i], SL_IOCTL_SNOOP_GET, &q) != -1 || errno != EAGAIN)
				return fail("fault empty snoop");
		}
		struct epoll_event e = { .events = EPOLLIN | EPOLLET, .data.u32 = i };
		if (epoll_ctl(epoll, EPOLL_CTL_ADD, readers[i], &e)) return fail("fault epoll arm");
	}
	struct epoll_event e[2];
	if (epoll_wait(epoll, e, 2, 0)) return fail("fault epoll initially ready");
	return epoll;
}

static int query_valid(struct sle_management_query *q, unsigned long long gen)
{
	return q->version == 1 && q->generation == gen && q->state == SLE_MANAGEMENT_FREE &&
	       !q->lease && !q->mode && !q->flags && !q->error && !q->status && !q->opcode && !q->reserved;
}

static int fault_case(unsigned int slot, int acquire, int survivor,
		      const struct sci_dev_info *survivor_info)
{
	const char *mode = acquire ? "acquire" : "query";
	struct native_open_probe p = { .slot = slot, .mode = 2 };
	int bad = 0;
	if (fixture(NATIVE_OPEN_START, &p) || fixture_wait(&p, 5) || p.result) return -1;
	int observer = fixture_bind(&p), fd = fixture_bind(&p), readers[2];
	int epoll = arm_observers(&p, readers);
	if (observer < 0 || fd < 0 || epoll < 0) return -1;
	long page_size = sysconf(_SC_PAGESIZE);
	void *page = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) return fail("RPC fault page");
	if (acquire) {
		*(struct sle_management_request *)page = (struct sle_management_request){
			.version = 1, .generation = p.generation, .mode = SLE_MANAGEMENT_DIAGNOSTIC };
	} else {
		*(struct sle_management_query *)page = (struct sle_management_query){
			.version = 1, .generation = p.generation };
	}
	int uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	struct uffdio_api api = { .api = UFFD_API,
		.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP | UFFD_FEATURE_THREAD_ID };
	struct uffdio_register region = { .range = { .start = (uintptr_t)page, .len = page_size },
		.mode = UFFDIO_REGISTER_MODE_WP };
	struct uffdio_writeprotect wp = { .range = region.range, .mode = UFFDIO_WRITEPROTECT_MODE_WP };
	if (uffd < 0 || ioctl(uffd, UFFDIO_API, &api) || ioctl(uffd, UFFDIO_REGISTER, &region) ||
	    ioctl(uffd, UFFDIO_WRITEPROTECT, &wp)) return fail("kernel-origin userfaultfd WP setup");
	struct rpc_job job = { .fd = fd, .buffer = page, .operation = acquire ?
		SL_IOCTL_MANAGEMENT_ACQUIRE : SL_IOCTL_MANAGEMENT_QUERY };
	pthread_t worker;
	if (start_rpc(&worker, &job)) return -1;
	struct pollfd fault_poll = { .fd = uffd, .events = POLLIN };
	struct uffd_msg message;
	if (poll(&fault_poll, 1, 2000) != 1 || read(uffd, &message, sizeof(message)) != (ssize_t)sizeof(message) ||
	    message.event != UFFD_EVENT_PAGEFAULT ||
	    (message.arg.pagefault.address & ~(page_size - 1)) != (uintptr_t)page ||
	    message.arg.pagefault.flags != (UFFD_PAGEFAULT_FLAG_WRITE | UFFD_PAGEFAULT_FLAG_WP) ||
	    message.arg.pagefault.feat.ptid != (unsigned int)atomic_load(&job.tid) || atomic_load(&job.done))
		return fail("actual ioctl kernel usercopy WP barrier");
	printf("RPC_FAULT_ARMED: mode=%s id=%u generation=%llu kernel_wp=1 thread=1 epoll_empty=1\n",
	       mode, p.id, (unsigned long long)p.generation);
	struct sle_management_query other = { .version = 1, .generation = p.generation };
	struct rpc_job other_job = { .fd = observer, .buffer = &other, .operation = SL_IOCTL_MANAGEMENT_QUERY };
	pthread_t other_thread;
	if (!acquire) {
		double began = now();
		if (start_rpc(&other_thread, &other_job)) return -1;
		if (job_wait(&other_job, 0.2)) {
			printf("RPC_FAULT_QUERY_BLOCKED: elapsed_ms=%.3f\n", (now() - began) * 1000);
			bad = 1;
		} else {
			if (other_job.result || !query_valid(&other, p.generation)) return fail("parallel query snapshot");
			printf("RPC_FAULT_QUERY: elapsed_ms=%.3f free=1 copy_blocked=1\n", (now() - began) * 1000);
		}
	}
	if (query(survivor, survivor_info, 0x0403, 0)) return -1;
	double began = now();
	if (fixture(NATIVE_OPEN_RETIRE, &p)) return -1;
	unsigned int seen = 0;
	while (seen != 3 && now() - began < 0.2) {
		struct epoll_event e[2];
		int count = epoll_wait(epoll, e, 2, 200);
		if (count < 0) return fail("RPC fault observer wait");
		for (int i = 0; i < count; i++) {
			unsigned int type = e[i].data.u32;
			if (type > 1 || (seen & (1U << type)) || e[i].events != (EPOLLERR | EPOLLHUP))
				return fail("RPC fault observer mask/identity");
			seen |= 1U << type;
		}
	}
	double elapsed = now() - began;
	if (seen != 3 || elapsed >= 0.2) {
		printf("RPC_FAULT_WAKE_TIMEOUT: mode=%s elapsed_ms=%.3f copy_blocked=1\n", mode, elapsed * 1000);
		bad = 1;
	} else {
		printf("RPC_FAULT_WAKE: mode=%s elapsed_ms=%.3f event_hup=1 snoop_hup=1 copy_blocked=1\n",
		       mode, elapsed * 1000);
	}
	if (atomic_load(&job.done)) return fail("usercopy unexpectedly resolved before release");
	if (!bad && !acquire && fixture_wait(&p, 16)) return -1;
	if (fixture(NATIVE_OPEN_QUERY, &p)) return -1;
	if (!bad && (p.gets != 1 || p.puts != (acquire ? 0U : 1U) ||
		     p.closes != (acquire ? 0U : 1U) || p.sends ||
		     p.flags != (acquire ? 15U : 31U))) return fail("retirement usercopy lifecycle");
	wp.mode = 0;
	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) || job_wait(&job, 2) || pthread_join(worker, NULL))
		return fail("release kernel-origin usercopy");
	if (!acquire && (job_wait(&other_job, 2) || pthread_join(other_thread, NULL))) return fail("join parallel query");
	if (fixture_wait(&p, 16) || p.gets != 1 || p.puts != 1 || p.closes != 1 || p.sends)
		return fail("RPC fault exact teardown");
	if (acquire) {
		if (job.result != -1 || job.error != ENODEV) {
			printf("RPC_FAULT_LATE_LEASE: result=%d error=%d\n", job.result, job.error);
			bad = 1;
		}
	} else if (job.result || !query_valid(page, p.generation)) {
		return fail("query must retain its pre-retirement snapshot");
	}
	if (stale(fd) || stale(observer)) return -1;
	struct native_open_probe next = { .slot = slot + 4, .mode = 2 };
	if (fixture(NATIVE_OPEN_START, &next) || fixture_wait(&next, 5) || next.result ||
	    next.id != p.id || next.generation <= p.generation) return fail("RPC fault index reuse");
	int replacement = fixture_bind(&next);
	struct sle_management_request claim = { .version = 1, .generation = next.generation,
		.mode = SLE_MANAGEMENT_DIAGNOSTIC };
	if (replacement < 0 || fixture(NATIVE_OPEN_STALE, &p) || fixture_snapshot(replacement, &next) ||
	    ioctl(replacement, SL_IOCTL_MANAGEMENT_ACQUIRE, &claim) || claim.lease != 1 ||
	    ioctl(replacement, SL_IOCTL_MANAGEMENT_RELEASE, &claim) ||
	    retire_wait(replacement, &next, 0) || stale(fd)) return fail("RPC fault replacement lease/old owner");
	if (query(survivor, survivor_info, 0x0403, 0)) return -1;
	if (!bad) printf("RPC_FAULT_CASE: mode=%s copy_release=1 result=%s get=1 put=1 close=1 sends=0 old_fd=ENODEV new_lease=1 survivor=1\n",
			mode, acquire ? "ENODEV" : "snapshot");
	close(replacement);
	for (unsigned int i = 0; i < 2; i++) close(readers[i]);
	close(epoll); close(observer); close(fd); close(uffd);
	munmap(page, page_size);
	return bad;
}

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	control = open("/dev/sparklink-native-open-test", O_RDWR);
	int probe = open("/dev/sparklink", O_RDWR | O_NONBLOCK);
	struct sci_dev_info info;
	unsigned long long generation;
	if (control < 0 || probe < 0 || mask_wait(probe, 1)) return 1;
	int survivor = bind_owner(0, &info, &generation);
	if (survivor < 0) return 1;
	int query_failed = fault_case(0, 0, survivor, &info);
	int acquire_failed = fault_case(1, 1, survivor, &info);
	if (query_failed || acquire_failed || same(survivor, &info, generation) || exercise(survivor, &info)) return 1;
	close(survivor); close(probe); close(control);
	puts("RPC_FAULT_LIFECYCLE: PASS synthetic_only=1 cases=2");
	return failed;
}
