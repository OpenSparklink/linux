// SPDX-License-Identifier: GPL-2.0-only
/* Guest-only blocking native callback fixture. No USB, firmware or RF. */
#include <linux/atomic.h>
#include <linux/completion.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sparklink_native.h>
#include <linux/uaccess.h>
#include "native_open_fixture.h"

#define FIXTURE_SLOTS 8
struct fixture {
	struct completion entered, release, registered, retired;
	struct task_struct *registration, *retirement;
	struct sparklink_native_identity identity;
	atomic_t gets, puts, closes, sends;
	u32 mode;
	int result;
};
static struct fixture fixtures[FIXTURE_SLOTS];
static DEFINE_MUTEX(control_lock);

static void fixture_get(void *context)
{
	atomic_inc(&((struct fixture *)context)->gets);
}

static void fixture_put(void *context)
{
	atomic_inc(&((struct fixture *)context)->puts);
}

static int fixture_open(void *context, u16 id, u64 generation)
{
	struct fixture *f = context;

	f->identity.id = id;
	f->identity.generation = generation;
	complete_all(&f->entered);
	/* Bound a failed test. Userspace releases after its observations. */
	if (!wait_for_completion_timeout(&f->release, msecs_to_jiffies(10000)))
		return -ETIMEDOUT;
	return f->mode == 1 ? -EIO : 0;
}

static void fixture_close(void *context)
{
	atomic_inc(&((struct fixture *)context)->closes);
}

static int fixture_validate(void *context, u16 opcode, const u8 *params,
			    size_t length)
{
	return -EOPNOTSUPP;
}

static int fixture_send(void *context, u16 opcode, const u8 *params, size_t length)
{
	atomic_inc(&((struct fixture *)context)->sends);
	return -EOPNOTSUPP;
}

static const struct sparklink_native_ops fixture_ops = {
	.owner = THIS_MODULE,
	.get = fixture_get,
	.put = fixture_put,
	.open = fixture_open,
	.close = fixture_close,
	.validate_command = fixture_validate,
	.send_command = fixture_send,
};

static int fixture_register(void *context)
{
	struct fixture *f = context;
	struct sparklink_native_identity output = {};
	struct sparklink_native_info info = {
		.profile = SPARKLINK_NATIVE_WS73_HCC,
		.version = { 1, 2, 3, 4, 5 },
		.features = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 },
		.address = { 2, 0x4f, 0x50, 0x45, 0x4e, 1 },
		.command_credits = 1,
	};

	info.address[5] += f - fixtures;
	WRITE_ONCE(f->result, sparklink_native_register(&info, &fixture_ops, f, &output));
	if (!f->result && (output.id != f->identity.id ||
			   output.generation != f->identity.generation))
		WRITE_ONCE(f->result, -EPROTO);
	complete_all(&f->registered);
	while (!kthread_should_stop())
		schedule_timeout_interruptible(HZ);
	return 0;
}

static int fixture_retire(void *context)
{
	struct fixture *f = context;

	sparklink_native_unregister(f->identity.id, f->identity.generation);
	complete_all(&f->retired);
	while (!kthread_should_stop())
		schedule_timeout_interruptible(HZ);
	return 0;
}

static long fixture_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct native_open_probe probe;
	struct fixture *f;
	long result = 0;

	if (copy_from_user(&probe, (void __user *)arg, sizeof(probe)))
		return -EFAULT;
	if (probe.slot >= FIXTURE_SLOTS || probe.mode > 2 || probe.reserved)
		return -EINVAL;
	mutex_lock(&control_lock);
	f = &fixtures[probe.slot];
	switch (cmd) {
	case NATIVE_OPEN_START:
		if (f->registration) {
			result = -EBUSY;
			break;
		}
		f->mode = probe.mode;
		if (f->mode == 2)
			complete_all(&f->release);
		f->registration = kthread_run(fixture_register, f, "sl-open-%u", probe.slot);
		if (IS_ERR(f->registration)) {
			result = PTR_ERR(f->registration);
			f->registration = NULL;
		}
		break;
	case NATIVE_OPEN_RELEASE:
		if (!completion_done(&f->entered)) {
			result = -EAGAIN;
			break;
		}
		complete_all(&f->release);
		break;
	case NATIVE_OPEN_RETIRE:
		if (!completion_done(&f->entered) || f->retirement) {
			result = -EINVAL;
			break;
		}
		f->retirement = kthread_run(fixture_retire, f, "sl-retire-%u", probe.slot);
		if (IS_ERR(f->retirement)) {
			result = PTR_ERR(f->retirement);
			f->retirement = NULL;
		}
		break;
	case NATIVE_OPEN_STALE:
		if (!completion_done(&f->retired)) {
			result = -EINVAL;
			break;
		}
		sparklink_native_unregister(f->identity.id, f->identity.generation);
		break;
	case NATIVE_OPEN_QUERY:
		break;
	default:
		result = -ENOTTY;
	}
	probe.flags = (completion_done(&f->entered) ? 1 : 0) |
		(completion_done(&f->release) ? 2 : 0) |
		(completion_done(&f->registered) ? 4 : 0) |
		(f->retirement ? 8 : 0) | (completion_done(&f->retired) ? 16 : 0);
	probe.id = probe.flags & 1 ? f->identity.id : U16_MAX;
	probe.generation = probe.flags & 1 ? f->identity.generation : 0;
	probe.result = READ_ONCE(f->result);
	probe.gets = atomic_read(&f->gets);
	probe.puts = atomic_read(&f->puts);
	probe.closes = atomic_read(&f->closes);
	probe.sends = atomic_read(&f->sends);
	mutex_unlock(&control_lock);
	if (!result && copy_to_user((void __user *)arg, &probe, sizeof(probe)))
		return -EFAULT;
	return result;
}

static const struct file_operations fixture_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = fixture_ioctl,
};
static struct miscdevice fixture_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "sparklink-native-open-test",
	.fops = &fixture_fops,
	.mode = 0600,
};

static int __init fixture_init(void)
{
	int i;

	for (i = 0; i < FIXTURE_SLOTS; i++) {
		init_completion(&fixtures[i].entered);
		init_completion(&fixtures[i].release);
		init_completion(&fixtures[i].registered);
		init_completion(&fixtures[i].retired);
	}
	return misc_register(&fixture_device);
}

static void __exit fixture_exit(void)
{
	int i;

	/* Retained transports pin THIS_MODULE; tests retire them before unload. */
	misc_deregister(&fixture_device);
	for (i = 0; i < FIXTURE_SLOTS; i++) {
		if (fixtures[i].registration)
			kthread_stop(fixtures[i].registration);
		if (fixtures[i].retirement)
			kthread_stop(fixtures[i].retirement);
	}
}
module_init(fixture_init);
module_exit(fixture_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Guest-only SparkLink blocking native open lifecycle fixture");
