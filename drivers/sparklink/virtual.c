// SPDX-License-Identifier: GPL-2.0-only
/* Explicit test backend. No synthetic response is linked into another driver.
 * One control File creates one Runtime, dup shares it, final close retires it.
 * Module ownership follows control files and common retained Backend refs.
 */
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/slab.h>
#include <linux/sparklink_backend.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include "virtual.h"
#include "virtual_codec.h"

struct sparklink_virtual {
	refcount_t refs;
	struct mutex lock;
	struct delayed_work reply_work;
	struct sparklink_native_identity identity;
	struct sparklink_native_info info;
	struct sparklink_virtual_control control;
	u64 submitted, delivered, dropped, failed;
	u8 reply[18];
	int reply_length;
	bool live, pending;
};

static void virtual_get(void *context)
{
	refcount_inc(&((struct sparklink_virtual *)context)->refs);
}

static void virtual_put(void *context)
{
	struct sparklink_virtual *v = context;

	if (refcount_dec_and_test(&v->refs))
		kfree(v);
}

static void virtual_deliver(struct work_struct *work)
{
	struct sparklink_virtual *v = container_of(to_delayed_work(work),
						 struct sparklink_virtual, reply_work);
	struct sparklink_native_identity identity;
	u8 reply[18];
	int length;

	mutex_lock(&v->lock);
	if (!v->live || !v->pending) {
		mutex_unlock(&v->lock);
		return;
	}
	identity = v->identity;
	length = v->reply_length;
	memcpy(reply, v->reply, length);
	v->pending = false;
	v->delivered++;
	mutex_unlock(&v->lock);
	/* close joins this call; exact old identity can never target a reused slot.
	 * delivered counts driver callback attempts, not accepted Host replies.
	 */
	sparklink_backend_standard_receive(identity.id, identity.generation,
					    reply, length, 1, 0);
}

static int virtual_open(void *context, u16 id, u64 generation)
{
	struct sparklink_virtual *v = context;
	int ret = 0;

	mutex_lock(&v->lock);
	if (id != v->identity.id || generation != v->identity.generation)
		ret = -ENODEV;
	else
		v->live = true;
	mutex_unlock(&v->lock);
	return ret;
}

static void virtual_close(void *context)
{
	struct sparklink_virtual *v = context;

	mutex_lock(&v->lock);
	v->live = false;
	v->pending = false;
	mutex_unlock(&v->lock);
	/* No mutex held while joining a callback which takes the same mutex. */
	cancel_delayed_work_sync(&v->reply_work);
}

static int virtual_validate(void *context, u16 opcode, const u8 *params, size_t length)
{
	(void)context;
	return sparklink_virtual_validate(opcode, params, length);
}

static int virtual_send(void *context, u16 opcode, const u8 *params, size_t length)
{
	struct sparklink_virtual *v = context;
	int ret = sparklink_virtual_validate(opcode, params, length);

	if (ret)
		return ret;
	mutex_lock(&v->lock);
	if (!v->live) {
		ret = -ENODEV;
		goto out;
	}
	if (v->pending) {
		ret = -EBUSY;
		goto out;
	}
	v->submitted++;
	if (v->control.fail_next) {
		v->control.fail_next--;
		v->failed++;
		ret = -EIO;
		goto out;
	}
	if (v->control.drop_next) {
		v->control.drop_next--;
		v->dropped++;
		ret = 0; /* Submitted, no reply: the real Host deadline must fire. */
		goto out;
	}
	ret = sparklink_virtual_reply(&v->info, opcode, params, length, v->reply);
	if (ret < 0)
		goto out;
	v->reply_length = ret;
	v->pending = true;
	if (!queue_delayed_work(system_wq, &v->reply_work,
				msecs_to_jiffies(v->control.delay_ms))) {
		v->pending = false;
		ret = -EBUSY;
	} else {
		ret = 0;
	}
out:
	mutex_unlock(&v->lock);
	return ret;
}

static const struct sparklink_native_ops virtual_ops = {
	.owner = THIS_MODULE,
	.get = virtual_get, .put = virtual_put,
	.open = virtual_open, .close = virtual_close,
	.validate_command = virtual_validate, .send_command = virtual_send,
};

static int virtual_control_open(struct inode *inode, struct file *file)
{
	struct sparklink_virtual *v;
	struct sparklink_backend_descriptor descriptor;
	struct sparklink_native_identity installed;
	int ret;

	v = kzalloc_obj(*v);
	if (!v)
		return -ENOMEM;
	refcount_set(&v->refs, 1); /* The control File owns the initial reference. */
	mutex_init(&v->lock);
	INIT_DELAYED_WORK(&v->reply_work, virtual_deliver);
	ret = sparklink_backend_reserve(SPARKLINK_BACKEND_TEST,
					SPARKLINK_NATIVE_STANDARD_DLI, &v->identity);
	if (ret)
		goto put;
	v->info.profile = SPARKLINK_NATIVE_STANDARD_DLI;
	v->info.command_credits = 1;
	v->info.version[0] = 0xff; /* Test version, never an SDK/firmware claim. */
	v->info.version[4] = 1;
	v->info.address[0] = 2;
	v->info.address[1] = 0x56;
	v->info.address[2] = 0x49;
	v->info.address[3] = 0x52;
	v->info.address[4] = v->identity.id;
	v->info.address[5] = v->identity.generation;
	descriptor = (struct sparklink_backend_descriptor) {
		.version = SPARKLINK_BACKEND_VERSION, .size = sizeof(descriptor),
		.bus = SPARKLINK_BACKEND_TEST, .info = v->info,
		.ops = &virtual_ops, .context = v,
	};
	ret = sparklink_backend_register_reserved(&descriptor, &v->identity, &installed);
	if (!ret && (installed.id != v->identity.id ||
		     installed.generation != v->identity.generation))
		ret = -EPROTO;
	if (ret) {
		sparklink_native_unregister(v->identity.id, v->identity.generation);
		sparklink_backend_cancel(v->identity.id, v->identity.generation);
		goto put;
	}
	file->private_data = v;
	return 0;
put:
	virtual_put(v);
	return ret;
}

static int virtual_control_release(struct inode *inode, struct file *file)
{
	struct sparklink_virtual *v = file->private_data;

	sparklink_native_unregister(v->identity.id, v->identity.generation);
	virtual_put(v);
	return 0;
}

static long virtual_control_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct sparklink_virtual *v = file->private_data;
	struct sparklink_virtual_control config;
	struct sparklink_virtual_status status = {};
	int ret = 0;

	if (cmd == SPARKLINK_VIRTUAL_STATUS) {
		mutex_lock(&v->lock);
		status = (struct sparklink_virtual_status) {
			.generation = v->identity.generation, .id = v->identity.id,
			.submitted = v->submitted, .delivered = v->delivered,
			.dropped = v->dropped, .failed = v->failed,
			.live = v->live, .pending = v->pending,
		};
		mutex_unlock(&v->lock);
		return copy_to_user((void __user *)arg, &status, sizeof(status)) ? -EFAULT : 0;
	}
	if (cmd != SPARKLINK_VIRTUAL_CONFIG)
		return -ENOTTY;
	if (copy_from_user(&config, (void __user *)arg, sizeof(config)))
		return -EFAULT;
	if (config.reserved || config.delay_ms > 6000 ||
	    config.drop_next > 32 || config.fail_next > 32)
		return -EINVAL;
	mutex_lock(&v->lock);
	if (!v->live)
		ret = -ENODEV;
	else if (v->pending)
		ret = -EBUSY;
	else
		v->control = config;
	mutex_unlock(&v->lock);
	return ret;
}

static const struct file_operations virtual_fops = {
	.owner = THIS_MODULE,
	.open = virtual_control_open, .release = virtual_control_release,
	.unlocked_ioctl = virtual_control_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static struct miscdevice virtual_device = {
	.minor = MISC_DYNAMIC_MINOR, .name = "sparklink_virtual",
	.fops = &virtual_fops, .mode = 0600,
};
module_misc_device(virtual_device);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Explicit per-file SparkLink virtual query/fault test backend");
