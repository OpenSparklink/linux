// SPDX-License-Identifier: GPL-2.0
/* Registry-only observation. No controller selection, management, protocol
 * credit or multicast projection lives here. Requests take no attributes.
 */
#include <linux/module.h>
#include <net/genetlink.h>
#include <uapi/linux/sparklink.h>
extern u32 sparklink_genl_get_dev_count(void);
extern u32 sparklink_genl_get_proto_version(void);
int sparklink_genl_register(void);
void sparklink_genl_unregister(void);
static int sparklink_genl_get_registry_count(struct sk_buff *skb, struct genl_info *info);
static int sparklink_genl_get_version(struct sk_buff *skb, struct genl_info *info);
static const struct genl_small_ops sparklink_genl_ops[] = {
	{ .cmd = SPARKLINK_CMD_GET_REGISTRY_COUNT, .doit = sparklink_genl_get_registry_count },
	{ .cmd = SPARKLINK_CMD_GET_VERSION, .doit = sparklink_genl_get_version },
};
static struct genl_family sparklink_genl_family __ro_after_init = {
	.name = SPARKLINK_GENL_NAME,
	.version = SPARKLINK_GENL_VERSION,
	.module = THIS_MODULE,
	.small_ops = sparklink_genl_ops,
	.n_small_ops = ARRAY_SIZE(sparklink_genl_ops),
	.parallel_ops = true,
};

static int sparklink_genl_get_registry_count(struct sk_buff *skb,
				       struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;
	u32 count;

	if (genlmsg_len(info->genlhdr))
		return -EINVAL;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &sparklink_genl_family, 0,
			  SPARKLINK_CMD_GET_REGISTRY_COUNT);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	count = sparklink_genl_get_dev_count();
	if (nla_put_u32(msg, SPARKLINK_ATTR_DEV_COUNT, count))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return -EMSGSIZE;
}

/* -----------------------------------------------------------------------
 * GET_VERSION handler
 *
 * Returns protocol stack and genetlink interface versions.
 * -----------------------------------------------------------------------
 */
static int sparklink_genl_get_version(struct sk_buff *skb,
				      struct genl_info *info)
{
	struct sk_buff *msg;
	void *hdr;

	if (genlmsg_len(info->genlhdr))
		return -EINVAL;

	msg = genlmsg_new(GENLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &sparklink_genl_family, 0,
			  SPARKLINK_CMD_GET_VERSION);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}

	if (nla_put_u32(msg, SPARKLINK_ATTR_PROTO_VERSION,
			sparklink_genl_get_proto_version()))
		goto nla_put_failure;
	if (nla_put_u32(msg, SPARKLINK_ATTR_GENL_VERSION,
			SPARKLINK_GENL_VERSION))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return genlmsg_reply(msg, info);

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	nlmsg_free(msg);
	return -EMSGSIZE;
}

int sparklink_genl_register(void)
{
	int ret;

	ret = genl_register_family(&sparklink_genl_family);
	if (ret)
		pr_err("sparklink: failed to register genetlink family: %d\n",
		       ret);
	else
		pr_info("sparklink: genetlink family \"%s\" v%d registered\n",
			SPARKLINK_GENL_NAME, SPARKLINK_GENL_VERSION);

	return ret;
}

void sparklink_genl_unregister(void)
{
	genl_unregister_family(&sparklink_genl_family);
	pr_info("sparklink: genetlink family unregistered\n");
}
