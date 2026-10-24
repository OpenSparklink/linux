/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_MESSAGE_SECURITY_H
#define _SLE_MESSAGE_SECURITY_H
static inline int
sl_send_constraint_valid(const struct sparklink_send_constraint *c)
{
	return c->version == SPARKLINK_SEND_CONSTRAINT_VERSION &&
	       c->size == sizeof(*c) && c->minimum <= 2 && !c->reserved &&
	       c->generation && c->lifetime && c->security_epoch &&
	       c->deadline_monotonic_ns;
}
static inline int sl_send_constraint_identity(
	const struct sparklink_send_constraint *c,
	unsigned long long generation, unsigned long long lifetime,
	unsigned int controller, unsigned int handle, unsigned int local,
	unsigned int remote, unsigned int pi)
{
	return c->generation == generation && c->lifetime == lifetime &&
	       c->controller == controller && c->handle == handle &&
	       c->local_tcid == local && c->remote_tcid == remote &&
	       c->pi == pi;
}
static inline int sl_send_constraint_permits(unsigned long long epoch,
					     unsigned int minimum,
					     unsigned long long revision,
					     int level)
{
	return epoch && epoch == revision && minimum <= 2 && level >= 0 &&
	       level <= 2 && (unsigned int)level >= minimum;
}
static inline int sl_send_constraint_timely(unsigned long long deadline,
					    unsigned long long now)
{
	return deadline && now < deadline;
}
/* Actual pure receipt transitions; the caller supplies Owner observations
 * under Runtime admission. These helpers neither query nor mint authority. */
static inline void
sl_message_receipt_observe(struct sparklink_message_security *m,
			   unsigned long long current_revision, int level)
{
	if (m->security_epoch && m->security_epoch == current_revision &&
	    level >= 0 && level <= 2) {
		m->security = level;
		m->flags = SPARKLINK_MESSAGE_SECURITY_KNOWN;
	} else {
		m->security = 0;
		m->flags = 0;
	}
}
static inline unsigned char
sl_message_receipt_dequeue_flags(const struct sparklink_message_security *m,
				 unsigned long long current_revision, int level)
{
	unsigned char flags = m->flags & SPARKLINK_MESSAGE_SECURITY_KNOWN;
	if (flags && m->security_epoch &&
	    m->security_epoch == current_revision && level >= 0 && level <= 2 &&
	    (unsigned int)level >= m->security)
		flags |= SPARKLINK_MESSAGE_SECURITY_CURRENT;
	return flags;
}
#endif
