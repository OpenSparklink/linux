/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_MESSAGE_SECURITY_H
#define _SLE_MESSAGE_SECURITY_H
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
