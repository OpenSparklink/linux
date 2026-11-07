/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _SPARKLINK_IRQ_LOCK_H
#define _SPARKLINK_IRQ_LOCK_H

#include <linux/spinlock.h>

void sle_irq_lock_init(raw_spinlock_t *lock, const char *name,
		       void *key);
unsigned long sle_irq_lock(raw_spinlock_t *lock);
int sle_irq_trylock(raw_spinlock_t *lock, unsigned long *flags);
void sle_irq_unlock(raw_spinlock_t *lock, unsigned long flags);
void sle_irq_assert_held(raw_spinlock_t *lock);

#endif
