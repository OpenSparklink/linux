// SPDX-License-Identifier: GPL-2.0
#include "sle_irq_lock.h"

/* Keep macro-dependent raw spinlock layout and IRQ flags on the C side. */
void sle_irq_lock_init(raw_spinlock_t *lock, const char *name,
		       void *key)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	__raw_spin_lock_init(lock, name, (struct lock_class_key *)key, LD_WAIT_SPIN);
#else
	(void)name;
	(void)key;
	raw_spin_lock_init(lock);
#endif
}

unsigned long sle_irq_lock(raw_spinlock_t *lock)
{
	unsigned long flags;

	raw_spin_lock_irqsave(lock, flags);
	return flags;
}

int sle_irq_trylock(raw_spinlock_t *lock, unsigned long *flags)
{
	return raw_spin_trylock_irqsave(lock, *flags);
}

void sle_irq_unlock(raw_spinlock_t *lock, unsigned long flags)
{
	raw_spin_unlock_irqrestore(lock, flags);
}

void sle_irq_assert_held(raw_spinlock_t *lock)
{
	(void)lock;
	lockdep_assert_held(lock);
}
