/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _SLE_CHANNEL_GRANT_H
#define _SLE_CHANNEL_GRANT_H
/* Production immutable fd grant. Runtime Host validates the active lease;
 * this scope/direction check runs under Session lock before each data action.
 * Security facts are read from the sole physical Session while Host is locked.
 * A frozen receipt epoch is not named identity, durable trust or Bond.
 */
#define SL_GRANT_TX 1U
#define SL_GRANT_RX 2U
struct sl_grant_scope {
	unsigned long long generation, lifetime, epoch;
	unsigned int controller, handle, local_tcid, remote_tcid, pi;
};
struct sl_channel_grant {
	struct sl_grant_scope scope;
	unsigned int directions, security;
	unsigned long long security_epoch;
};
static inline int sl_grant_scope_valid(struct sl_grant_scope s)
{
	return s.generation && s.lifetime && s.epoch && s.controller <= 65535 &&
		s.handle <= 65535 && s.local_tcid <= 255 && s.remote_tcid <= 255 && s.pi <= 255;
}
static inline int sl_grant_init_security(struct sl_channel_grant *grant,
					 struct sl_grant_scope scope,
					 unsigned int directions,
					 unsigned int security,
					 unsigned long long epoch,
					 unsigned int level)
{
	if (!sl_grant_scope_valid(scope) || !directions ||
	    (directions & ~(SL_GRANT_TX | SL_GRANT_RX)) || security > 2 ||
	    (security && (!epoch || level < security || level > 2)))
		return 0;
	*grant = (struct sl_channel_grant){ .scope = scope,
					    .directions = directions,
					    .security = security,
					    .security_epoch = security ? epoch :
									 0 };
	return 1;
}
static inline int sl_grant_init(struct sl_channel_grant *grant,
				struct sl_grant_scope scope,
				unsigned int directions, unsigned int security)
{
	return sl_grant_init_security(grant, scope, directions, security, 0, 0);
}
static inline int
sl_grant_security_permits(const struct sl_channel_grant *grant,
			  unsigned long long epoch, unsigned int level)
{
	return grant->security <= 2 &&
	       (!grant->security ||
		(grant->security_epoch && grant->security_epoch == epoch &&
		 level >= grant->security && level <= 2));
}
static inline int sl_grant_permits(const struct sl_channel_grant *grant,
				  struct sl_grant_scope observed_scope, unsigned int direction)
{
	struct sl_grant_scope s = grant->scope;
	return sl_grant_scope_valid(s) && grant->security <= 2 &&
	       (!grant->security || grant->security_epoch) &&
	       (direction == SL_GRANT_TX || direction == SL_GRANT_RX) &&
	       !(grant->directions & ~(SL_GRANT_TX | SL_GRANT_RX)) &&
	       (grant->directions & direction) &&
	       s.controller == observed_scope.controller &&
	       s.generation == observed_scope.generation &&
	       s.lifetime == observed_scope.lifetime &&
	       s.epoch == observed_scope.epoch &&
	       s.handle == observed_scope.handle &&
	       s.local_tcid == observed_scope.local_tcid &&
	       s.remote_tcid == observed_scope.remote_tcid &&
	       s.pi == observed_scope.pi;
}
#endif
