// SPDX-License-Identifier: GPL-2.0-only
#include "sparklink_socket.h"
#include "sle_message_security.h"
#include "sle_channel_grant.h"
extern struct sparklink_send_constraint nondet_constraint(void);
extern struct sl_grant_scope nondet_scope(void);
extern unsigned long long nondet_ull(void);
extern unsigned int nondet_uint(void);
extern int nondet_int(void);
void verify_send_constraint(void) {
 struct sparklink_send_constraint c=nondet_constraint();
 struct sl_grant_scope scope=nondet_scope();struct sl_channel_grant g={0};
 unsigned long long epoch=nondet_ull(),now=nondet_ull(),bound_epoch=nondet_ull();
 unsigned int floor=nondet_uint(),admit_level=nondet_uint();int level=nondet_int();
 int valid=sl_send_constraint_valid(&c);
 __CPROVER_assert(!valid||(c.version==1&&c.size==48&&c.minimum<=2&&!c.reserved&&c.generation&&c.lifetime&&c.security_epoch&&c.deadline_monotonic_ns),"constraint shape excludes unset scope and deadline");
 int permitted=sl_send_constraint_permits(c.security_epoch,c.minimum,epoch,level);
 __CPROVER_assert(!permitted||(c.security_epoch&&c.security_epoch==epoch&&level>=0&&level<=2&&(unsigned int)level>=c.minimum),"constraint requires original epoch and bounded sufficient mechanism");
 __CPROVER_assert(c.security_epoch==epoch||!permitted,"minimum zero cannot bypass old epoch");
 int timely=sl_send_constraint_timely(c.deadline_monotonic_ns,now);
 __CPROVER_assert(!timely||(c.deadline_monotonic_ns&&now<c.deadline_monotonic_ns),"expired absolute deadline rejects a candidate submit");
 int created=sl_grant_init_security(&g,scope,3,floor,bound_epoch,admit_level);
 int can=created&&valid&&permitted&&timely&&sl_grant_permits(&g,scope,1)&&
  sl_grant_security_permits(&g,epoch,level)&&
  sl_send_constraint_identity(&c,scope.generation,scope.lifetime,scope.controller,scope.handle,scope.local_tcid,scope.remote_tcid,scope.pi);
 __CPROVER_assert(!can||(!floor||(g.security_epoch==epoch&&level>=0&&(unsigned int)level>=floor)),"constraint cannot weaken the original grant floor or epoch");
 __CPROVER_assert(!can||(c.generation==scope.generation&&c.lifetime==scope.lifetime&&c.controller==scope.controller&&c.handle==scope.handle&&c.local_tcid==scope.local_tcid&&c.remote_tcid==scope.remote_tcid&&c.pi==scope.pi),"foreign lifetime or channel cannot obtain submission consent");
}
void empty_check(void) {__CPROVER_assert(1,"empty inventory is not proof");}
