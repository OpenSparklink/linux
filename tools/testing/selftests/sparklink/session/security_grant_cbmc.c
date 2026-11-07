// SPDX-License-Identifier: GPL-2.0-only
/* Direct production pure C Grant checks. The provided observed level/revision
 * are inputs, not a model of Owner/Host/USB/credits, policy or cryptography. */
#include "sle_channel_grant.h"
extern unsigned int nondet_uint(void);
extern unsigned long long nondet_ull(void);
void verify_grant_policy(void) {
 struct sl_grant_scope scope={nondet_ull(),nondet_ull(),nondet_ull(),nondet_uint(),nondet_uint(),nondet_uint(),nondet_uint(),nondet_uint()};
 unsigned int directions=nondet_uint(),required=nondet_uint(),level=nondet_uint();
 unsigned long long epoch=nondet_ull(),current=nondet_ull();
 struct sl_channel_grant grant={.security=99,.security_epoch=777};
 int initialized=sl_grant_init_security(&grant,scope,directions,required,epoch,level);
 if (!initialized) {
  __CPROVER_assert(grant.security==99&&grant.security_epoch==777,"failed mint leaves grant unchanged");
 } else {
  __CPROVER_assert(directions&&!(directions&~3U)&&required<=2,"only supported requirements and directions mint");
  __CPROVER_assert(!required||(epoch&&level>=required&&level<=2),"protected mint requires actual sufficient facts");
  __CPROVER_assert(sl_grant_permits(&grant,scope,directions&1U?1U:2U),"minted exact scope permits granted direction");
  if (required) {
   __CPROVER_assert(!sl_grant_security_permits(&grant,current,level)||current==epoch,"old security epoch never authorizes current submit");
   __CPROVER_assert(!sl_grant_security_permits(&grant,epoch,0),"no protected authorization without current mechanism");
  }
  struct sl_grant_scope other=scope;
  unsigned int field=nondet_uint();__CPROVER_assume(field<8);
  switch(field){case 0:other.generation^=1;break;case 1:other.lifetime^=1;break;case 2:other.epoch^=1;break;
   case 3:other.controller^=1;break;case 4:other.handle^=1;break;case 5:other.local_tcid^=1;break;
   case 6:other.remote_tcid^=1;break;case 7:other.pi^=1;break;}
  __CPROVER_assert(!sl_grant_permits(&grant,other,1)&&!sl_grant_permits(&grant,other,2),"foreign lifetime lease or channel cannot use grant");
 }
}
void empty_check(void) {__CPROVER_assert(1,"only an empty control, not the required proof");}
