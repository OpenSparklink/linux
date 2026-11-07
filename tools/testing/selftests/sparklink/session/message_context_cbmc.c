// SPDX-License-Identifier: GPL-2.0-only
#include "sparklink_socket.h"
#include "sle_message_security.h"
extern unsigned long long nondet_ull(void);
extern int nondet_int(void);
void verify_message_receipt(void) {
 unsigned long long epoch=nondet_ull(),arrival=nondet_ull(),now=nondet_ull();
 int before=nondet_int(),after=nondet_int();
 struct sparklink_message_security m={.security_epoch=epoch,.security=99,.flags=255};
 sl_message_receipt_observe(&m,arrival,before);
 __CPROVER_assert(!m.flags||(epoch&&epoch==arrival&&before>=0&&before<=2),"known receipt requires matching original epoch and bounded Owner observation");
 __CPROVER_assert(m.flags||!m.security,"unknown receipt has no asserted grade");
 unsigned int saved=m.security;unsigned long long saved_epoch=m.security_epoch;
 unsigned char flags=sl_message_receipt_dequeue_flags(&m,now,after);
 __CPROVER_assert(m.security==saved&&m.security_epoch==saved_epoch,"dequeue cannot upgrade historical grade or epoch");
 __CPROVER_assert(!(flags&2)||((flags&1)&&epoch&&epoch==now&&after>=0&&after<=2&&(unsigned int)after>=saved),"current receipt needs same epoch and sufficient live mechanism");
 __CPROVER_assert(epoch==now||!(flags&2),"old receipt never obtains current qualification");
}
void empty_check(void) {__CPROVER_assert(1,"empty inventory is not proof");}
