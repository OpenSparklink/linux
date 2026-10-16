// SPDX-License-Identifier: GPL-2.0-only
/* Included after actual production enqueue bodies and explicit Linux API fixtures. */
extern unsigned int nondet_uint(void);
void verify_wake_sequences(void) {
 struct sl_connection_session s = { .refs = 1 };
 owner = &s;
 unsigned int initial = nondet_uint(); __CPROVER_assume(initial < 5);
 if (initial == 1 || initial == 2) sl_channel_start(&s.progress,2042,2047);
 if (initial == 2) {
  sl_channel_request_submitted(&s.progress,0);
  sl_channel_peer_capability(&s.progress,2042,2047,0);
  sl_channel_response_submitted(&s.progress,0);
 }
 if (initial == 3) sl_channel_start(&s.progress,0,0);
 if (initial == 4) sl_channel_close(&s.progress);
 for (unsigned int i = 0; i < 20; i++) {
  unsigned int op = nondet_uint(); __CPROVER_assume(op < 6);
  switch (op) {
   case 0: sl_connection_session_kick(&s); break;
   case 1: sl_schedule(&s); break;
   case 2: if (s.work.pending && !s.work.running) begin(&s); break;
   case 3: if (s.work.running) finish(&s); break;
   case 4: stop(&s); break;
   case 5: sl_connection_session_kick(&s);sl_connection_session_kick(&s);break;
  }
  __CPROVER_assert(s.refs == 1U+(unsigned)s.work.pending+(unsigned)s.work.running,"one reference per queued/running invocation");
  __CPROVER_assert(sl_channel_active(s.progress) || !s.work.pending,"closed rejects new queue");
  __CPROVER_assert(!s.work.pending || s.work.delay<=10,"event never postponed beyond fallback");
 }
 stop(&s); if (s.work.running) finish(&s);
 __CPROVER_assert(s.refs==1&&!s.work.pending&&!s.work.running,"close/cancel/finish settle queue refs");
}
