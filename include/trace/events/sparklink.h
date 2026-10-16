/* SPDX-License-Identifier: GPL-2.0-only */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sparklink

#if !defined(_TRACE_SPARKLINK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SPARKLINK_H
#include <linux/tracepoint.h>

/* Observations only: a work's planned delay is not proof it was enqueued.
 * epoch belongs to the immutable physical Session, not a new authorization. */
TRACE_EVENT(sparklink_session_work,
	TP_PROTO(u16 controller, u64 generation, u64 lifetime, u64 epoch,
		 u64 service, u8 stage, unsigned int packets, unsigned int bytes,
		 unsigned int stop, u64 elapsed_ns, unsigned long planned_delay, int error),
	TP_ARGS(controller, generation, lifetime, epoch, service, stage, packets,
		bytes, stop, elapsed_ns, planned_delay, error),
	TP_STRUCT__entry(
		__field(u16, controller) __field(u64, generation) __field(u64, lifetime)
		__field(u64, epoch) __field(u64, service) __field(u8, stage)
		__field(unsigned int, packets) __field(unsigned int, bytes)
		__field(unsigned int, stop) __field(u64, elapsed_ns)
		__field(unsigned long, planned_delay) __field(int, error)
	),
	TP_fast_assign(
		__entry->controller = controller; __entry->generation = generation;
		__entry->lifetime = lifetime; __entry->epoch = epoch;
		__entry->service = service; __entry->stage = stage;
		__entry->packets = packets; __entry->bytes = bytes; __entry->stop = stop;
		__entry->elapsed_ns = elapsed_ns; __entry->planned_delay = planned_delay;
		__entry->error = error;
	),
	TP_printk("ctl=%u gen=%llu life=%llu epoch=%llu service=%llu stage=%u attempts=%u bytes=%u stop=%u elapsed_ns=%llu planned_delay=%lu error=%d",
		__entry->controller, __entry->generation, __entry->lifetime, __entry->epoch,
		__entry->service, __entry->stage, __entry->packets, __entry->bytes,
		__entry->stop, __entry->elapsed_ns, __entry->planned_delay, __entry->error)
);

/* Queue stages 0/1/2 are software admission/dequeue/operation retirement,
 * not USB, controller or peer completion. bytes includes the DTAP header. */
TRACE_EVENT(sparklink_session_queue,
	TP_PROTO(u16 controller, u64 generation, u64 lifetime, u64 epoch,
		 u64 sequence, int slot, unsigned int bytes, unsigned long deadline, u8 stage),
	TP_ARGS(controller, generation, lifetime, epoch, sequence, slot, bytes, deadline, stage),
	TP_STRUCT__entry(
		__field(u16, controller) __field(u64, generation) __field(u64, lifetime)
		__field(u64, epoch) __field(u64, sequence) __field(int, slot)
		__field(unsigned int, bytes) __field(unsigned long, deadline) __field(u8, stage)
	),
	TP_fast_assign(
		__entry->controller = controller; __entry->generation = generation;
		__entry->lifetime = lifetime; __entry->epoch = epoch;
		__entry->sequence = sequence; __entry->slot = slot; __entry->bytes = bytes;
		__entry->deadline = deadline; __entry->stage = stage;
	),
	TP_printk("ctl=%u gen=%llu life=%llu epoch=%llu sequence=%llu slot=%d bytes=%u deadline=%lu stage=%u",
		__entry->controller, __entry->generation, __entry->lifetime, __entry->epoch,
		__entry->sequence, __entry->slot, __entry->bytes, __entry->deadline, __entry->stage)
);

/* stage 0: before Native API; 1: after its synchronous result; 2: actual
 * atomic submit callback result. Only stage2/result0 means USB queue accepted;
 * none of them is controller completion, NOCP or peer application delivery.
 * Data sequence is the admission ID; service/epoch join to the work event.
 * Control slot -1 has a separate per-call sequence. IDs wrap as debug counters.
 * No payload, kernel pointers, credentials or keys are emitted. */
TRACE_EVENT(sparklink_session_tx,
	TP_PROTO(u16 controller, u64 generation, u64 lifetime, u64 service,
		 u64 sequence, int slot, unsigned int boundary, unsigned int length,
		 unsigned int offset, int result, u32 wait, u8 stage),
	TP_ARGS(controller, generation, lifetime, service, sequence, slot, boundary,
		length, offset, result, wait, stage),
	TP_STRUCT__entry(
		__field(u16, controller) __field(u64, generation) __field(u64, lifetime)
		__field(u64, service) __field(u64, sequence) __field(int, slot)
		__field(unsigned int, boundary) __field(unsigned int, length)
		__field(unsigned int, offset) __field(int, result)
		__field(u32, wait) __field(u8, stage)
	),
	TP_fast_assign(
		__entry->controller = controller; __entry->generation = generation;
		__entry->lifetime = lifetime; __entry->service = service;
		__entry->sequence = sequence; __entry->slot = slot;
		__entry->boundary = boundary; __entry->length = length;
		__entry->offset = offset; __entry->result = result;
		__entry->wait = wait; __entry->stage = stage;
	),
	TP_printk("ctl=%u gen=%llu life=%llu service=%llu sequence=%llu slot=%d pb=%u len=%u offset=%u result=%d wait=%u stage=%u",
		__entry->controller, __entry->generation, __entry->lifetime,
		__entry->service, __entry->sequence, __entry->slot, __entry->boundary,
		__entry->length, __entry->offset, __entry->result, __entry->wait, __entry->stage)
);
#endif
#include <trace/define_trace.h>
