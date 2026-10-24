# Session timer, owner and work reference model

This model is limited to two independent Session objects and the references owned
by Runtime/table or its stop action, queued/running work, and one notification.
Additional fd, actor and binding references are outside its ledger; its cleanup
property concerns only this projection, not actual final Session destruction.

| Model | Production mapping |
| --- | --- |
| `owner` | constructor reference adopted by `ControllerRuntime.sessions`, or the detached `Action::Retire`; `Action::Stop` clones a ref across stop/join |
| `Arm` | positive-delay `sl_schedule` under the Session lock, `hrtimer_start` of the embedded timer; timer borrows parent ownership |
| `TimerBegin/Hint/Done` | kernel invokes `sl_deadline_wake`, which only calls locked `sl_connection_session_kick` and returns NORESTART |
| `NotifyBegin/Hint/Done` | temporary pointer reference in `notify_session_data`, then the same C kick and put |
| `pending/running` | one ordered delayed-work object, now queued only with delay zero; each invocation owns one kref, including requeue during execution |
| `Close` | `sl_connection_session_stop` closes progress and bindings under the Session lock |
| `JoinTimer` | `hrtimer_cancel` outside the Session lock, before work join and parent drop |
| `JoinWork` | `cancel_delayed_work_sync`, canceling a pending reference or waiting for running work |
| `DropOwner` | Runtime's stopped/retired table entry or action may release its constructor/temporary owner after stop returns |

The Session lock linearizes closed admission and the callback's kick. Worker and
notification references remain independent from the timer's borrowed owner.
Unpublished candidates never start work; last application fd closure does not
drop the physical Session table reference. Actual generation/lifetime are
immutable fields of each object; this model has no handle-reuse or raw RX routing.

The trusted basis is Linux hrtimer/workqueue/kref/spinlock contracts, the embedded
container mapping and the audited Rust parent ownership. These APIs are not
proved here. Actions may interleave between callback entry, kick and return,
between Runtime notification and put, and during worker execution and stop.
Weak fairness assumes invoked callbacks, notifications, workers and stop joins
can eventually return. There is no unconditional bounded scheduling or I/O
progress claim. `CleanupConverges` only applies after Close, under that fairness.

The positive configuration checks six safety invariants and conditional cleanup
liveness over the full finite reachable state graph. The negative configuration
intentionally omits the callback join condition; it must produce a
`NoFreeWhileLive` counterexample. It does not report a production counterexample.
The corresponding implementation regression checks source stop order and late
closed callbacks; actual C functions are also checked with explicit API fixtures
and 20-step CBMC. Neither is a full C refinement or running-kernel race proof.

`run_session_wake_tlc.py --output NEW_DIRECTORY` retains exact model/config/source
hashes, commands, tool banner, raw terminal output, state counts and negative
trace. A timeout, unsupported feature, missing property, incomplete graph or
unexpected diagnostic stays UNPROVED. VM regression still checks original
application deadlines and real queues; no model replaces USB/peer/hardware data.
