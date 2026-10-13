Historical legacy read-copy analysis
====================================

.. warning::

    The production read queue and 44-byte ABI were removed. This page preserves old failure and partial-copy semantics; it does not describe the current ControllerEventGet contract.

    Original source: e78b88f050aa98f7e8c83ff12c828eb172968d66. Historical evidence does not qualify the current image.

SparkLink legacy event record delivery
=====================================

The legacy ``read()`` path delivers fixed-size ``SleWireEvent`` records through
a bounded per-fd queue. It must not consume a record or increase delivery
accounting until ``copy_to_iter`` has copied that entire record. The queue mutex
remains held while copying and committing; producers and concurrent readers of
that fd cannot replace the head during a copy. Other fds have independent queues.

A zero-length read returns zero. A nonzero buffer smaller than one record returns
``EINVAL``; an empty queue with sufficient buffer space returns ``EAGAIN``.
A failed/partial first record returns ``EFAULT``. If previous complete records
were copied, their byte count is returned and the incomplete next record remains
queued. Userspace must ignore bytes beyond the returned count. Explicit bounded
queue overflow remains a separate, counted drop policy; copy failure is not a
drop. This does not provide fault-atomic writes to userspace memory.

There were no callers of the old ``drain_to_buf`` helper; it has been removed.
The only dequeue helper is private and commits complete record delivery. The
same ``copy_records`` implementation is used by the actual miscdevice read
method and by the development boundary tests, rather than a second queue model.

``run_event_copy.py`` compiles the actual complete event module and read method
with explicit copy/lock/init dependencies. See its ``event-copy/README`` for
the nine failure/fan-out/budget tests and their limits. Full kernel compilation
verifies wiring. A fresh VM real-WS73 regression is required after this change;
fixture success cannot establish RF, live VFS faults or device-removal wakeups.

Migration remains open
---------------------

Native WS73 management consumers use independent controller event subscriptions
and typed cursors. The old user ``EventReceiver`` still uses ``DLI_POLL_EVENT``;
that ioctl pops a controller/runtime ring before usercopy, has a direct backend
poll fallback, and is not repaired by changing ``read()``. Its callers and the
legacy event queue/UAPI must migrate or be removed. The ABI is unpublished and
has no promised compatibility period. No complete event-ownership, U2/K3, R12,
natural recovery or overall subsystem acceptance is claimed by this batch.
