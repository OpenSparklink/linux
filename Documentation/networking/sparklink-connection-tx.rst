Historical legacy connection submission
=======================================

.. warning::

    The old submission path is not the Native channel socket contract. Check actual unpublished UAPI and current qualification before using any command below.

    Original source: e78b88f050aa98f7e8c83ff12c828eb172968d66. Historical evidence does not qualify the current image.

Legacy connection submission cleanup
====================================

The unpublished CONN_SEND ioctl is a temporary caller of ConnManager::send.
It does not define the final connection data plane. The final design uses one
socket per negotiated logical channel, bound to controller generation, peer,
connection and TCID; SSAP and services belong to userspace.

The former path appended to a depth-64 TX ring with no consumer, then sent the
same payload directly. Queue exhaustion was unrelated to backend capacity;
errors had already advanced sequence, byte counters and activity. The ioctl
resolved handle zero but passed the original zero to the backend.

There is now one submission callback. The per-Runtime protocol mutex covers
validation, backend submission and accounting commit. It resolves the Host
handle, and a command-Host backend requires the learned controller handle.
Missing mapping, closed/non-connected channels, invalid length/MTU and counter
overflow fail before submission. Unsupported reliable framing and segmentation
are rejected: a TCID prefix alone does not implement retransmission or credits.

There is no shadow TX ring or allocation. Legacy tx_pending is zero because
this path has no asynchronous queue. tx_bytes counts payload accepted by the
backend, not peer delivery. Counters, sequence and activity change only after
backend success. An error may follow a partial physical transfer; the kernel
does not automatically retry it or claim that no bytes reached the peer.

The old generic USB sender rejects invalid/oversized payloads and handles,
checks exact USB completion length and preserves errno. This is separate from
the native WS73 HCC/BSLE/discovery transport, which is unchanged and continues
to reject connection data until its real backend is connected.

Development gate::

  python3 tools/testing/selftests/sparklink/run_connection_tx.py

This compiles the actual sender, handle resolver, ioctl and USB function bodies
with explicitly mocked dependencies. Eleven Rust tests cover sustained >64
submissions, backend failures, resolved/mapped handles, lengths, MTU/MPS,
unsupported reliable mode, overflow, retry accounting and independent Runtime
contexts. Actual C USB tests cover allocation failure, transport errno, every
short completion, exact and maximum transfer under ASan/UBSan/LeakSanitizer.
It is not a socket, negotiated protocol, USB hardware or RF qualification.

Existing positive legacy tests and their historical results are retained.
Tests must not count failed backend submissions as successful payload bytes;
full positive connection/SSAP cases need a dedicated test backend and real
controller-handle events. This fix does not qualify those old tests as passing.

Remaining work: bounded per-channel socket queues, real completion semantics,
permissions/generation, reliable transport, segmentation, cancellation/retire,
backpressure and real two-device data exchange. Replace callers and remove
CONN_SEND/RECV afterwards; UAPI has not been released, so no compatibility period
is promised. R03/R10 and the complete connection issues remain open.
