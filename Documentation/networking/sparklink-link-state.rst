SparkLink PHY and encryption state qualification
===============================================

The legacy PHY ioctls (information, MCS, TX power, bandwidth, local MCS
selection, hopping and SINR thresholds) return EOPNOTSUPP. The old local PHY
model was never a hardware snapshot or a matched controller transaction. Its
default values are no longer stored in ControllerState or returned as device
configuration. Unused PHY and empty-parameter encryption command convenience
wrappers have been removed. Canonical opcode definitions are not a claim of
support.

The legacy adapter-global encryption-enable operation also returns
EOPNOTSUPP, including when a test artificially supplies Paired keys. It does
not alter the state, credentials or counters and does not send a command.
Future support requires an authenticated per-connection credential, validated
installation parameters, a generation/connection-bound transaction and a
matching successful hardware terminal event. Backend acceptance alone must
not commit PHY/encryption state. Failure, timeout, cancellation and retirement
must leave the last confirmed state unchanged or explicitly unknown.

Historical MCS/MIMO/default PHY/codec algorithms live only in
tools/testing/selftests/sparklink/phy-model. run_phy_model.py retains model
boundaries and compiles the actual rejection match arm with dependency
fixtures. These are not current standard vectors, hardware PHY tests or
security qualification. Channel-map/hopping helpers still used by the legacy
connection path remain pending connection/socket migration, with no hardware
or conformance claim. The PHY module's old global dead-code suppression has
been removed.

This removes the known premature state-commit behavior. PHY policy, real
encryption installation, authenticated security and complete R09 acceptance
remain open. WS73 discovery has independent versioned state and is retained;
production changes require a new complete kernel build and real-device
VM-only regression before extending previous evidence to the new revision.
