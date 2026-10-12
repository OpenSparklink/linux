# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := sparklink_test ws73_bsle_test ws73_dli_test ws73_discovery_test
TEST_GEN_PROGS += ws73_recovery_test
TEST_GEN_PROGS += ws73_acb_test
TEST_GEN_PROGS += sle_channel_wire_test
TEST_GEN_PROGS += sle_channel_state_test
TEST_GEN_PROGS_EXTENDED += ssap_removed_uapi_test sparklink_socket_type_test
TEST_GEN_PROGS_EXTENDED += sparklink_runtime_test ws73_native_runtime_test sparklink_host_plan_test sparklink_discovery_operation_test
TEST_GEN_PROGS_EXTENDED += ws73_native_tx_fault_test
TEST_GEN_PROGS_EXTENDED += ws73_native_open_test
TEST_GEN_PROGS_EXTENDED += ws73_native_rpc_fault_test
TEST_GEN_PROGS_EXTENDED += sparklink_event_copy_test
TEST_GEN_PROGS_EXTENDED += sparklink_diagnostic_result_test
TEST_GEN_PROGS_EXTENDED += sparklink_setup_release_test

TEST_PROGS := run_qemu_test.sh run_security_remediation.py run_backend_containment.py
TEST_PROGS += run_connection_tx.py run_ssap_containment.py run_native_connection_contract.py
TEST_PROGS += run_event_copy.py
TEST_PROGS += run_phy_model.py
TEST_PROGS += run_diagnostic_result.py
TEST_PROGS += run_management_release.py run_link_observation.py
TEST_PROGS += run_native_data.py run_native_ticket_driver.py
TEST_PROGS += run_usb_firmware.py
TEST_PROGS += run_usb_discovery.py

include ../lib.mk

$(OUTPUT)/sle_channel_state_test: sle_channel_state_test.c ../../../../net/sparklink/sle_channel_state.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/sle_channel_wire_test: sle_channel_wire_test.c ../../../../net/sparklink/sle_channel_wire.c ../../../../net/sparklink/sle_channel_wire.h
	$(CC) $(CFLAGS) $< ../../../../net/sparklink/sle_channel_wire.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_acb_test: ws73_acb_test.c ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/wire.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_recovery_test: ws73_recovery_test.c ../../../../drivers/sparklink/ws73/recovery.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_tx_fault_test: ws73_native_tx_fault_test.c ws73_native_runtime_test.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_open_test: ws73_native_open_test.c ws73_native_runtime_test.c native-open/native_open_fixture.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_rpc_fault_test: ws73_native_rpc_fault_test.c ws73_native_open_test.c ws73_native_runtime_test.c native-open/native_open_fixture.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -pthread -o $@

RUSTC ?= rustc
$(OUTPUT)/sparklink_host_plan_test: sparklink_host_plan_test.rs \
	../../../../net/sparklink/sle_command_plan.rs \
	../../../../net/sparklink/sle_command_queue.rs
	$(RUSTC) --edition=2021 --test -D warnings $< -o $@

$(OUTPUT)/sparklink_discovery_operation_test: sparklink_discovery_operation_test.rs \
	../../../../net/sparklink/sle_command_plan.rs \
	../../../../net/sparklink/sle_discovery_operation.rs
	$(RUSTC) --edition=2021 --test -D warnings $< -o $@

$(OUTPUT)/ws73_discovery_test: ws73_discovery_test.c \
	../../../../drivers/sparklink/ws73/discovery.c \
	../../../../drivers/sparklink/ws73/dli.c \
	../../../../drivers/sparklink/ws73/dli.h \
	../../../../drivers/sparklink/ws73/discovery.h \
	../../../../include/linux/sparklink_discovery.h \
	../../../../drivers/sparklink/ws73/wire.c \
	../../../../drivers/sparklink/ws73/wire.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/discovery.c \
		../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/dli.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_bsle_test: ws73_bsle_test.c \
	../../../../drivers/sparklink/ws73/wire.c \
	../../../../drivers/sparklink/ws73/bsle.c \
	../../../../drivers/sparklink/ws73/wire.h \
	../../../../drivers/sparklink/ws73/bsle.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c \
		../../../../drivers/sparklink/ws73/bsle.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_dli_test: ws73_dli_test.c \
	../../../../drivers/sparklink/ws73/wire.c \
	../../../../drivers/sparklink/ws73/dli.c \
	../../../../drivers/sparklink/ws73/wire.h \
	../../../../drivers/sparklink/ws73/bsle.h \
	../../../../drivers/sparklink/ws73/dli.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c \
		../../../../drivers/sparklink/ws73/dli.c $(LDLIBS) -o $@
