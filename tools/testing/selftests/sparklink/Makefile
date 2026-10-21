# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := ws73_bsle_test ws73_dli_test ws73_discovery_test
TEST_GEN_PROGS += ws73_recovery_test sparklink_backend_test
TEST_GEN_PROGS += ws73_acb_test
TEST_GEN_PROGS += ws73_chip_test
TEST_GEN_PROGS += ws73_sle_efuse_test
TEST_GEN_PROGS += virtual_codec_test
TEST_GEN_PROGS += sle_channel_wire_test sle_channel_signal_test
TEST_GEN_PROGS += sle_channel_state_test sle_channel_table_test
TEST_GEN_PROGS_EXTENDED += ssap_removed_uapi_test sparklink_socket_type_test
TEST_GEN_PROGS_EXTENDED += sparklink_host_plan_test sparklink_discovery_operation_test
TEST_GEN_PROGS_EXTENDED += sparklink_runtime_address_test
TEST_GEN_PROGS_EXTENDED += ws73_native_open_test
TEST_GEN_PROGS_EXTENDED += ws73_native_rpc_fault_test
TEST_GEN_PROGS_EXTENDED += sparklink_event_copy_test
TEST_GEN_PROGS_EXTENDED += sparklink_diagnostic_result_test
TEST_GEN_PROGS_EXTENDED += sparklink_setup_release_test
TEST_GEN_PROGS_EXTENDED += genl_registry_test
TEST_GEN_PROGS_EXTENDED += retired_uapi_test
TEST_GEN_PROGS_EXTENDED += virtual_runtime_test

TEST_PROGS := run_security_remediation.py run_backend_containment.py
TEST_PROGS += run_crypto_mechanism_faults.py
TEST_PROGS += run_security_relay.py
TEST_PROGS += run_connection_tx.py run_ssap_containment.py run_native_connection_contract.py
TEST_PROGS += run_event_copy.py run_runtime_ingress.py run_usb_registration.py
TEST_PROGS += run_phy_model.py run_power_retirement.py
TEST_PROGS += run_diagnostic_result.py
TEST_PROGS += run_management_release.py run_link_observation.py
TEST_PROGS += run_session_wake.py
TEST_PROGS += run_native_data.py run_native_ticket_driver.py run_session_dispatch.py
TEST_PROGS += run_retired_transport.py
TEST_PROGS += run_usb_firmware.py
TEST_PROGS += run_usb_binding.py
TEST_PROGS += run_ws73_runtime_rx.py
TEST_PROGS += run_ws73_hcc_memory.py
TEST_PROGS += run_standard_provider.py
TEST_PROGS += run_standard_driver.py
TEST_PROGS += run_usb_discovery.py run_backend_command_port.py run_usb_bootstrap_metadata.py
TEST_PROGS += test_virtual_vm_verdict.py run_standard_events.py test_dli_parser_budget.py
TEST_PROGS += run_raw_uapi_retirement.py
TEST_FILES += native_runtime_probe.h vm_test_utils.py retired-raw-uapi
TEST_FILES += ws73-runtime-rx
TEST_FILES += dli_parser_budget.py retired_uapi_test.c retired_ioctl_cases.h retired_ioctl_numbers.h file_affinity_probe.h
TEST_FILES += run_virtual_vm.py standard_event_fixture.rs retired-standard-events retired-registry-version

include ../lib.mk

$(OUTPUT)/ws73_chip_test: ws73_chip_test.c ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/bsle.c ../../../../drivers/sparklink/ws73/wire.h ../../../../drivers/sparklink/ws73/bsle.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/bsle.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_sle_efuse_test: ws73_sle_efuse_test.c ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/bsle.c ../../../../drivers/sparklink/ws73/wire.h ../../../../drivers/sparklink/ws73/bsle.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/bsle.c $(LDLIBS) -o $@

$(OUTPUT)/virtual_codec_test: virtual_codec_test.c ../../../../drivers/sparklink/virtual_codec.h
	$(CC) $(CFLAGS) -I../../../../include $< $(LDLIBS) -o $@

$(OUTPUT)/sle_channel_state_test: sle_channel_state_test.c ../../../../net/sparklink/sle_channel_state.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/sle_channel_wire_test: sle_channel_wire_test.c ../../../../net/sparklink/sle_channel_wire.c ../../../../net/sparklink/sle_channel_wire.h
	$(CC) $(CFLAGS) $< ../../../../net/sparklink/sle_channel_wire.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_acb_test: ws73_acb_test.c ../../../../drivers/sparklink/ws73/wire.c ../../../../drivers/sparklink/ws73/wire.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/wire.c $(LDLIBS) -o $@

$(OUTPUT)/ws73_recovery_test: ws73_recovery_test.c ../../../../drivers/sparklink/ws73/recovery.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_open_test: ws73_native_open_test.c native_runtime_probe.h retired_ioctl_numbers.h native-open/native_open_fixture.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_rpc_fault_test: ws73_native_rpc_fault_test.c ws73_native_open_test.c native_runtime_probe.h retired_ioctl_numbers.h native-open/native_open_fixture.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -pthread -o $@

RUSTC ?= rustc
$(OUTPUT)/sparklink_runtime_address_test: ../../../../net/sparklink/sle_runtime_address.rs
	$(RUSTC) --edition=2021 -D warnings --test $< -o $@

$(OUTPUT)/sparklink_host_plan_test: sparklink_host_plan_test.rs \
	../../../../net/sparklink/sle_command_plan.rs \
	../../../../net/sparklink/sle_command_queue.rs \
	../../../../net/sparklink/sle_link_query.rs \
	../../../../net/sparklink/sle_connection_operation.rs \
	../../../../net/sparklink/sle_security_relay.rs \
	../../../../net/sparklink/sle_security_relay_state.rs \
	run_host_plan.py security_relay_fixture.py
	RUSTC=$(RUSTC) python3 run_host_plan.py --binary $@

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

$(OUTPUT)/sparklink_backend_test: sparklink_backend_test.c ../../../../include/linux/sparklink_backend.h
	$(CC) $(CFLAGS) -I../../../../include $< $(LDLIBS) -o $@

$(OUTPUT)/sle_channel_table_test: sle_channel_table_test.c ../../../../net/sparklink/sle_channel_table.h ../../../../net/sparklink/sle_channel_grant.h
	$(CC) $(CFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/sle_channel_signal_test: sle_channel_signal_test.c ../../../../net/sparklink/sle_channel_wire.c ../../../../net/sparklink/sle_channel_wire.h
	$(CC) $(CFLAGS) $< ../../../../net/sparklink/sle_channel_wire.c $(LDLIBS) -o $@
