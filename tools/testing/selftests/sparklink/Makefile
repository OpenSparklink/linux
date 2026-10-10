# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := sparklink_test ws73_bsle_test ws73_dli_test ws73_discovery_test
TEST_GEN_PROGS_EXTENDED := sparklink_runtime_test ws73_native_runtime_test sparklink_host_plan_test sparklink_discovery_operation_test
TEST_GEN_PROGS_EXTENDED += ws73_native_tx_fault_test
TEST_GEN_PROGS_EXTENDED += ws73_native_open_test

TEST_PROGS := run_qemu_test.sh

include ../lib.mk

$(OUTPUT)/ws73_native_tx_fault_test: ws73_native_tx_fault_test.c ws73_native_runtime_test.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

$(OUTPUT)/ws73_native_open_test: ws73_native_open_test.c ws73_native_runtime_test.c native-open/native_open_fixture.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

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
