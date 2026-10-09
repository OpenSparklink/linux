# SPDX-License-Identifier: GPL-2.0

TEST_GEN_PROGS := sparklink_test ws73_bsle_test ws73_dli_test ws73_discovery_test
TEST_GEN_PROGS_EXTENDED := sparklink_runtime_test ws73_native_runtime_test sparklink_host_plan_test
TEST_PROGS := run_qemu_test.sh

include ../lib.mk

RUSTC ?= rustc
$(OUTPUT)/sparklink_host_plan_test: sparklink_host_plan_test.rs \
	../../../../net/sparklink/sle_command_plan.rs \
	../../../../net/sparklink/sle_command_queue.rs
	$(RUSTC) --edition=2021 --test -D warnings $< -o $@

$(OUTPUT)/ws73_discovery_test: ws73_discovery_test.c \
	../../../../drivers/sparklink/ws73/discovery.c \
	../../../../drivers/sparklink/ws73/discovery.h \
	../../../../drivers/sparklink/ws73/wire.c \
	../../../../drivers/sparklink/ws73/wire.h
	$(CC) $(CFLAGS) $< ../../../../drivers/sparklink/ws73/discovery.c \
		../../../../drivers/sparklink/ws73/wire.c $(LDLIBS) -o $@

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
