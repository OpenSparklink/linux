# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_SPARKLINK)	+= sparklink.o

sparklink-y := sparklink_core.o
sparklink-y += sle_irq_lock.o
sparklink-y += sle_native_ffi.o
sparklink-y += sle_channel_wire.o sle_channel_socket.o
# Crypto mechanism sources are retained for future per-session security and
# dedicated fault tests; no unconnected crypto object in the default runtime.
sparklink-$(CONFIG_SPARKLINK_GENL) += sparklink_genl.o
