# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_SPARKLINK)	+= sparklink.o

sparklink-y := sparklink_core.o
sparklink-y += sle_irq_lock.o
sparklink-y += sle_native_ffi.o
sparklink-y += sle_channel_wire.o sle_channel_socket.o
sparklink-y += sle_pair_crypto.o sle_pair_material.o
# Only the used P256/CMAC Session mechanism is linked. Historical SM3/SM4 and
# the removed security/RPA facade are isolated in selftests/retired-security-state.
sparklink-$(CONFIG_SPARKLINK_GENL) += sparklink_genl.o
