# SPDX-License-Identifier: GPL-2.0-only
"""Actual driver/codec source paths; legacy fixture labels are not production placement."""
from pathlib import Path


def source_path(net, name):
    if name == 'sle_usb_ffi.c':
        return net.parents[1]/'drivers/sparklink/standard_usb.c'
    if name == 'sle_usb.rs':
        return net/'sle_standard_dli.rs'
    return net/name
