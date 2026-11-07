#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Literal production dependency adapter for the two standard parser fixtures."""
import re


def production_budget(source):
    declarations = re.findall(
        r'(?m)^pub\(crate\) const DLI_PARAM_MAX: usize = ([0-9_]+);$', source)
    if len(declarations) != 1:
        raise ValueError('one literal production DLI_PARAM_MAX is required;no fallback')
    value = int(declarations[0].replace('_', ''))
    if not 0 <= value <= 0xffff:
        raise ValueError('production DLI parameter budget exceeds wire length')
    return 'pub(crate) const DLI_PARAM_MAX: usize = ' + declarations[0] + ';', value
