#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Dependency adapter unit checks,not parser/kernel or hardware qualification."""
import unittest
from dli_parser_budget import production_budget


class ProductionBudget(unittest.TestCase):
    def test_exact_source_declaration_is_injected(self):
        for literal,value in [('240',240),('255',255),('2_40',240)]:
            source=f'pub(crate) const DLI_PARAM_MAX: usize = {literal};'
            self.assertEqual(production_budget(source),(source,value))

    def test_missing_duplicate_expression_or_out_of_wire_range_fail_closed(self):
        declaration='pub(crate) const DLI_PARAM_MAX: usize = 240;'
        for source in ['',declaration+'\n'+declaration,declaration.replace('240','120+120'),declaration.replace('240','65536')]:
            with self.subTest(source=source),self.assertRaises(ValueError):
                production_budget(source)


if __name__=='__main__':
    unittest.main()
