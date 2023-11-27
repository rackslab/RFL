# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from pathlib import Path

from rfl.build.ninja import NinjaBuilder


class TestNinjaBuilder(unittest.TestCase):
    def test_ninja_builder_basic(self):
        builder = NinjaBuilder()
        builder.variable("var1", "value1")
        builder.rule(name="build-cmd", command="build-stuff $in $out")
        builder.build(
            outputs=[Path("/output")], rule="build-cmd", inputs=[Path("/input")]
        )
