# Copyright (c) 2024 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from rfl.core.utils import shlex_join


class TestUtils(unittest.TestCase):
    def test_shlex_join(self):
        self.assertEqual(shlex_join(["cmd", "arg1", "arg2"]), "cmd arg1 arg2")
        self.assertEqual(
            shlex_join(["cmd", "arg1", "arg2 with space"]), "cmd arg1 'arg2 with space'"
        )
