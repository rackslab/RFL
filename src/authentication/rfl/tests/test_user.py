# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from rfl.authentication.user import AuthenticatedUser, AnonymousUser


class TestUser(unittest.TestCase):
    def test_user(self):
        user = AuthenticatedUser("test")
        self.assertFalse(user.is_anonymous())

    def test_anonymous(self):
        user = AnonymousUser()
        self.assertTrue(user.is_anonymous())
