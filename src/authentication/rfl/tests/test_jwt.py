# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from rfl.authentication.user import AuthenticatedUser
from rfl.authentication.jwt import JWTPrivateKeyFileLoader, JWTManager
from rfl.authentication.errors import JWTEncodeError, JWTDecodeError

PRIVATE_KEY = b"TEST_PRIVATE_KEY"


class TestJWTManager(unittest.TestCase):
    def test_generate_decode(self):
        loader = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        manager = JWTManager("test", "HS256", loader)
        token = manager.generate(AuthenticatedUser(login="user", groups=["group"]), 1)
        self.assertEqual(manager.decode(token).login, "user")

    def test_invalid_algo(self):
        loader = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        manager = JWTManager("test", "FAIL", loader)
        with self.assertRaisesRegex(
            JWTEncodeError,
            "^JWT token encode error: Algorithm not supported$",
        ):
            manager.generate(AuthenticatedUser(login="user", groups=["group"]), 1)

    def test_invalid_token(self):
        loader = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        manager = JWTManager("test", "HS256", loader)
        with self.assertRaisesRegex(
            JWTDecodeError,
            "^Unable to decode token: Not enough segments$",
        ):
            manager.decode("FAIL")

    def test_invalid_signature(self):
        loader1 = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        manager1 = JWTManager("test", "HS256", loader1)
        loader2 = JWTPrivateKeyFileLoader(value=b"OTHER_PRIVATE_KEY")
        manager2 = JWTManager("test", "HS256", loader2)
        token = manager1.generate(AuthenticatedUser(login="user", groups=["group"]), 1)
        with self.assertRaisesRegex(
            JWTDecodeError,
            "^Token signature is invalid$",
        ):
            manager2.decode(token)

    def test_invalid_audience(self):
        loader = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        manager1 = JWTManager("test1", "HS256", loader)
        manager2 = JWTManager("test2", "HS256", loader)
        token = manager1.generate(AuthenticatedUser(login="user", groups=["group"]), 1)
        with self.assertRaisesRegex(
            JWTDecodeError,
            "^Token audience is invalid$",
        ):
            manager2.decode(token)
