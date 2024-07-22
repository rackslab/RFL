# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import stat
import tempfile
import os
import unittest

from rfl.authentication.user import AuthenticatedUser
from rfl.authentication.jwt import jwt_gen_key, JWTPrivateKeyFileLoader, JWTManager
from rfl.authentication.errors import (
    JWTPrivateKeyGeneratorError,
    JWTPrivateKeyLoaderError,
    JWTEncodeError,
    JWTDecodeError,
)

PRIVATE_KEY = b"TEST_PRIVATE_KEY"


class TestJWTGenKey(unittest.TestCase):
    def test_gen_key(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "private.key")
            jwt_gen_key(key_path)
            self.assertEqual(stat.filemode(key_path.stat().st_mode), "-r--------")
            self.assertEqual(key_path.stat().st_size, 64)

    def test_gen_key_permission_error(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "private.key")
            os.chmod(dir_name, 0o000)
            with self.assertRaisesRegex(
                JWTPrivateKeyGeneratorError,
                "^Error while generating JWT key .+/private.key: \[Errno 13\] "
                "Permission denied: '.+/private.key'$",
            ):
                jwt_gen_key(key_path)

    def test_gen_key_parent_file(self):
        key_path = Path("/dev/null/fail.key")
        with self.assertRaisesRegex(
            JWTPrivateKeyGeneratorError,
            "^Error while generating JWT key /dev/null/fail.key: \[Errno 20\] Not "
            "a directory: '/dev/null/fail.key'$",
        ):
            jwt_gen_key(key_path)

    def test_gen_key_parent_not_found(self):
        key_path = Path("/dev/fail/fail.key")
        with self.assertRaisesRegex(
            JWTPrivateKeyGeneratorError,
            "^Error while generating JWT key /dev/fail/fail.key: \[Errno 2\] No such "
            "file or directory: '/dev/fail/fail.key'$",
        ):
            jwt_gen_key(key_path)


class TestJWTPrivateKeyFileLoader(unittest.TestCase):
    def test_load_value(self):
        loader = JWTPrivateKeyFileLoader(value=PRIVATE_KEY)
        self.assertEqual(loader.key, PRIVATE_KEY)
        self.assertEqual(loader.path, None)

    def test_load_noarg(self):
        with self.assertRaisesRegex(
            JWTPrivateKeyLoaderError,
            "Either key value or a path must be given to load JWT private key",
        ):
            JWTPrivateKeyFileLoader()

    def test_load_path(self):
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(b"SECR3T")
            fh.flush()
            loader = JWTPrivateKeyFileLoader(path=Path(fh.name))
        self.assertEqual(loader.key, "SECR3T")

    def test_load_empty_key(self):
        with self.assertRaisesRegex(
            JWTPrivateKeyLoaderError,
            "Key loaded from file /dev/null is empty",
        ):
            JWTPrivateKeyFileLoader(path=Path("/dev/null"))

    def test_load_unexisting_path(self):
        with self.assertRaisesRegex(
            JWTPrivateKeyLoaderError, "Token private key file /dev/not-found not found"
        ):
            JWTPrivateKeyFileLoader(path=Path("/dev/not-found"))

    def test_load_path_permission_denied(self):
        with tempfile.NamedTemporaryFile() as fh:
            os.chmod(fh.name, 0o000)
            with self.assertRaisesRegex(
                JWTPrivateKeyLoaderError,
                f"Permission error to access private key file {fh.name}",
            ):
                JWTPrivateKeyFileLoader(path=Path(fh.name))

    def test_load_path_unicode_error(self):
        with tempfile.NamedTemporaryFile() as fh:
            fh.write(b"\x12\x34\x56\x78\x9a")
            fh.flush()
            with self.assertRaisesRegex(
                JWTPrivateKeyLoaderError,
                f"Unable to decode private key file {fh.name}: '\S+' codec can't "
                "decode byte 0x9a in position 4: invalid start byte$",
            ):
                JWTPrivateKeyFileLoader(path=Path(fh.name))

    def test_load_create(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "private.key")
            loader = JWTPrivateKeyFileLoader(path=key_path, create=True)
            self.assertEqual(stat.filemode(key_path.stat().st_mode), "-r--------")
        self.assertEqual(len(loader.key), 64)
        self.assertEqual(str(loader.path), str(key_path))

    def test_load_create_parent(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "private.key")
            os.rmdir(dir_name)
            loader = JWTPrivateKeyFileLoader(
                path=key_path, create=True, create_parent=True
            )
            self.assertEqual(stat.filemode(key_path.stat().st_mode), "-r--------")
        self.assertEqual(len(loader.key), 64)
        self.assertEqual(str(loader.path), str(key_path))

    def test_load_missing_parent(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "private.key")
            os.rmdir(dir_name)
            with self.assertRaisesRegex(
                JWTPrivateKeyLoaderError,
                f"Token private key parent directory {dir_name} not found",
            ):
                JWTPrivateKeyFileLoader(path=key_path, create=True)

    def test_load_create_parent_permission_denied(self):
        with tempfile.TemporaryDirectory() as dir_name:
            key_path = Path(dir_name, "subdir", "private.key")
            key_path.parent.parent.chmod(0o500)
            with self.assertRaisesRegex(
                JWTPrivateKeyLoaderError,
                f"Permission denied to create key parent directory {key_path.parent}",
            ):
                JWTPrivateKeyFileLoader(path=key_path, create=True, create_parent=True)


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
