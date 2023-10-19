# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import secrets
from datetime import datetime, timezone, timedelta
import logging
from pathlib import Path

import jwt

from .errors import JWTPrivateKeyLoaderError, JWTDecodeError, JWTEncodeError

logger = logging.getLogger(__name__)


class JWTPrivateKeyLoader:
    pass


class JWTPrivateKeyFileLoader:
    def __init__(
        self,
        path: Path = None,
        value: str = None,
        create: bool = False,
        create_parent: bool = False,
    ):
        if path is not None:
            logger.debug("Loading JWT private key from path %s", path)
            self.path = path
            self.key = None
            self._load_path(create, create_parent)
        elif value is not None:
            logger.debug("Loading JWT private key from value")
            self.path = None
            self.key = value
        else:
            raise JWTPrivateKeyLoaderError(
                "Either key value or a path must be given to load JWT private key"
            )

    def _load_path(self, create: bool, create_parent: bool) -> None:
        """Load the JWT private key from path. If create argument is True, the private
        key is randomly generated if not present. If create_parent is True, the parent
        directory of the private key is also created if not present. Raise
        JWTPrivateKeyLoaderError if create_parent is False and private parent directory
        does not exist or if create is False and private key file does not exist."""
        # Create tokens directory if missing
        if not self.path.parent.exists():
            if create_parent:
                logger.info("Creating JWT private key directory %s", self.path.parent)
                try:
                    self.path.parent.mkdir()
                    self.path.parent.chmod(0o755)  # be umask agnostic
                except PermissionError as err:
                    raise JWTPrivateKeyLoaderError(
                        "Permission denied to create key parent directory "
                        f"{self.path.parent}"
                    )
            else:
                raise JWTPrivateKeyLoaderError(
                    f"Token private key parent directory {self.path.parent} not found"
                )
        # Generate instance tokens encryption key file if missing
        if not self.path.exists():
            if create:
                logger.info("Generating JWT private key file %s", self.path)
                with open(self.path, "w+") as fh:
                    fh.write(secrets.token_hex(32))
                self.path.chmod(0o400)  # restrict access to encryption key
            else:
                raise JWTPrivateKeyLoaderError(
                    f"Token private key file {self.path} not found"
                )
        # Load the instance tokens encryption key
        with open(self.path, "r") as fh:
            self.key = fh.read()


class JWTManager:
    def __init__(self, audience: str, algorithm: str, loader: JWTPrivateKeyLoader):
        self.audience = audience
        self.algorithm = algorithm
        self.key = loader.key

    def decode(self, token) -> str:
        """Decode the given token with the encryption key an returns the user of
        this token."""
        try:
            payload = jwt.decode(
                token,
                self.key,
                audience=self.audience,
                algorithms=[self.algorithm],
            )
        except jwt.InvalidSignatureError as err:
            raise JWTDecodeError("Token signature is invalid") from err
        except jwt.ExpiredSignatureError as err:
            raise JWTDecodeError("Token is expired") from err
        except jwt.InvalidAudienceError as err:
            raise JWTDecodeError("Token audience is invalid") from err
        except jwt.exceptions.DecodeError as err:
            raise JWTDecodeError(f"Unable to decode token: {str(err)}") from err
        return payload["sub"]

    def generate(self, user: str, duration: int) -> str:
        """Returns a JWT token for the given user, signed with the encryption
        key, for the configured audience and valid for the given duration."""
        try:
            return jwt.encode(
                {
                    "iat": datetime.now(tz=timezone.utc),
                    "exp": datetime.now(tz=timezone.utc) + timedelta(days=duration),
                    "aud": self.audience,
                    "sub": user,
                },
                self.key,
                algorithm=self.algorithm,
            )
        except NotImplementedError as err:
            raise JWTEncodeError(f"JWT token encode error: {str(err)}") from err

    @classmethod
    def key(
        cls,
        audience: str,
        algorithm: str,
        path: Path,
        create: bool = False,
        create_parent: bool = False,
    ):
        return cls(
            audience,
            algorithm,
            JWTPrivateKeyFileLoader(
                path=path, create=create, create_parent=create_parent
            ),
        )
