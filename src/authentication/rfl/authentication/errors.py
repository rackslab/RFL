# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from rfl.core.errors import RFLError


class AuthenticationError(RFLError):
    pass


class LDAPAuthenticationError(AuthenticationError):
    pass


class JWTError(AuthenticationError):
    pass


class JWTPrivateKeyGeneratorError(JWTError):
    pass


class JWTPrivateKeyLoaderError(JWTError):
    pass


class JWTDecodeError(JWTError):
    pass


class JWTEncodeError(JWTError):
    pass
