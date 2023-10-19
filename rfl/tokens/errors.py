# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from ..errors import RFLError


class JWTError(RFLError):
    pass


class JWTPrivateKeyLoaderError(JWTError):
    pass


class JWTDecodeError(JWTError):
    pass


class JWTEncodeError(JWTError):
    pass
