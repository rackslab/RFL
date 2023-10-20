# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from rfl.core.errors import RFLError


class AuthorizationError(RFLError):
    pass


class RBACPolicyError(AuthorizationError):
    pass


class RBACPolicyDefinitionLoadError(RBACPolicyError):
    pass


class RBACPolicyRolesLoadError(RBACPolicyError):
    pass
