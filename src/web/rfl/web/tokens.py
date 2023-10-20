# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from functools import wraps
from pathlib import Path
import sys
import logging

from flask import request, abort, current_app

from rfl.tokens.jwt import JWTManager
from rfl.tokens.errors import JWTDecodeError, JWTPrivateKeyLoaderError
from rfl.authorizations.rbac import RBACPolicyManager
from rfl.authorizations.errors import (
    RBACPolicyDefinitionLoadError,
    RBACPolicyRolesLoadError,
)

logger = logging.getLogger(__name__)


def _get_token_user(request):
    """Return the user name as decoded in the token found in request autorization
    headers. Raise a HTTP/403 forbidden error if the token cannot be decoded properly.
    Return None if the authorization header is not found, which is assimilated to
    anonymous user."""

    auth = request.headers.get("Authorization")
    if auth is None:
        return None

    if not auth.startswith("Bearer "):
        logger.warning("Malformed authorization header found in request")
        abort(403, "No valid token provided")
    token = auth.split(" ", 1)[1]
    try:
        user = current_app.jwt.decode(token)
    except JWTDecodeError as err:
        abort(403, str(err))
    return user


def rbac_action(action):
    """Decorator for Flask views functions check for valid authentification JWT
    token and permission in policy."""

    def inner_decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = _get_token_user(request)
            # verify unauthorized anonymous access
            if user is None and (
                not current_app.policy.allow_anonymous
                or not current_app.policy.allowed_anonymous_action(action)
            ):
                logger.warning("Unauthorized anonymous access to action %s", action)
                abort(
                    403,
                    f"anonymous role is not allowed to perform action {action}",
                )
            # verify real user access
            elif user is not None and not current_app.policy.allowed_user_action(
                user, [], action
            ):
                logger.warning(
                    "Unauthorized access from user %s to action %s",
                    user,
                    action,
                )
                abort(
                    403,
                    f"user {user} is not allowed to perform action " f"{action}",
                )
            return view(*args, **kwargs)

        return wrapped

    return inner_decorator


class RFLTokenizedWebApp:
    def __init__(
        self, audience: str, algorithm: str, key: Path, policy: Path, roles: Path
    ):
        try:
            self.jwt = JWTManager.key(
                audience=audience,
                algorithm=algorithm,
                path=key,
                create=True,
                create_parent=True,
            )
        except JWTPrivateKeyLoaderError as err:
            logger.critical(f"Error while loading JWT private key {key}: {str(err)}")
            sys.exit(1)
        try:
            self.policy = RBACPolicyManager.yaml_definition_ini_roles(
                definition=policy, roles=roles
            )
        except RBACPolicyDefinitionLoadError as err:
            logger.critical(
                f"Error while loading RBAC policy definition file {policy}: {str(err)}"
            )
            sys.exit(1)
        except RBACPolicyRolesLoadError as err:
            logger.critical(
                f"Error while loading RBAC roles policy file {roles}: {str(err)}"
            )
            sys.exit(1)
