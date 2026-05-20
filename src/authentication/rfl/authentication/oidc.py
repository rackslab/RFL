# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

from typing import Any, Dict, List, Mapping, Optional, Union
from pathlib import Path
import logging

try:
    from authlib.integrations.base_client import OAuthError
    from authlib.integrations.flask_client import OAuth
except ImportError as err:
    raise ImportError("Authlib is required for RFL OIDC Authentication") from err

from .errors import OIDCAuthenticationError
from .user import AuthenticatedUser

logger = logging.getLogger(__name__)


class OIDCClient:
    """OpenID Connect client for Flask apps using Authlib's Flask integration."""

    _OIDC_CLIENT_NAME = "rfl_oidc"

    def __init__(
        self,
        app,
        *,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        client_secret: Optional[str] = None,
        scope: str = "openid profile email",
        subject_claim: str = "sub",
        fullname_claim: str = "name",
        groups_claim: Optional[str] = "groups",
        restricted_groups: Optional[List[str]] = None,
        verify_ssl: bool = True,
        cacert: Optional[Path] = None,
        pkce: Optional[str] = None,
        fetch_token=None,
        update_token=None,
        cache=None,
    ):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        secret = client_secret if client_secret else None
        self.client_secret = secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.subject_claim = subject_claim
        self.fullname_claim = fullname_claim
        self.groups_claim = groups_claim
        self.restricted_groups = restricted_groups

        if secret is None and pkce is None:
            raise OIDCAuthenticationError("PKCE is required for public OIDC clients")

        client_kwargs: Dict[str, Any] = {
            "scope": scope,
            "verify": self._verify(verify_ssl, cacert),
        }
        if pkce is not None:
            client_kwargs["code_challenge_method"] = pkce

        metadata_url = f"{self.issuer}/.well-known/openid-configuration"
        oauth = OAuth(
            app,
            cache=cache,
            fetch_token=fetch_token,
            update_token=update_token,
        )
        self._client = oauth.register(
            self._OIDC_CLIENT_NAME,
            client_id=client_id,
            client_secret=secret,
            server_metadata_url=metadata_url,
            client_kwargs=client_kwargs,
        )
        client_type = "public" if secret is None else "confidential"
        logger.debug(
            "Initialized %s OIDC client for issuer %s (client_id=%s, redirect_uri=%s)",
            client_type,
            self.issuer,
            self.client_id,
            self.redirect_uri,
        )

    @staticmethod
    def _verify(verify_ssl: bool, cacert: Optional[Path]) -> Union[bool, str]:
        if cacert is not None:
            return str(cacert)
        return verify_ssl

    def redirect(self, redirect_uri=None, **kwargs):
        """Create HTTP redirect to the OIDC authorization endpoint."""
        try:
            return self._client.authorize_redirect(
                redirect_uri=redirect_uri or self.redirect_uri,
                **kwargs,
            )
        except OAuthError as err:
            raise OIDCAuthenticationError(
                f"OIDC authorization redirect failed: {err}"
            ) from err

    def authenticate(self, **kwargs) -> AuthenticatedUser:
        """Complete the authorization code flow and return an AuthenticatedUser."""
        try:
            token = self._client.authorize_access_token(**kwargs)
        except OAuthError as err:
            raise OIDCAuthenticationError(f"OIDC authorization failed: {err}") from err
        user = self._user_from_token(token)
        if not self._allowed_groups(user.groups):
            raise OIDCAuthenticationError(
                f"User {user.login} is not member of restricted groups"
            )
        logger.info("OIDC authentication completed for user %s", user.login)
        return user

    def _user_from_token(self, token: Mapping[str, Any]) -> AuthenticatedUser:
        userinfo = token.get("userinfo")
        if userinfo is None:
            raise OIDCAuthenticationError(
                "OIDC token response does not contain validated userinfo"
            )
        return self._claims_to_user(userinfo)

    def _normalize_groups(self, value: Any) -> List[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(group) for group in value]
        return [str(value)]

    def _claims_to_user(self, claims: Dict[str, Any]) -> AuthenticatedUser:
        login = claims.get(self.subject_claim)
        if not login:
            raise OIDCAuthenticationError(
                f"OIDC claims do not contain subject claim {self.subject_claim}"
            )

        fullname = claims.get(self.fullname_claim)
        groups = []
        if self.groups_claim is not None:
            groups = self._normalize_groups(claims.get(self.groups_claim))

        return AuthenticatedUser(
            login=str(login),
            fullname=str(fullname) if fullname is not None else None,
            groups=groups,
        )

    def _allowed_groups(self, groups: List[str]) -> bool:
        """Return False if restricted groups are set and none of the groups match."""
        return not (
            self.restricted_groups is not None
            and len(self.restricted_groups)
            and not any(group in self.restricted_groups for group in groups)
        )
