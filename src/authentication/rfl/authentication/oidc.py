# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

from typing import Any, Dict, List, Mapping, NamedTuple, Optional, Union
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse
import hmac
import logging

try:
    from authlib.common.encoding import to_bytes
    from authlib.common.security import generate_token
    from authlib.integrations.requests_client import OAuth2Session
    from authlib.oidc.core.util import create_half_hash
except ImportError as err:
    raise ImportError("Authlib library is required for RFL OIDC authentifier") from err

try:
    from joserfc import jwt
    from joserfc.errors import JoseError
    from joserfc.jwk import KeySet
    from joserfc.jwt import JWTClaimsRegistry

    _JWT_BACKEND = "joserfc"
except ImportError:
    from authlib.jose import jwt
    from authlib.oidc.core import CodeIDToken

    _JWT_BACKEND = "authlib"

from .errors import OIDCAuthenticationError
from .user import AuthenticatedUser

logger = logging.getLogger(__name__)


def _validate_at_hash(
    claims: Dict[str, Any],
    alg: Optional[str],
    access_token: Optional[str],
) -> None:
    """Validate OIDC at_hash when present alongside an access token."""
    at_hash = claims.get("at_hash")
    if not at_hash or not access_token:
        return
    hash_value = create_half_hash(access_token, alg)
    if hash_value is None or not hmac.compare_digest(to_bytes(at_hash), hash_value):
        raise OIDCAuthenticationError("Invalid OIDC id_token: at_hash")


class AuthorizationRequest(NamedTuple):
    """Authorization Code flow state to persist until the IdP callback."""

    url: str
    state: str
    code_verifier: Optional[str]
    nonce: str


class OIDCAuthentifier:
    def __init__(
        self,
        issuer: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: str = "openid profile email",
        subject_claim: str = "sub",
        fullname_claim: str = "name",
        groups_claim: Optional[str] = "groups",
        restricted_groups: Optional[List[str]] = None,
        code_challenge_method: Optional[str] = "S256",
        verify_ssl: bool = True,
        cacert: Optional[Path] = None,
    ):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.subject_claim = subject_claim
        self.fullname_claim = fullname_claim
        self.groups_claim = groups_claim
        self.restricted_groups = restricted_groups
        self.code_challenge_method = code_challenge_method
        self.verify_ssl = verify_ssl
        self.cacert = cacert
        self._discovery_metadata: Optional[Dict[str, Any]] = None
        logger.debug(
            "Initialized OIDC authentifier for issuer %s "
            "(client_id=%s, redirect_uri=%s)",
            self.issuer,
            self.client_id,
            self.redirect_uri,
        )

    def _verify(self) -> Union[bool, str]:
        if self.cacert is not None:
            return str(self.cacert)
        return self.verify_ssl

    def _session(self) -> OAuth2Session:
        kwargs = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
        }
        if self.code_challenge_method is not None:
            kwargs["code_challenge_method"] = self.code_challenge_method
        session = OAuth2Session(**kwargs)
        session.verify = self._verify()
        return session

    def _metadata(self) -> Dict[str, Any]:
        if self._discovery_metadata is None:
            logger.debug("Fetching OIDC discovery metadata from issuer %s", self.issuer)
            try:
                session = self._session()
                self._discovery_metadata = session.fetch_server_metadata(self.issuer)
            except Exception as err:
                raise OIDCAuthenticationError(
                    f"Unable to fetch OIDC discovery metadata from {self.issuer}: {err}"
                ) from err
            logger.debug(
                "Loaded OIDC discovery metadata (issuer=%s)",
                self._discovery_metadata.get("issuer", self.issuer),
            )
        return self._discovery_metadata

    def create_authorization_request(
        self,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        code_verifier: Optional[str] = None,
    ) -> AuthorizationRequest:
        """Build the authorization redirect URL and flow parameters."""
        logger.debug("Creating OIDC authorization request")
        metadata = self._metadata()
        authorization_endpoint = metadata.get("authorization_endpoint")
        if not authorization_endpoint:
            raise OIDCAuthenticationError(
                "OIDC metadata does not define authorization_endpoint"
            )

        if state is None:
            state = generate_token()
        if nonce is None:
            nonce = generate_token()
        if self.code_challenge_method is not None and code_verifier is None:
            code_verifier = generate_token(48)

        logger.debug(
            "Building authorization URL at %s (scope=%s, pkce=%s)",
            authorization_endpoint,
            self.scope,
            self.code_challenge_method is not None,
        )
        session = self._session()
        try:
            kwargs = {
                "redirect_uri": self.redirect_uri,
                "nonce": nonce,
            }
            if code_verifier is not None:
                kwargs["code_verifier"] = code_verifier
            url, returned_state = session.create_authorization_url(
                authorization_endpoint,
                state=state,
                **kwargs,
            )
        except Exception as err:
            raise OIDCAuthenticationError(
                f"Unable to create OIDC authorization URL: {err}"
            ) from err

        auth_request = AuthorizationRequest(
            url=url,
            state=returned_state or state,
            code_verifier=code_verifier,
            nonce=nonce,
        )
        logger.info(
            "OIDC authorization request created (authorization_endpoint=%s)",
            authorization_endpoint,
        )
        return auth_request

    def authorization_response_from_query(self, request_args: Mapping[str, str]) -> str:
        """Build a callback URL from query parameters (e.g. Flask request.args)."""
        query = urlencode(
            [(key, value) for key, value in request_args.items()],
            doseq=True,
        )
        return f"{self.redirect_uri}?{query}"

    def complete_authorization(
        self,
        authorization_response: str,
        request: AuthorizationRequest,
    ) -> AuthenticatedUser:
        """Exchange the authorization code and return an AuthenticatedUser."""
        logger.debug(
            "Completing OIDC authorization (callback=%s)",
            self._callback_log_label(authorization_response),
        )
        callback_state = self._state_from_authorization_response(authorization_response)
        if callback_state != request.state:
            raise OIDCAuthenticationError("OIDC state parameter mismatch")

        metadata = self._metadata()
        token_endpoint = metadata.get("token_endpoint")
        if not token_endpoint:
            raise OIDCAuthenticationError(
                "OIDC metadata does not define token_endpoint"
            )

        session = self._session()
        logger.debug("Exchanging authorization code at %s", token_endpoint)
        try:
            fetch_kwargs = {
                "authorization_response": authorization_response,
                "nonce": request.nonce,
            }
            if request.code_verifier is not None:
                fetch_kwargs["code_verifier"] = request.code_verifier
            token_response = session.fetch_token(
                token_endpoint,
                **fetch_kwargs,
            )
        except Exception as err:
            raise OIDCAuthenticationError(
                f"Unable to exchange OIDC authorization code: {err}"
            ) from err
        logger.debug("OIDC token response received from %s", token_endpoint)

        claims = self._validate_id_token(token_response, request.nonce)
        claims = self._merge_userinfo_claims(session, metadata, claims, token_response)
        user = self._claims_to_user(claims)
        if not self._allowed_groups(user.groups):
            raise OIDCAuthenticationError(
                f"User {user.login} is not member of restricted groups"
            )
        logger.info("OIDC authorization completed for user %s", user.login)
        return user

    def _callback_log_label(self, authorization_response: str) -> str:
        """Return a log-safe description of the callback URL (no secret values)."""
        parsed = urlparse(authorization_response)
        param_names = sorted(parse_qs(parsed.query))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{','.join(param_names)}"

    def _state_from_authorization_response(
        self, authorization_response: str
    ) -> Optional[str]:
        parsed = urlparse(authorization_response)
        values = parse_qs(parsed.query).get("state")
        if not values:
            return None
        return values[0]

    def _validate_id_token(
        self, token_response: Dict[str, Any], nonce: str
    ) -> Dict[str, Any]:
        id_token = token_response.get("id_token")
        if not id_token:
            raise OIDCAuthenticationError(
                "OIDC token response does not contain id_token"
            )

        metadata = self._metadata()
        jwks_uri = metadata.get("jwks_uri")
        if not jwks_uri:
            raise OIDCAuthenticationError("OIDC metadata does not define jwks_uri")

        session = self._session()
        logger.debug("Fetching OIDC JWKS from %s", jwks_uri)
        try:
            jwks = session.get(jwks_uri).json()
        except Exception as err:
            raise OIDCAuthenticationError(
                f"Unable to fetch OIDC JWKS from {jwks_uri}: {err}"
            ) from err

        issuer = metadata.get("issuer", self.issuer)
        logger.debug(
            "Validating OIDC id_token (issuer=%s, jwt_backend=%s)",
            issuer,
            _JWT_BACKEND,
        )
        try:
            if _JWT_BACKEND == "joserfc":
                claims = self._validate_id_token_joserfc(
                    id_token, jwks, issuer, nonce, token_response
                )
            else:
                claims = self._validate_id_token_authlib(
                    id_token, jwks, issuer, nonce, token_response
                )
        except OIDCAuthenticationError:
            raise
        except Exception as err:
            raise OIDCAuthenticationError(f"Invalid OIDC id_token: {err}") from err

        logger.debug("OIDC id_token validated successfully")
        return claims

    def _validate_id_token_joserfc(
        self,
        id_token: str,
        jwks: Dict[str, Any],
        issuer: str,
        nonce: str,
        token_response: Dict[str, Any],
    ) -> Dict[str, Any]:
        key_set = KeySet.import_key_set(jwks)
        token = jwt.decode(id_token, key_set)
        registry = JWTClaimsRegistry(
            iss={"essential": True, "value": issuer},
            aud={"essential": True, "value": self.client_id},
            nonce={"essential": True, "value": nonce},
        )
        try:
            registry.validate(token.claims)
            # joserfc JWTClaimsRegistry only validates claims in the payload while
            # authlib.jose.jwt.decode() validates at_hash via claims_params.
            _validate_at_hash(
                token.claims,
                token.header.get("alg"),
                token_response.get("access_token"),
            )
        except JoseError as err:
            raise OIDCAuthenticationError(f"Invalid OIDC id_token: {err}") from err
        return dict(token.claims)

    def _validate_id_token_authlib(
        self,
        id_token: str,
        jwks: Dict[str, Any],
        issuer: str,
        nonce: str,
        token_response: Dict[str, Any],
    ) -> Dict[str, Any]:
        claims = jwt.decode(
            id_token,
            jwks,
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "value": issuer},
                "aud": {"essential": True, "value": self.client_id},
                "nonce": {"essential": True, "value": nonce},
            },
            claims_params={
                "access_token": token_response.get("access_token"),
                "client_id": self.client_id,
            },
        )
        claims.validate()
        return dict(claims)

    def _merge_userinfo_claims(
        self,
        session: OAuth2Session,
        metadata: Dict[str, Any],
        claims: Dict[str, Any],
        token_response: Dict[str, Any],
    ) -> Dict[str, Any]:
        if self.groups_claim is None:
            logger.debug("Skipping OIDC userinfo request (groups_claim disabled)")
            return claims
        if self.groups_claim in claims:
            logger.debug(
                "Skipping OIDC userinfo request (%s present in id_token claims)",
                self.groups_claim,
            )
            return claims

        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if not userinfo_endpoint:
            logger.debug(
                "Skipping OIDC userinfo request (no userinfo_endpoint in metadata)"
            )
            return claims

        access_token = token_response.get("access_token")
        if not access_token:
            logger.debug(
                "Skipping OIDC userinfo request (no access_token in token response)"
            )
            return claims

        logger.debug(
            "Fetching OIDC userinfo from %s for claim %s",
            userinfo_endpoint,
            self.groups_claim,
        )
        try:
            session.token = token_response
            response = session.get(userinfo_endpoint)
            response.raise_for_status()
            userinfo = response.json()
        except Exception as err:
            raise OIDCAuthenticationError(
                f"Unable to fetch OIDC userinfo: {err}"
            ) from err

        logger.debug("OIDC userinfo fetched from %s", userinfo_endpoint)
        merged = dict(claims)
        merged.update(userinfo)
        return merged

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
