# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import time
import unittest
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

try:
    from authlib.oidc.core.util import create_half_hash

    from rfl.authentication import oidc as oidc_mod
    from rfl.authentication.errors import OIDCAuthenticationError
    from rfl.authentication.oidc import AuthorizationRequest, OIDCAuthentifier
    from rfl.authentication.user import AuthenticatedUser
except ImportError:
    AUTHLIB_AVAILABLE = False
else:
    AUTHLIB_AVAILABLE = True


@unittest.skipUnless(AUTHLIB_AVAILABLE, "authlib is not installed")
class TestOIDCAuthentifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if oidc_mod._JWT_BACKEND == "joserfc":
            from joserfc.jwk import RSAKey

            cls._signing_key = RSAKey.generate_key(2048, private=True)
            public = cls._signing_key.as_dict(private=False)
        else:
            from authlib.jose import JsonWebKey

            cls._signing_key = JsonWebKey.generate_key("RSA", 2048, is_private=True)
            try:
                public = cls._signing_key.as_dict(is_private=False)
            except TypeError:
                # authlib 0.15.x (e.g. Ubuntu Jammy python3-authlib): as_dict() only
                # accepts add_kid; drop RSA private fields to build the public JWK.
                public = {
                    k: v
                    for k, v in cls._signing_key.as_dict().items()
                    if k not in {"d", "p", "q", "dp", "dq", "qi", "oth"}
                }
        public["kid"] = "test-key"
        cls._jwks = {"keys": [public]}

    def setUp(self):
        self.authentifier = OIDCAuthentifier(
            issuer="https://idp.example.com",
            client_id="client-id",
            client_secret="client-secret",
            redirect_uri="https://app.example.com/callback",
        )
        self.metadata = {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
            "userinfo_endpoint": "https://idp.example.com/userinfo",
        }

    def _make_id_token(
        self,
        nonce: str = "nonce-1",
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        now = int(time.time())
        payload = {
            "iss": self.metadata["issuer"],
            "aud": self.authentifier.client_id,
            "sub": "alice",
            "nonce": nonce,
            "iat": now,
            "exp": now + 3600,
        }
        if extra_claims:
            payload.update(extra_claims)
        header = {"alg": "RS256", "kid": "test-key"}
        token = oidc_mod.jwt.encode(header, payload, self._signing_key)
        if isinstance(token, bytes):
            return token.decode()
        return token

    def _jwks_response(self):
        response = MagicMock()
        response.json.return_value = self._jwks
        return response

    def _auth_request(self, nonce: str = "nonce-1") -> AuthorizationRequest:
        return AuthorizationRequest(
            url="https://idp.example.com/authorize",
            state="state-1",
            code_verifier="verifier",
            nonce=nonce,
        )

    def test_defaults(self):
        auth = OIDCAuthentifier(
            issuer="https://idp.example.com",
            client_id="cid",
            client_secret="secret",
            redirect_uri="https://app/cb",
        )
        self.assertEqual(auth.scope, "openid profile email")
        self.assertEqual(auth.subject_claim, "sub")
        self.assertEqual(auth.fullname_claim, "name")
        self.assertEqual(auth.groups_claim, "groups")
        self.assertEqual(auth.code_challenge_method, "S256")

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_create_authorization_request(self, mock_session_cls):
        mock_session = mock_session_cls.return_value
        mock_session.create_authorization_url.return_value = (
            "https://idp.example.com/authorize?state=abc",
            "abc",
        )
        self.authentifier._discovery_metadata = self.metadata

        request = self.authentifier.create_authorization_request()

        self.assertIsInstance(request, AuthorizationRequest)
        self.assertEqual(request.url, "https://idp.example.com/authorize?state=abc")
        self.assertEqual(request.state, "abc")
        self.assertIsNotNone(request.code_verifier)
        self.assertIsNotNone(request.nonce)
        mock_session.create_authorization_url.assert_called_once()
        call_kwargs = mock_session.create_authorization_url.call_args[1]
        self.assertEqual(call_kwargs["redirect_uri"], self.authentifier.redirect_uri)
        self.assertEqual(call_kwargs["nonce"], request.nonce)
        self.assertEqual(call_kwargs["code_verifier"], request.code_verifier)

    def test_authorization_response_from_query(self):
        response = self.authentifier.authorization_response_from_query(
            {"code": "auth-code", "state": "xyz"}
        )
        self.assertEqual(
            response,
            "https://app.example.com/callback?code=auth-code&state=xyz",
        )

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": self._make_id_token(
                extra_claims={"name": "Alice", "groups": ["users"]}
            ),
        }
        mock_session.get.return_value = self._jwks_response()

        auth_request = self._auth_request()
        authorization_response = (
            "https://app.example.com/callback?code=auth-code&state=state-1"
        )

        user = self.authentifier.complete_authorization(
            authorization_response, auth_request
        )

        self.assertIsInstance(user, AuthenticatedUser)
        self.assertEqual(user.login, "alice")
        self.assertEqual(user.fullname, "Alice")
        self.assertEqual(user.groups, ["users"])
        mock_session.fetch_token.assert_called_once()
        mock_session.get.assert_called_once_with(self.metadata["jwks_uri"])

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_state_mismatch(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        auth_request = AuthorizationRequest(
            url="https://idp.example.com/authorize",
            state="expected",
            code_verifier="verifier",
            nonce="nonce-1",
        )
        authorization_response = (
            "https://app.example.com/callback?code=auth-code&state=wrong"
        )

        with self.assertRaises(OIDCAuthenticationError) as ctx:
            self.authentifier.complete_authorization(
                authorization_response, auth_request
            )
        self.assertIn("state", str(ctx.exception).lower())
        mock_session_cls.return_value.fetch_token.assert_not_called()

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_userinfo_groups(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": self._make_id_token(
                extra_claims={"sub": "bob", "name": "Bob"},
            ),
        }
        mock_userinfo_response = MagicMock()
        mock_userinfo_response.json.return_value = {"groups": ["admins"]}
        mock_userinfo_response.raise_for_status = MagicMock()
        mock_session.get.side_effect = [
            self._jwks_response(),
            mock_userinfo_response,
        ]

        auth_request = self._auth_request()
        authorization_response = (
            "https://app.example.com/callback?code=auth-code&state=state-1"
        )

        user = self.authentifier.complete_authorization(
            authorization_response, auth_request
        )

        self.assertEqual(user.login, "bob")
        self.assertEqual(user.groups, ["admins"])
        self.assertEqual(mock_session.get.call_count, 2)
        mock_session.get.assert_any_call(self.metadata["userinfo_endpoint"])

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_restricted_groups_allowed(self, mock_session_cls):
        self.authentifier.restricted_groups = ["admins"]
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": self._make_id_token(extra_claims={"groups": ["admins"]}),
        }
        mock_session.get.return_value = self._jwks_response()

        user = self.authentifier.complete_authorization(
            "https://app.example.com/callback?code=c&state=state-1",
            self._auth_request(),
        )
        self.assertEqual(user.groups, ["admins"])

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_restricted_groups_rejected(self, mock_session_cls):
        self.authentifier.restricted_groups = ["admins"]
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": self._make_id_token(extra_claims={"groups": ["users"]}),
        }
        mock_session.get.return_value = self._jwks_response()

        with self.assertRaises(OIDCAuthenticationError) as ctx:
            self.authentifier.complete_authorization(
                "https://app.example.com/callback?code=c&state=state-1",
                self._auth_request(),
            )
        self.assertIn("restricted groups", str(ctx.exception))

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_at_hash_valid(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        access_token = "access-token-value"
        at_hash = create_half_hash(access_token, "RS256").decode()
        mock_session.fetch_token.return_value = {
            "access_token": access_token,
            "id_token": self._make_id_token(extra_claims={"at_hash": at_hash}),
        }
        mock_session.get.return_value = self._jwks_response()

        user = self.authentifier.complete_authorization(
            "https://app.example.com/callback?code=c&state=state-1",
            self._auth_request(),
        )
        self.assertEqual(user.login, "alice")

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_at_hash_mismatch(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access-token-value",
            "id_token": self._make_id_token(extra_claims={"at_hash": "wrong-hash"}),
        }
        mock_session.get.return_value = self._jwks_response()

        with self.assertRaises(OIDCAuthenticationError) as ctx:
            self.authentifier.complete_authorization(
                "https://app.example.com/callback?code=c&state=state-1",
                self._auth_request(),
            )
        self.assertIn("id_token", str(ctx.exception))

    @patch("rfl.authentication.oidc.jwt")
    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_invalid_id_token(self, mock_session_cls, mock_jwt):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": "not-a-valid-jwt",
        }
        mock_session.get.return_value = self._jwks_response()
        mock_jwt.decode.side_effect = ValueError("bad signature")

        with self.assertRaises(OIDCAuthenticationError) as ctx:
            self.authentifier.complete_authorization(
                "https://app.example.com/callback?code=c&state=state-1",
                self._auth_request(),
            )
        self.assertIn("id_token", str(ctx.exception))
        mock_jwt.decode.assert_called_once()

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_complete_authorization_missing_id_token(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session_cls.return_value.fetch_token.return_value = {
            "access_token": "access"
        }

        with self.assertRaises(OIDCAuthenticationError) as ctx:
            self.authentifier.complete_authorization(
                "https://app.example.com/callback?code=c&state=state-1",
                self._auth_request(),
            )
        self.assertIn("id_token", str(ctx.exception))

    @patch("rfl.authentication.oidc.OAuth2Session")
    def test_groups_claim_as_string(self, mock_session_cls):
        self.authentifier._discovery_metadata = self.metadata
        mock_session = mock_session_cls.return_value
        mock_session.fetch_token.return_value = {
            "access_token": "access",
            "id_token": self._make_id_token(extra_claims={"groups": "users"}),
        }
        mock_session.get.return_value = self._jwks_response()

        user = self.authentifier.complete_authorization(
            "https://app.example.com/callback?code=c&state=state-1",
            self._auth_request(),
        )
        self.assertEqual(user.groups, ["users"])
