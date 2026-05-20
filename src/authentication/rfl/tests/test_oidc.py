# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import unittest
from unittest.mock import MagicMock, patch

import flask

try:
    from authlib.integrations.base_client import OAuthError

    from rfl.authentication.errors import OIDCAuthenticationError
    from rfl.authentication.oidc import OIDCClient
    from rfl.authentication.user import AuthenticatedUser
except ImportError:
    AUTHLIB_AVAILABLE = False
else:
    AUTHLIB_AVAILABLE = True


@unittest.skipUnless(AUTHLIB_AVAILABLE, "authlib is not installed")
class TestOIDCClient(unittest.TestCase):
    def setUp(self):
        self.app = flask.Flask(__name__)
        self.app.secret_key = "test-secret"

    def _make_client(self, **kwargs):
        defaults = {
            "issuer": "https://idp.example.com",
            "client_id": "client-id",
            "client_secret": "client-secret",
            "redirect_uri": "https://app.example.com/callback",
        }
        defaults.update(kwargs)
        with self.app.app_context():
            return OIDCClient(self.app, **defaults)

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_registers_client(self, mock_oauth_cls):
        mock_oauth = mock_oauth_cls.return_value
        mock_client = MagicMock()
        mock_oauth.register.return_value = mock_client

        client = self._make_client(scope="openid email", cacert="/etc/ssl/ca.pem")

        mock_oauth_cls.assert_called_once_with(
            self.app,
            cache=None,
            fetch_token=None,
            update_token=None,
        )
        mock_oauth.register.assert_called_once_with(
            "rfl_oidc",
            client_id="client-id",
            client_secret="client-secret",
            server_metadata_url="https://idp.example.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid email",
                "verify": "/etc/ssl/ca.pem",
            },
        )
        self.assertIs(client._client, mock_client)

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_with_pkce(self, mock_oauth_cls):
        mock_oauth_cls.return_value.register.return_value = MagicMock()

        self._make_client(pkce="S256")

        register_kwargs = mock_oauth_cls.return_value.register.call_args.kwargs
        self.assertEqual(
            register_kwargs["client_kwargs"]["code_challenge_method"],
            "S256",
        )

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_without_pkce(self, mock_oauth_cls):
        mock_oauth_cls.return_value.register.return_value = MagicMock()

        self._make_client()

        register_kwargs = mock_oauth_cls.return_value.register.call_args.kwargs
        self.assertNotIn("code_challenge_method", register_kwargs["client_kwargs"])

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_public_client(self, mock_oauth_cls):
        mock_oauth_cls.return_value.register.return_value = MagicMock()

        client = self._make_client(client_secret=None, pkce="S256")

        mock_oauth_cls.return_value.register.assert_called_once_with(
            "rfl_oidc",
            client_id="client-id",
            client_secret=None,
            server_metadata_url="https://idp.example.com/.well-known/openid-configuration",
            client_kwargs={
                "scope": "openid profile email",
                "verify": True,
                "code_challenge_method": "S256",
            },
        )
        self.assertIsNone(client.client_secret)

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_public_client_empty_secret(self, mock_oauth_cls):
        mock_oauth_cls.return_value.register.return_value = MagicMock()

        client = self._make_client(client_secret="", pkce="S256")

        register_kwargs = mock_oauth_cls.return_value.register.call_args.kwargs
        self.assertIsNone(register_kwargs["client_secret"])
        self.assertIsNone(client.client_secret)

    @patch("rfl.authentication.oidc.OAuth")
    def test_init_public_client_requires_pkce(self, mock_oauth_cls):
        with self.assertRaisesRegex(
            OIDCAuthenticationError,
            "PKCE is required for public OIDC clients",
        ):
            self._make_client(client_secret=None, pkce=None)

        mock_oauth_cls.return_value.register.assert_not_called()

    @patch("rfl.authentication.oidc.OAuth")
    def test_redirect_uses_default_redirect_uri(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_response = MagicMock()
        mock_client.authorize_redirect.return_value = mock_response

        client = self._make_client()
        with self.app.test_request_context():
            response = client.redirect()

        mock_client.authorize_redirect.assert_called_once_with(
            redirect_uri="https://app.example.com/callback",
        )
        self.assertIs(response, mock_response)

    @patch("rfl.authentication.oidc.OAuth")
    def test_redirect_custom_redirect_uri(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client

        client = self._make_client()
        with self.app.test_request_context():
            client.redirect(redirect_uri="https://other.example/cb")

        mock_client.authorize_redirect.assert_called_once_with(
            redirect_uri="https://other.example/cb",
        )

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_returns_authenticated_user(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {
                "sub": "alice",
                "name": "Alice",
                "groups": ["users", "admins"],
            },
        }

        client = self._make_client()
        with self.app.test_request_context():
            user = client.authenticate()

        self.assertIsInstance(user, AuthenticatedUser)
        self.assertEqual(user.login, "alice")
        self.assertEqual(user.fullname, "Alice")
        self.assertEqual(user.groups, ["users", "admins"])

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_custom_claims(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {
                "uid": "bob",
                "displayName": "Bob",
                "memberOf": "operators",
            },
        }

        client = self._make_client(
            subject_claim="uid",
            fullname_claim="displayName",
            groups_claim="memberOf",
        )
        with self.app.test_request_context():
            user = client.authenticate()

        self.assertEqual(user.login, "bob")
        self.assertEqual(user.fullname, "Bob")
        self.assertEqual(user.groups, ["operators"])

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_missing_userinfo(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {"access_token": "tok"}

        client = self._make_client()
        with self.app.test_request_context():
            with self.assertRaisesRegex(
                OIDCAuthenticationError,
                "validated userinfo",
            ):
                client.authenticate()

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_missing_subject(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {"name": "Alice"},
        }

        client = self._make_client()
        with self.app.test_request_context():
            with self.assertRaisesRegex(
                OIDCAuthenticationError,
                r"subject claim sub",
            ):
                client.authenticate()

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_groups_claim_disabled(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {"sub": "alice", "groups": ["admins"]},
        }

        client = self._make_client(groups_claim=None)
        with self.app.test_request_context():
            user = client.authenticate()

        self.assertEqual(user.groups, [])

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_restricted_groups_allowed(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {"sub": "alice", "groups": ["admins", "users"]},
        }

        client = self._make_client(restricted_groups=["admins"])
        with self.app.test_request_context():
            user = client.authenticate()

        self.assertEqual(user.login, "alice")

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_restricted_groups_rejected(self, mock_oauth_cls):
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.return_value = {
            "userinfo": {"sub": "alice", "groups": ["users"]},
        }

        client = self._make_client(restricted_groups=["admins"])
        with self.app.test_request_context():
            with self.assertRaisesRegex(
                OIDCAuthenticationError,
                r"alice.*restricted groups",
            ):
                client.authenticate()

    @patch("rfl.authentication.oidc.OAuth")
    def test_authenticate_oauth_error_translated(self, mock_oauth_cls):
        oauth_error = OAuthError(
            error="access_denied",
            description="User denied access",
        )
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_access_token.side_effect = oauth_error

        client = self._make_client()
        with self.app.test_request_context():
            with self.assertRaisesRegex(
                OIDCAuthenticationError,
                r"OIDC authorization failed: access_denied",
            ) as ctx:
                client.authenticate()

        self.assertIs(ctx.exception.__cause__, oauth_error)

    @patch("rfl.authentication.oidc.OAuth")
    def test_redirect_oauth_error_translated(self, mock_oauth_cls):
        oauth_error = OAuthError(error="mismatching_state")
        mock_client = MagicMock()
        mock_oauth_cls.return_value.register.return_value = mock_client
        mock_client.authorize_redirect.side_effect = oauth_error

        client = self._make_client()
        with self.app.test_request_context():
            with self.assertRaisesRegex(
                OIDCAuthenticationError,
                r"OIDC authorization redirect failed: mismatching_state",
            ) as ctx:
                client.redirect()

        self.assertIs(ctx.exception.__cause__, oauth_error)
