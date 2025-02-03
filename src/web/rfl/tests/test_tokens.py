# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import tempfile
import json
from pathlib import Path

import flask
import werkzeug

from rfl.web.tokens import RFLTokenizedRBACWebApp, check_jwt, rbac_action
from rfl.authentication.user import AuthenticatedUser, AnonymousUser
from rfl.permissions.rbac import ANONYMOUS_ROLE

VALID_DEFINITION = """
actions:
  view-users: View all users information
  add-users: Add users to the system
  view-tasks: View all tasks on the system
  launch-tasks: Launch tasks on the system
  edit-tasks: Edit all submitted tasks
"""

VALID_ROLES = """
[roles]
anonymous
# All authenticated users have the base role
user=@users,mike,lisa
operator=lisa
administrator=john,@admins

# The anonymous role is permitted to perform all view-* actions.
[anonymous]
actions=view-tasks

# "user" role is permitted to perform all anonymous actions and launch-tasks action.
[user]
actions=@anonymous,launch-tasks

[operator]
actions=edit-tasks

# "administrator" role is permitted to perform all anonymous and user actions, augmented
# with edit-tasks and add-users actions.
[administrator]
actions=@user,@operator,add-users
"""


class RFLCustomTestResponse(flask.Response):
    """Custom flask Response class to backport text property of
    werkzeug.test.TestResponse class on werkzeug < 0.15."""

    @property
    def text(self):
        return self.get_data(as_text=True)

    @property
    def json(self):
        if self.mimetype != "application/json":
            return None
        return json.loads(self.text)


class TestingFlaskApp(flask.Flask, RFLTokenizedRBACWebApp):
    def __init__(self, anonymous_enabled=True):
        # Generate JWT signing key
        key = tempfile.NamedTemporaryFile(mode="w+")
        key.write("hey")
        key.seek(0)
        policy = tempfile.NamedTemporaryFile(mode="w+")
        policy.write(VALID_DEFINITION)
        policy.seek(0)
        roles = tempfile.NamedTemporaryFile(mode="w+")
        roles.write(VALID_ROLES)
        roles.seek(0)
        RFLTokenizedRBACWebApp.__init__(
            self, "rfl", "HS256", Path(key.name), Path(policy.name), Path(roles.name)
        )

        if not anonymous_enabled:
            for role in self.policy.loader.roles.copy():
                if role.name == ANONYMOUS_ROLE:
                    self.policy.loader.roles.remove(role)
        key.close()
        policy.close()
        roles.close()
        flask.Flask.__init__(self, "rfl.web")
        self.config.update(
            {
                "TESTING": True,
            }
        )

        # werkzeug.test.TestResponse class does not have text and json
        # properties in werkzeug <= 0.15. When such version is installed, use
        # custom test response class to backport these text and json properties.
        try:
            getattr(werkzeug.test.TestResponse, "text")
            getattr(werkzeug.test.TestResponse, "json")
        except AttributeError:
            self.response_class = RFLCustomTestResponse
        self.add_url_rule("/no-check", view_func=endpoint_no_check)
        self.add_url_rule("/check-jwt", view_func=endpoint_check_jwt)
        self.add_url_rule("/view-tasks", view_func=endpoint_view_tasks)
        self.add_url_rule("/launch-tasks", view_func=endpoint_launch_tasks)
        self.add_url_rule("/edit-tasks", view_func=endpoint_edit_tasks)

        # register generic error handler
        for error in [401, 403, 404, 500, 501]:
            self.register_error_handler(error, self._handle_bad_request)

    def _handle_bad_request(self, error):
        return (
            flask.jsonify(error.description),
            error.code,
        )


def endpoint_no_check():
    return flask.jsonify("test no check")


@check_jwt
def endpoint_check_jwt():
    return flask.jsonify("test check jwt")


@rbac_action("view-tasks")
def endpoint_view_tasks():
    return flask.jsonify("test view tasks")


@rbac_action("launch-tasks")
def endpoint_launch_tasks():
    return flask.jsonify("test launch tasks")


@rbac_action("edit-tasks")
def endpoint_edit_tasks():
    return flask.jsonify("test edit tasks")


class TestRFLTokenizedRBACWebApp(unittest.TestCase):

    def setupClient(self, use_token=True, anonymous_token=False, user_admin=False):
        # Get token valid to get user role with all permissions as defined in
        # default policy.
        self.client = self.app.test_client()
        if use_token:
            if anonymous_token:
                self.user = AnonymousUser()
            else:
                self.user = AuthenticatedUser(
                    login="test",
                    fullname="Testing User",
                    groups=["admins" if user_admin else "users"],
                )
            token = self.app.jwt.generate(
                user=self.user,
                duration=3600,
            )
            self.client.environ_base["HTTP_AUTHORIZATION"] = "Bearer " + token

    def test_no_token(self):
        self.app = TestingFlaskApp()
        self.setupClient(use_token=False)

        response = self.client.get("/no-check")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test no check")

        response = self.client.get("/check-jwt")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

        response = self.client.get("/view-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

        response = self.client.get("/launch-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json,
            "Not allowed to access endpoint without bearer token",
        )

        response = self.client.get("/edit-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

    def test_no_token_anonymous_disabled(self):
        self.app = TestingFlaskApp(anonymous_enabled=False)
        self.setupClient(use_token=False)

        response = self.client.get("/no-check")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test no check")

        response = self.client.get("/check-jwt")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

        response = self.client.get("/view-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

        response = self.client.get("/launch-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json,
            "Not allowed to access endpoint without bearer token",
        )

        response = self.client.get("/edit-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Not allowed to access endpoint without bearer token"
        )

    def test_anonymous_token(self):
        self.app = TestingFlaskApp()
        self.setupClient(anonymous_token=True)

        response = self.client.get("/no-check")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test no check")

        response = self.client.get("/check-jwt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test check jwt")

        response = self.client.get("/view-tasks")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test view tasks")

        response = self.client.get("/launch-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json,
            "Anonymous role is not allowed to perform action launch-tasks",
        )

        response = self.client.get("/edit-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Anonymous role is not allowed to perform action edit-tasks"
        )

    def test_anonymous_token_anonymous_disabled(self):
        self.app = TestingFlaskApp(anonymous_enabled=False)
        self.setupClient(anonymous_token=True)

        response = self.client.get("/no-check")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test no check")

        response = self.client.get("/check-jwt")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, "test check jwt")

        response = self.client.get("/view-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Anonymous role is not allowed to perform action view-tasks"
        )

        response = self.client.get("/launch-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json,
            "Anonymous role is not allowed to perform action launch-tasks",
        )

        response = self.client.get("/edit-tasks")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json, "Anonymous role is not allowed to perform action edit-tasks"
        )

    def test_authenticated_user(self):
        for anonymous_enabled in [True, False]:
            self.app = TestingFlaskApp(anonymous_enabled=anonymous_enabled)
            self.setupClient()

            response = self.client.get("/no-check")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test no check")

            response = self.client.get("/check-jwt")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test check jwt")

            response = self.client.get("/view-tasks")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test view tasks")

            response = self.client.get("/launch-tasks")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test launch tasks")

            response = self.client.get("/edit-tasks")
            self.assertEqual(response.status_code, 403)
            self.assertEqual(
                response.json,
                "user test (∅) [users] is not allowed to perform action edit-tasks",
            )

    def test_authenticated_admin(self):
        for anonymous_enabled in [True, False]:
            self.app = TestingFlaskApp(anonymous_enabled=anonymous_enabled)
            self.setupClient(user_admin=True)

            response = self.client.get("/no-check")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test no check")

            response = self.client.get("/check-jwt")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test check jwt")

            response = self.client.get("/view-tasks")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test view tasks")

            response = self.client.get("/launch-tasks")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test launch tasks")

            response = self.client.get("/edit-tasks")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json, "test edit tasks")
