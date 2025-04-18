# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest

from rfl.authentication.user import AuthenticatedUser, AnonymousUser
from rfl.permissions.rbac import (
    RBACPolicyRole,
    RBACPolicyDefinitionYAMLLoader,
    RBACPolicyRolesIniLoader,
    RBACPolicyManager,
)
from rfl.permissions.errors import (
    RBACPolicyDefinitionLoadError,
    RBACPolicyRolesLoadError,
)

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
base=ALL
user=@users,mike,lisa
operator=lisa
administrator=john,@admins

# The anonymous role is permitted to perform all view-* actions.
[anonymous]
actions=view-tasks

[base]
actions=view-users

# "user" role is permitted to perform all anonymous actions and launch-tasks action.
[user]
actions=launch-tasks

[operator]
actions=edit-tasks

# "administrator" role is permitted to perform all anonymous and user actions, augmented
# with edit-tasks and add-users actions.
[administrator]
actions=@user,@operator,add-users
"""


class TestRBACPolicyDefinitionYAMLLoader(unittest.TestCase):
    def test_load_valid_definition(self):
        loader = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        self.assertEqual(
            loader.actions,
            {"view-users", "add-users", "view-tasks", "launch-tasks", "edit-tasks"},
        )

    def test_load_invalid_yaml(self):
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Invalid YAML policy definition: while parsing a block mapping",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION + "\n fail")

    def test_load_invalid_actions_key(self):
        raw_definition = "fail:" + VALID_DEFINITION[6:]
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Actions key not found in YAML policy definition$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=raw_definition)

    def test_load_invalid_actions_content(self):
        raw_definition = "actions: fail"
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Unable to extract the set of actions from actions key in YAML policy "
            r"definition$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=raw_definition)


class TestRBACPolicyRolesIniLoader(unittest.TestCase):
    def test_load_valid_roles(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        self.assertEqual(len(loader.roles), 5)
        for role in loader.roles:
            self.assertIsInstance(role, RBACPolicyRole)
            self.assertIn(
                role.name, ["anonymous", "base", "user", "operator", "administrator"]
            )
            if role.name == "user":
                self.assertEqual(role.actions, {"launch-tasks"})
                self.assertEqual(role.members, {"mike", "@users", "lisa"})
            elif role.name == "administrator":
                self.assertEqual(
                    role.actions, {"launch-tasks", "edit-tasks", "add-users"}
                )
                self.assertEqual(role.members, {"john", "@admins"})

    def test_load_roles_missing_roles_section(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.remove_section("roles")
        with self.assertRaisesRegex(
            RBACPolicyRolesLoadError,
            r"^Section roles to define roles members is not defined in INI content$",
        ):
            loader._load()

    def test_load_roles_missing_role_section(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.remove_section("administrator")
        with self.assertRaisesRegex(
            RBACPolicyRolesLoadError,
            r"^Section to define actions for role administrator is not defined in INI "
            r"content$",
        ):
            loader._load()

    def test_load_roles_missing_role_option(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.remove_option("administrator", "actions")
        with self.assertRaisesRegex(
            RBACPolicyRolesLoadError,
            r"^Option to define actions for role administrator is not defined in INI "
            r"content$",
        ):
            loader._load()

    def test_load_roles_undefined_action(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.set("administrator", "actions", "fail")
        with self.assertRaisesRegex(
            RBACPolicyRolesLoadError,
            r"^Action fail not found in policy definition$",
        ):
            loader._load()

    def test_load_roles_undefined_expand(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.set("administrator", "actions", "@fail")
        with self.assertRaisesRegex(
            RBACPolicyRolesLoadError,
            r"^Unable to inherit actions from role fail not found in policy$",
        ):
            loader._load()


class TestRBACPolicyManager(unittest.TestCase):
    def test_manager_init(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        self.assertTrue(manager.allow_anonymous)

    def test_manager_disable_anonymous(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        self.assertTrue(manager.allow_anonymous)
        manager.disable_anonymous()
        self.assertFalse(manager.allow_anonymous)

    def test_manager_load_wo_anonymous(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.remove_option("roles", "anonymous")
        loader._load()
        manager = RBACPolicyManager(loader)
        self.assertFalse(manager.allow_anonymous)

    def test_manager_roles_actions(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        self.assertEqual(
            manager.roles_actions(AuthenticatedUser(login="FAKE", groups=["users"])),
            (
                {"user", "base"},
                {"launch-tasks", "view-users"},
            ),
        )
        self.assertEqual(
            manager.roles_actions(AuthenticatedUser(login="lisa", groups=["FAKE"])),
            (
                {"operator", "base", "user"},
                {"launch-tasks", "view-users", "edit-tasks"},
            ),
        )
        self.assertEqual(
            manager.roles_actions(AuthenticatedUser(login="FAKE", groups=["admins"])),
            (
                {"base", "administrator"},
                {"edit-tasks", "add-users", "launch-tasks", "view-users"},
            ),
        )

    def test_manager_roles_actions_unknown_user(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        manager = RBACPolicyManager(loader)
        # Remove the base role for all authenticated users so unknown user could not be
        # associated to any role defined in policy.
        loader.content.remove_option("roles", "base")
        loader._load()
        manager = RBACPolicyManager(loader)
        self.assertEqual(
            manager.roles_actions(AuthenticatedUser(login="FAKE", groups=["unknown"])),
            (set(), set()),
        )

    def test_manager_roles_actions_anonymous(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        self.assertEqual(
            manager.roles_actions(AnonymousUser()),
            ({"anonymous"}, {"view-tasks"}),
        )

    def test_manager_roles_actions_anonymous_disabled(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(
            definition=definition, raw=VALID_ROLES, preload=False
        )
        loader.content.remove_option("roles", "anonymous")
        loader._load()
        manager = RBACPolicyManager(loader)
        self.assertFalse(manager.allow_anonymous)
        self.assertEqual(
            manager.roles_actions(AnonymousUser()),
            (set(), set()),
        )

    def test_manager_allowed_anonymous_action(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        self.assertEqual(manager.allowed_anonymous_action("view-tasks"), True)
        self.assertEqual(manager.allowed_anonymous_action("view-users"), False)
        self.assertEqual(manager.allowed_anonymous_action("launch-tasks"), False)

    def test_manager_allowed_anonymous_user_action(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        user = AnonymousUser()
        self.assertEqual(manager.allowed_user_action(user, "view-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "view-users"), False)
        self.assertEqual(manager.allowed_user_action(user, "launch-tasks"), False)

    def test_manager_allowed_user_action(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        loader = RBACPolicyRolesIniLoader(definition=definition, raw=VALID_ROLES)
        manager = RBACPolicyManager(loader)
        # Members of users group must have access to base and user roles actions but not
        # to anonymous and operator role actions.
        user = AuthenticatedUser(login="FAKE", groups=["users"])
        self.assertEqual(manager.allowed_user_action(user, "view-users"), True)
        self.assertEqual(manager.allowed_user_action(user, "launch-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "view-tasks"), False)
        self.assertEqual(manager.allowed_user_action(user, "edit-tasks"), False)

        # Mike (user) must have access to user role actions but not to operator role
        # actions.
        user = AuthenticatedUser(login="mike", groups=["FAKE"])
        self.assertEqual(manager.allowed_user_action(user, "launch-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "edit-tasks"), False)

        # Members of admins group must have access to all actions
        user = AuthenticatedUser(login="FAKE", groups=["admins"])
        self.assertEqual(manager.allowed_user_action(user, "view-users"), True)
        self.assertEqual(manager.allowed_user_action(user, "edit-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "add-users"), True)

        # John (admin) must have access to all actions except those not declared.
        user = AuthenticatedUser(login="john", groups=["FAKE"])
        self.assertEqual(manager.allowed_user_action(user, "view-users"), True)
        self.assertEqual(manager.allowed_user_action(user, "fail"), False)

        # Lisa (user + operator) must have access to base, user and operator roles
        # actions but not to anonymous and admin role actions.
        user = AuthenticatedUser(login="lisa", groups=["users"])
        self.assertEqual(manager.allowed_user_action(user, "edit-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "view-users"), True)
        self.assertEqual(manager.allowed_user_action(user, "launch-tasks"), True)
        self.assertEqual(manager.allowed_user_action(user, "view-tasks"), False)
        self.assertEqual(manager.allowed_user_action(user, "add-users"), False)
