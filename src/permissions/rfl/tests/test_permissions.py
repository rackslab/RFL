# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import textwrap
import unittest
import warnings

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
  edit-tasks:
    description: Edit all submitted tasks
"""

DEFINITION_DEPRECATED = """
actions:
  old-action:
    description: Old action
    deprecated: true
    replaced_by: new-action
  old-no-replace:
    description: Old action without replacement
    deprecated: true
  new-action:
    description: New action
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
            set(loader.actions.keys()),
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
            r"^Actions definition must be a mapping of action names to definitions$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=raw_definition)

    def test_load_missing_description(self):
        definition = textwrap.dedent("""
            actions:
              old-action:
                deprecated: true
            """)
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Description is mandatory for action old-action$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=definition)

    def test_load_invalid_deprecated_not_boolean(self):
        definition = textwrap.dedent("""
            actions:
              old-action:
                description: Old action
                deprecated: "true"
            """)
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Invalid deprecated value for action old-action$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=definition)

    def test_load_invalid_replaced_by_list(self):
        definition = textwrap.dedent("""
            actions:
              old-action:
                description: Old action
                deprecated: true
                replaced_by:
                  - a
                  - b
            """)
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Invalid replaced_by value for action old-action$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=definition)

    def test_load_invalid_replaced_by_unknown(self):
        definition = textwrap.dedent("""
            actions:
              old-action:
                description: Old action
                deprecated: true
                replaced_by: missing
            """)
        with self.assertRaisesRegex(
            RBACPolicyDefinitionLoadError,
            r"^Replacement action missing for old-action not found in policy "
            r"definition$",
        ):
            RBACPolicyDefinitionYAMLLoader(raw=definition)

    def test_load_legacy_string_description(self):
        loader = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        expected = {
            "view-users": "View all users information",
            "add-users": "Add users to the system",
            "view-tasks": "View all tasks on the system",
            "launch-tasks": "Launch tasks on the system",
            "edit-tasks": "Edit all submitted tasks",
        }
        self.assertEqual(
            {action: meta.description for action, meta in loader.actions.items()},
            expected,
        )

    def test_apply_non_deprecated_action(self):
        loader = RBACPolicyDefinitionYAMLLoader(raw=VALID_DEFINITION)
        result = loader.apply("view-users")
        self.assertEqual(result, {"view-users"})

    def test_apply_deprecated_action_without_replacement(self):
        loader = RBACPolicyDefinitionYAMLLoader(raw=DEFINITION_DEPRECATED)
        with self.assertWarns(UserWarning) as warning:
            result = loader.apply("old-no-replace")
        self.assertEqual(result, set())
        self.assertIn("Action old-no-replace is deprecated", str(warning.warning))

    def test_apply_deprecated_action_with_replacement(self):
        loader = RBACPolicyDefinitionYAMLLoader(raw=DEFINITION_DEPRECATED)
        with self.assertWarns(UserWarning) as warning:
            result = loader.apply("old-action")
        self.assertEqual(result, {"new-action"})
        self.assertIn("Action old-action is deprecated", str(warning.warning))
        self.assertIn("use new-action instead", str(warning.warning))

    def test_apply_deprecated_action_recursive_replacement(self):
        definition = textwrap.dedent("""
            actions:
              old-action:
                description: Old action
                deprecated: true
                replaced_by: intermediate-action
              intermediate-action:
                description: Intermediate action
                deprecated: true
                replaced_by: final-action
              final-action:
                description: Final action
            """)
        loader = RBACPolicyDefinitionYAMLLoader(raw=definition)
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = loader.apply("old-action")
        self.assertEqual(result, {"final-action"})
        # Should warn about both deprecated actions
        self.assertEqual(len(w), 2, f"Expected 2 warnings, got {len(w)}")
        warnings_messages = [str(warning.message) for warning in w]
        self.assertTrue(
            any("old-action" in msg for msg in warnings_messages),
            f"Expected warning about old-action in {warnings_messages}",
        )
        self.assertTrue(
            any("intermediate-action" in msg for msg in warnings_messages),
            f"Expected warning about intermediate-action in {warnings_messages}",
        )


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

    def test_load_roles_deprecated_replaced(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=DEFINITION_DEPRECATED)
        roles = textwrap.dedent("""
            [roles]
            user=ALL

            [user]
            actions=old-action
            """)
        with self.assertWarns(UserWarning):
            loader = RBACPolicyRolesIniLoader(definition=definition, raw=roles)
        # old-action stripped, new-action added
        user_role = next(role for role in loader.roles if role.name == "user")
        self.assertEqual(user_role.actions, {"new-action"})

    def test_load_roles_deprecated_without_replacement(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=DEFINITION_DEPRECATED)
        roles = textwrap.dedent("""
            [roles]
            user=ALL

            [user]
            actions=old-no-replace
            """)
        with self.assertWarns(UserWarning):
            loader = RBACPolicyRolesIniLoader(definition=definition, raw=roles)
        user_role = next(role for role in loader.roles if role.name == "user")
        self.assertEqual(user_role.actions, set())

    def test_load_roles_inheritance_with_deprecated(self):
        definition = RBACPolicyDefinitionYAMLLoader(raw=DEFINITION_DEPRECATED)
        roles = textwrap.dedent("""
            [roles]
            base=ALL
            user=ALL

            [base]
            actions=old-action

            [user]
            actions=@base
            """)
        with self.assertWarns(UserWarning):
            loader = RBACPolicyRolesIniLoader(definition=definition, raw=roles)
        base_role = next(role for role in loader.roles if role.name == "base")
        user_role = next(role for role in loader.roles if role.name == "user")
        self.assertEqual(base_role.actions, {"new-action"})
        self.assertEqual(user_role.actions, {"new-action"})


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
