# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import configparser
import logging
from pathlib import Path
from typing import Set, Tuple

try:
    from functools import cached_property
except ImportError:
    # For Python 3.[6-7] compatibility. The dependency to cached_property
    # external library is not declared in setup.py, it is added explicitely in
    # packages codes only for distributions stuck with these old versions of
    # Python.
    #
    # This try/except block can be removed when support of Python < 3.8 is
    # dropped in Fatbuildr.
    from cached_property import cached_property

from rfl.authentication.user import AuthenticatedUser
import yaml

from .errors import RBACPolicyDefinitionLoadError, RBACPolicyRolesLoadError


logger = logging.getLogger(__name__)

ANONYMOUS_ROLE = "anonymous"
ALL_MEMBER = "ALL"


class RBACPolicyRole:
    def __init__(self, name: str, members: Set[str], actions: Set[str]):
        self.name = name
        self.members = members
        self.actions = actions

    def __repr__(self):
        return f"{self.name} [ members: {self.members}, actions: {self.actions} ]"


class RBACPolicyDefinitionLoader:
    pass


class RBACPolicyDefinitionYAMLLoader(RBACPolicyDefinitionLoader):
    def __init__(self, path: Path = None, raw: str = None):
        try:
            if raw is not None:
                content = yaml.safe_load(raw)
            elif path is not None:
                try:
                    with open(path) as fh:
                        content = yaml.safe_load(fh)
                except FileNotFoundError:
                    raise RBACPolicyDefinitionLoadError(
                        f"Policy definition file {path} not found"
                    )
            else:
                raise RBACPolicyDefinitionLoadError(
                    "Either a raw string value or a path must be given to load YAML "
                    "policy definition"
                )
        except yaml.parser.ParserError as err:
            raise RBACPolicyDefinitionLoadError(
                f"Invalid YAML policy definition: {str(err)}"
            ) from err
        try:
            self.actions = set(content["actions"].keys())
        except KeyError as err:
            raise RBACPolicyDefinitionLoadError(
                "Actions key not found in YAML policy definition"
            ) from err
        except AttributeError as err:
            raise RBACPolicyDefinitionLoadError(
                "Unable to extract the set of actions from actions key in YAML policy "
                "definition"
            ) from err


class RBACPolicyRolesLoader:
    pass


class RBACPolicyRolesIniLoader(RBACPolicyRolesLoader):
    def __init__(
        self,
        definition: RBACPolicyDefinitionLoader,
        path: Path = None,
        raw: str = None,
        preload: bool = True,
    ):
        self.definition = definition
        self.content = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
            allow_no_value=True,
        )
        try:
            if raw is not None:
                logger.debug("Loading settings in INI format from raw value")
                self.content.read_string(raw)
            elif path is not None:
                logger.debug("Loading settings file %s", path)
                self.content.read(path)
            else:
                raise RBACPolicyRolesLoadError(
                    "Either a raw string value or a path must be given to load site "
                    "settings"
                )
        except configparser.Error as err:
            raise RBACPolicyDefinitionLoadError(str(err)) from err
        self.roles = set()
        if preload:
            self._load()

    def _load(self):
        """Load the set of PolicyRoles defined in file pointed by the given path."""
        try:
            roles = self.content.options("roles")
        except configparser.NoSectionError as err:
            raise RBACPolicyRolesLoadError(
                "Section roles to define roles members is not defined in INI content"
            ) from err
        for role in roles:
            try:
                actions = self._expand_actions(self.content.get(role, "actions"))
            except configparser.NoSectionError as err:
                raise RBACPolicyRolesLoadError(
                    f"Section to define actions for role {role} is not defined in INI "
                    "content"
                ) from err
            except configparser.NoOptionError as err:
                raise RBACPolicyRolesLoadError(
                    f"Option to define actions for role {role} is not defined in INI "
                    "content"
                ) from err
            if role == ANONYMOUS_ROLE:
                members = None
            else:
                members = self._expand_members(self.content.get("roles", role))
            self.roles.add(RBACPolicyRole(role, members, actions))

    def _expand_actions(self, actions_str):
        """Return the set of actions declared in comma-separated list provided in
        actions_str argument. If an item is prefixed by @, the set is expanded with the
        actions of the role name that follows."""
        actions = set()
        for action in actions_str.split(","):
            if action.startswith("@"):
                actions.update(self._role_actions(action[1:]))
            else:
                if action not in self.definition.actions:
                    raise RBACPolicyRolesLoadError(
                        f"Action {action} not found in policy definition"
                    )
                actions.add(action)
        return actions

    def _expand_members(self, members_str):
        """Return the set of members declared in comma-separated list provided in
        members_str argument."""
        return set(members_str.split(","))

    def _role_actions(self, role):
        """Return the set of actions allowed the to given role. Raise
        RBACPolicyVerificationError if the role is not found in policy."""
        for _role in self.roles:
            if _role.name == role:
                return _role.actions

        raise RBACPolicyRolesLoadError(
            f"Unable to inherit actions from role {role} not found in policy"
        )


class RBACPolicyManager:
    def __init__(self, loader: RBACPolicyRolesLoader):
        self.loader = loader

    @cached_property
    def allow_anonymous(self) -> bool:
        """Return True if the anonymous role is declared in policy, False otherwise."""
        for role in self.loader.roles:
            if role.name == ANONYMOUS_ROLE:
                return True
        return False

    def _user_roles(self, user: AuthenticatedUser) -> Set[str]:
        """Return the set of roles associated to a given user name."""
        roles = set()
        for role in self.loader.roles:
            # anonymous role or role with ALL authenticated members
            if role.members is None or ALL_MEMBER in role.members:
                roles.add(role)
            else:
                for member in role.members:
                    if member == user.login or (
                        member.startswith("@") and member[1:] in user.groups
                    ):
                        roles.add(role)
        logger.debug("Found the following roles for user %s: %s", user, roles)
        return roles

    def roles_actions(self, user: AuthenticatedUser) -> Tuple[Set[str], Set[str]]:
        """Return tuple with set of role names and set of allowed actions for a
        particular user and list of groups membership."""
        roles = self._user_roles(user)
        actions = set()
        for role in roles:
            actions.update(role.actions)
        return (set([role.name for role in roles]), actions)

    def allowed_anonymous_action(self, action: str) -> bool:
        """Return True if the given action is allowed for anonymous role, False
        otherwise."""
        for role in self.loader.roles:
            if role.name == ANONYMOUS_ROLE and action in role.actions:
                return True
        return False

    def allowed_user_action(self, user: AuthenticatedUser, action: str) -> bool:
        """Return True if the given action is allowed for the given user, False
        otherwise."""
        for role in self._user_roles(user):
            if action in role.actions:
                logger.debug(
                    "Token for user %s is permitted to perform action %s",
                    user,
                    action,
                )
                return True
        logger.warning(
            "Token for user %s is not authorized to perform action %s",
            user,
            action,
        )
        return False

    @classmethod
    def yaml_definition_ini_roles(cls, definition: Path, roles: Path):
        return cls(
            RBACPolicyRolesIniLoader(
                definition=RBACPolicyDefinitionYAMLLoader(path=definition), path=roles
            )
        )
