# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Union
from pathlib import Path
import logging

import ldap

from .user import AuthenticatedUser
from .errors import LDAPAuthenticationError


logger = logging.getLogger(__name__)


class LDAPAuthentifier:
    def __init__(
        self,
        uri,
        cacert: Union[Path, None],
        user_base: str,
        user_class: str,
        group_base: str,
        user_fullname_attribute: str,
        group_name_attribute: str,
    ):
        self.uri = uri
        self.cacert = cacert
        self.user_base = user_base
        self.user_class = user_class
        self.group_base = group_base
        self.user_fullname_attribute = user_fullname_attribute
        self.group_name_attribute = group_name_attribute

    def connection(self):
        connection = ldap.initialize(self.uri.geturl())
        # LDAP/SSL setup
        if self.uri.geturl().startswith("ldaps"):
            connection.protocol_version = ldap.VERSION3
            # Force cert validation
            connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            if self.cacert is not None:
                connection.set_option(ldap.OPT_X_TLS_CACERTFILE, str(self.cacert))
            # Force libldap to create a new SSL context
            connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        return connection

    def _get_user_info(
        self, connection: ldap.ldapobject.LDAPObject, user_dn: str
    ) -> tuple[str, int]:
        # Get full username
        search_filter = f"(objectClass={self.user_class})"
        try:
            results = connection.search_s(
                user_dn,
                ldap.SCOPE_BASE,
                search_filter,
                [self.user_fullname_attribute, "gidNumber"],
            )
        except ldap.NO_SUCH_OBJECT as err:
            raise LDAPAuthenticationError(f"Unable to find user DN {user_dn}") from err
        logger.debug(
            "LDAP search base: %s, scope: base filter: %s, results: %s",
            user_dn,
            search_filter,
            str(results),
        )
        if not len(results):
            raise LDAPAuthenticationError(
                f"User not found in LDAP with class {self.user_class}"
            )
        try:
            fullname = results[0][1][self.user_fullname_attribute][0].decode()
        except KeyError as err:
            raise LDAPAuthenticationError(
                f"Unable to extract user full name with {self.group_name_attribute} "
                "attribute from user entries"
            ) from err
        try:
            gidNumber = int(results[0][1]["gidNumber"][0])
        except KeyError as err:
            raise LDAPAuthenticationError(
                "Unable to extract user primary group with gidNumber attribute from "
                "user entries"
            ) from err
        return fullname, gidNumber

    def _get_groups(
        self, connection: ldap.ldapobject.LDAPObject, user: str, gidNumber: int
    ) -> list[str]:
        """Support RFC 2307."""
        search_filter = (
            "(&(objectClass=posixGroup)"
            f"(|(memberUid={user})(gidNumber={gidNumber})))"
        )
        try:
            results = connection.search_s(
                self.group_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                [self.group_name_attribute],
            )
        except ldap.NO_SUCH_OBJECT as err:
            raise LDAPAuthenticationError(
                f"Unable to find group base {self.group_base}"
            ) from err
        logger.debug(
            "LDAP search base: %s, scope: subtree, filter: %s, results: %s",
            self.group_base,
            search_filter,
            str(results),
        )
        if not len(results):
            logger.warning(
                "Unable to find groups in LDAP for user %s or gidNumber %s",
                user,
                gidNumber,
            )
        try:
            return [
                result[1][self.group_name_attribute][0].decode() for result in results
            ]
        except KeyError as err:
            raise LDAPAuthenticationError(
                f"Unable to extract group name with {self.group_name_attribute} "
                "attribute from group entries"
            ) from err

    def login(self, user: str, password: str) -> AuthenticatedUser:
        fullname = None
        groups = None
        connection = self.connection()
        if user is None or password is None:
            raise LDAPAuthenticationError("Invalid authentication request")
        try:
            # Try simple authentication with user/password on LDAP directory
            user_dn = f"uid={user},{self.user_base}"
            connection.simple_bind_s(user_dn, password)
            fullname, gidNumber = self._get_user_info(connection, user_dn)
            groups = self._get_groups(connection, user, gidNumber)
        except ldap.SERVER_DOWN as err:
            raise LDAPAuthenticationError(
                f"LDAP server {self.uri.geturl()} is unreachable"
            ) from err
        except ldap.INVALID_CREDENTIALS as err:
            raise LDAPAuthenticationError("Invalid user or password") from err
        except ldap.UNWILLING_TO_PERFORM as err:
            raise LDAPAuthenticationError(
                f"LDAP server is unwilling to perform: {str(err)}"
            ) from err
        finally:
            connection.unbind_s()
        return AuthenticatedUser(login=user, fullname=fullname, groups=groups)
