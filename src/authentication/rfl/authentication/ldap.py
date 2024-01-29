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
        starttls: bool = False,
        bind_dn: Union[str, None] = None,
        bind_password: Union[str, None] = None,
    ):
        self.uri = uri
        self.cacert = cacert
        self.user_base = user_base
        self.user_class = user_class
        self.group_base = group_base
        self.user_fullname_attribute = user_fullname_attribute
        self.group_name_attribute = group_name_attribute
        self.starttls = starttls
        self.bind_dn = bind_dn
        self.bind_password = bind_password

    def connection(self):
        connection = ldap.initialize(self.uri.geturl())
        # SSL/TLS setup
        if self.uri.geturl().startswith("ldaps") or self.starttls:
            connection.protocol_version = ldap.VERSION3
            # Force server certificate validation
            connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            # For LDAPS and STARTTLS, libldap require the path to CA certificates to be
            # defined to authentication server certificate. If the cacert option is
            # defined, use it else use default system CA certificates directory defined
            # in OpenSSL library.
            if self.cacert is None:
                import ssl

                logger.debug(
                    "Using default system OpenSSL CA certificate directory to "
                    "authenticate server"
                )
                connection.set_option(
                    ldap.OPT_X_TLS_CACERTDIR,
                    ssl.get_default_verify_paths().openssl_capath,
                )
            else:
                logger.debug(
                    "Using CA certification %s to authenticate server", self.cacert
                )
                connection.set_option(ldap.OPT_X_TLS_CACERTFILE, str(self.cacert))
            # Force libldap to create a new SSL context
            connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        if self.starttls:
            try:
                logger.debug("Using STARTTLS to initialize TLS connection")
                connection.start_tls_s()
            except ldap.CONNECT_ERROR as err:
                raise LDAPAuthenticationError(
                    f"Unable to connect to LDAP server with STARTTLS: {str(err)}"
                ) from err
        return connection

    def _get_user_info(
        self, connection: ldap.ldapobject.LDAPObject, user_dn: str
    ) -> tuple[str, int]:
        """Return fullname and gidNumber from the provided user DN."""
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
        """Return the list of groups whose provided user is member, including its
        gidNumber. This function support RFC 2307 (aka. nis schema)."""
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
        """Verify provided user/password are valid and return the corresponding
        AuthenticatedUser."""
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

    def _list_user_dn(self, connection):
        """Return list of all users name/pairs pairs in LDAP directory."""
        search_filter = f"(objectClass={self.user_class})"
        try:
            results = connection.search_s(
                self.user_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                ["uid"],
            )
        except ldap.NO_SUCH_OBJECT as err:
            raise LDAPAuthenticationError(
                f"Unable to find user base {self.user_base}"
            ) from err
        logger.debug(
            "LDAP search base: %s, scope: subtree, filter: %s, results: %s",
            self.group_base,
            search_filter,
            str(results),
        )
        if not len(results):
            logger.warning(
                "Unable to find users in LDAP in base %s subtree",
                self.user_base,
            )
        try:
            return [(result[1]["uid"][0].decode(), result[0]) for result in results]
        except KeyError as err:
            raise LDAPAuthenticationError(
                "Unable to extract user uid from user entries"
            ) from err

    def users(self, with_groups: bool = False) -> list[AuthenticatedUser]:
        """Return list of AuthicatedUser available in LDAP directory. If with_groups is
        True, the groups attribute of the AuthenticatedUsers is also initialized with
        the list of their groups."""
        result = []
        connection = self.connection()

        if self.bind_dn is not None:
            logger.debug("Using DN %s to bind to LDAP directory", self.bind_dn)
            try:
                assert self.bind_password is not None
            except AssertionError as err:
                raise LDAPAuthenticationError(
                    f"Password to authenticate with bind DN {self.bind_dn} is required"
                ) from err
            try:
                connection.simple_bind_s(self.bind_dn, self.bind_password)
            except ldap.INVALID_CREDENTIALS as err:
                raise LDAPAuthenticationError("Invalid bind DN or password") from err

        try:
            for (user, user_dn) in self._list_user_dn(connection):
                fullname, gidNumber = self._get_user_info(connection, user_dn)
                groups = []
                if with_groups:
                    groups = self._get_groups(connection, user, gidNumber)
                result.append(
                    AuthenticatedUser(login=user, fullname=fullname, groups=groups)
                )
        except ldap.SERVER_DOWN as err:
            raise LDAPAuthenticationError(
                f"LDAP server {self.uri.geturl()} is unreachable"
            ) from err
        except ldap.UNWILLING_TO_PERFORM as err:
            raise LDAPAuthenticationError(
                f"LDAP server is unwilling to perform: {str(err)}"
            ) from err
        finally:
            connection.unbind_s()
        return result
