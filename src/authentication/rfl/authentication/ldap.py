# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Optional, List, Tuple
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
        user_base: str,
        group_base: str,
        user_class: str = "posixAccount",
        user_name_attribute: str = "uid",
        user_fullname_attribute: str = "cn",
        user_primary_group_attribute: str = "gidNumber",
        group_name_attribute: str = "cn",
        group_object_classes: Optional[List[str]] = None,
        cacert: Optional[Path] = None,
        starttls: bool = False,
        bind_dn: Optional[str] = None,
        bind_password: Optional[str] = None,
        restricted_groups: Optional[List[str]] = None,
    ):
        self.uri = uri
        self.cacert = cacert
        self.user_base = user_base
        self.user_class = user_class
        self.group_base = group_base
        self.user_name_attribute = user_name_attribute
        self.user_fullname_attribute = user_fullname_attribute
        self.user_primary_group_attribute = user_primary_group_attribute
        self.group_name_attribute = group_name_attribute
        if group_object_classes is None:
            # Standard RFC 2307 (aka. NIS) schema has group entries with posixGroup
            # structural class. RFC 2307 bis schema has group entries with generally at
            # least groupOfNames class.
            group_object_classes = ["posixGroup", "groupOfNames"]
        self.group_object_classes = group_object_classes
        self.starttls = starttls
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.restricted_groups = restricted_groups

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
            try:
                connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
            except ValueError as err:
                raise LDAPAuthenticationError(
                    "LDAP connection option value error"
                ) from err
        if self.starttls:
            try:
                logger.debug("Using STARTTLS to initialize TLS connection")
                connection.start_tls_s()
            except ldap.CONNECT_ERROR as err:
                raise LDAPAuthenticationError(
                    f"Unable to connect to LDAP server with STARTTLS: {str(err)}"
                ) from err
            except ldap.SERVER_DOWN as err:
                raise LDAPAuthenticationError(
                    f"LDAP server {self.uri.geturl()} is unreachable"
                ) from err
        return connection

    def _get_user_info(
        self, connection: ldap.ldapobject.LDAPObject, user_dn: str
    ) -> Tuple[str, int]:
        """Return fullname and primary group number from the provided user DN."""
        search_filter = f"(objectClass={self.user_class})"
        try:
            results = connection.search_s(
                user_dn,
                ldap.SCOPE_BASE,
                search_filter,
                [self.user_fullname_attribute, self.user_primary_group_attribute],
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
            gid = int(results[0][1][self.user_primary_group_attribute][0])
        except KeyError:
            logger.warning(
                "Unable to extract user primary group with %s attribute from user "
                "entry",
                self.user_primary_group_attribute,
            )
            gid = None
        return fullname, gid

    def _get_groups(
        self,
        connection: ldap.ldapobject.LDAPObject,
        user_name: str,
        user_dn: str,
        gid: Optional[int],
    ) -> List[str]:
        """Return the list of groups whose provided user is member, including its
        primary group ID. This function supports both RFC 2307 (aka. NIS schema) and
        RFC 2307bis schema."""
        # In standard RFC 2307 (aka. NIS) schema, group members are declared with
        # memberUid attributes (with user cn as values).
        #
        # In RFC 2307 bis schema, group members are declared with member attributes
        # (with full user dn as values).
        #
        # In both cases, user primary group declared in user entry (gid argument) must
        # not be forgiven if defined.
        object_class_filter = "".join(
            [
                f"(objectClass={object_class})"
                for object_class in self.group_object_classes
            ]
        )
        gid_filter = f"(gidNumber={gid})" if gid is not None else ""
        search_filter = (
            "(&"
            f"(|{object_class_filter})"
            f"(|(memberUid={user_name})(member={user_dn}){gid_filter}))"
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
                "Unable to find groups in LDAP for user %s%s",
                user_name,
                f" or gidNumber {gid}" if gid is not None else "",
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

    def _in_restricted_groups(self, groups: List[str]):
        """Return False if restricted groups are set and none of the groups in argument
        matches the restricted groups. If either restricted groups are unset or any of
        the groups in argument is in restricted group, True is returned."""
        return not (
            self.restricted_groups is not None
            and len(self.restricted_groups)
            and not any([group in self.restricted_groups for group in groups])
        )

    def login(self, user: str, password: str) -> AuthenticatedUser:
        """Verify provided user/password are valid and return the corresponding
        AuthenticatedUser. Raise LDAPAuthenticationError if restricted groups are set
        and the user in not member of any of these groups."""
        fullname = None
        groups = None
        connection = self.connection()
        if user is None or password is None:
            raise LDAPAuthenticationError("Invalid authentication request")
        try:
            # Try simple authentication with user/password on LDAP directory
            user_dn = f"{self.user_name_attribute}={user},{self.user_base}"
            connection.simple_bind_s(user_dn, password)
            fullname, gid = self._get_user_info(connection, user_dn)
            groups = self._get_groups(connection, user, user_dn, gid)
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
        if not self._in_restricted_groups(groups):
            raise LDAPAuthenticationError(
                f"User {user} is not member of restricted groups"
            )
        return AuthenticatedUser(login=user, fullname=fullname, groups=groups)

    def _list_user_dn(self, connection):
        """Return list of all users name/pairs pairs in LDAP directory."""
        search_filter = f"(objectClass={self.user_class})"
        try:
            results = connection.search_s(
                self.user_base,
                ldap.SCOPE_SUBTREE,
                search_filter,
                [self.user_name_attribute],
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
            # Return an empty list to avoid further processing.
            return []

        # Pick results where user name attribute is found. If attribute not found in
        # any result, raise LDAPAuthenticationError.
        user_name_attribute_found = False
        picked = []
        for result in results:
            if self.user_name_attribute not in result[1]:
                logger.warning(
                    "Unable to find %s from user entry %s",
                    self.user_name_attribute,
                    result[0],
                )
                continue
            user_name_attribute_found = True
            picked.append((result[1][self.user_name_attribute][0].decode(), result[0]))
        if not user_name_attribute_found:
            raise LDAPAuthenticationError(
                f"Unable to extract user {self.user_name_attribute} from user entries"
            )
        return picked

    def users(self, with_groups: bool = False) -> List[AuthenticatedUser]:
        """Return list of AuthenticatedUser available in LDAP directory. If with_groups
        is True, the groups attribute of the AuthenticatedUsers is also initialized with
        the list of their groups. If with_groups is True and restricted groups are set,
        all users whose groups do not match any of the restricted groups are
        discarded."""
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
            for user, user_dn in self._list_user_dn(connection):
                fullname, gid = self._get_user_info(connection, user_dn)
                groups = []
                if with_groups:
                    groups = self._get_groups(connection, user, user_dn, gid)
                    # Skip the user if not member of any of the restricted groups
                    if not self._in_restricted_groups(groups):
                        logger.debug(
                            "Discarding user %s not member of restricted groups", user
                        )
                        continue
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
