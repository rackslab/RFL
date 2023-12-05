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
    ):
        self.uri = uri
        self.cacert = cacert
        self.user_base = user_base
        self.user_class = user_class
        self.group_base = group_base
        self.user_fullname_attribute = user_fullname_attribute

    def connection(self):
        connection = ldap.initialize(self.uri.geturl())
        # LDAP/SSL setup
        if self.uri.geturl().startswith("ldaps"):
            connection.protocol_version = ldap.VERSION3
            # Force cert validation
            connection.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
            if self.cacert is not None:
                connection.set_option(ldap.OPT_X_TLS_CACERTFILE, self.cacert)
            # Force libldap to create a new SSL context
            connection.set_option(ldap.OPT_X_TLS_NEWCTX, 0)
        return connection

    def login(self, user: str, password: str) -> AuthenticatedUser:
        fullname = None
        groups = None
        connection = self.connection()
        if user is None or password is None:
            raise LDAPAuthenticationError("invalid authentication request")
        try:
            # Try simple authentication with user/password on LDAP directory
            user_dn = f"uid={user},{self.user_base}"
            connection.simple_bind_s(user_dn, password)
            # Get full username
            search_filter = f"(objectClass={self.user_class})"
            results = connection.search_s(
                user_dn,
                ldap.SCOPE_BASE,
                search_filter,
                [self.user_fullname_attribute, "gidNumber"],
            )
            logger.debug(
                "LDAP search base: %s, scope: base filter: %s, results: %s",
                user_dn,
                search_filter,
                str(results),
            )
            fullname = results[0][1][self.user_fullname_attribute][0].decode()
            gidNumber = int(results[0][1]["gidNumber"][0])
            # Support RFC 2307
            search_filter = (
                "(&(objectClass=posixGroup)"
                f"(|(memberUid={user})(gidNumber={gidNumber})))"
            )
            results = connection.search_s(
                self.group_base, ldap.SCOPE_SUBTREE, search_filter, ["cn"]
            )
            logger.debug(
                "LDAP search base: %s, scope: subtree, filter: %s, results: %s",
                self.group_base,
                search_filter,
                str(results),
            )
            groups = [result[1]["cn"][0].decode() for result in results]
        except ldap.SERVER_DOWN:
            raise LDAPAuthenticationError("LDAP server is unreachable")
        except ldap.INVALID_CREDENTIALS:
            raise LDAPAuthenticationError("User or password is incorrect")
        except ldap.NO_SUCH_OBJECT as error:
            raise LDAPAuthenticationError(f"No such object: {str(error)}")
        except ldap.UNWILLING_TO_PERFORM as error:
            raise LDAPAuthenticationError(
                f"LDAP server is unwilling to perform: {str(error)}"
            )
        finally:
            connection.unbind_s()
        return AuthenticatedUser(login=user, fullname=fullname, groups=groups)
