# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from unittest.mock import patch, Mock
from pathlib import Path
import urllib

import ldap

from rfl.authentication.ldap import LDAPAuthentifier
from rfl.authentication.errors import LDAPAuthenticationError


class MockLDAPObject:
    pass


class TestLDAPAuthentifier(unittest.TestCase):
    def setUp(self):
        self.authentifier = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            cacert=None,
            user_base="ou=people,dc=corp,dc=org",
            user_class="posixAccount",
            group_base="ou=groups,dc=corp,dc=org",
            user_fullname_attribute="cn",
            group_name_attribute="cn",
        )

    def test_connection(self):
        # With ldap uri
        self.authentifier.connection()
        # With ldaps uri
        self.authentifier.uri = urllib.parse.urlparse("ldaps://localhost")
        self.authentifier.connection()
        # With ldaps uri and cacert
        self.authentifier.cacert = Path("/dev/null")
        self.authentifier.connection()

    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch("rfl.authentication.ldap.ldap")
    def test_login_ok(self, mock_ldap, mock_get_groups, mock_get_user_info):
        # setup mocks return values
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)
        mock_ldap_object = mock_ldap.initialize.return_value

        # call method
        user = self.authentifier.login("john", "SECR3T")

        # verify mock calls
        mock_ldap_object.unbind_s.assert_called_once()
        mock_ldap_object.simple_bind_s.assert_called_once_with(
            "uid=john,ou=people,dc=corp,dc=org", "SECR3T"
        )
        mock_get_user_info.assert_called_once_with(
            mock_ldap_object, "uid=john,ou=people,dc=corp,dc=org"
        )
        mock_get_groups.assert_called_once_with(mock_ldap_object, "john", 42)

        # verify return value
        self.assertEqual(user.login, "john")
        self.assertEqual(user.fullname, "John Doe")
        self.assertEqual(user.groups, ["group1", "group2"])

    def test_login_missing_user_or_password(self):
        with self.assertRaisesRegex(
            LDAPAuthenticationError, "Invalid authentication request"
        ):
            self.authentifier.login("john", None)
            self.authentifier.login(None, "SECR3T")

    @patch.object(ldap.ldapobject.LDAPObject, "simple_bind_s")
    def test_login_errors(self, mock_simple_bind_s):
        mock_simple_bind_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
            self.authentifier.login("john", "SECR3T")
        mock_simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError, "^Invalid user or password$"
        ):
            self.authentifier.login("john", "SECR3return_valueT")
        mock_simple_bind_s.side_effect = ldap.UNWILLING_TO_PERFORM("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError, "^LDAP server is unwilling to perform: fail$"
        ):
            self.authentifier.login("john", "SECR3T")

    def test_user_info(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            (
                "uid=john,ou=people,dc=corp,dc=org",
                {"cn": [b"John Doe"], "gidNumber": [b"42"]},
            )
        ]
        fullname, gidNumber = self.authentifier._get_user_info(
            connection, "uid=john,ou=people,dc=corp,dc=org"
        )
        self.assertEqual(fullname, "John Doe")
        self.assertEqual(gidNumber, 42)

    def test_user_info_attributes_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If the user entries in LDAP directory do not contain attributes whose name
        # matches user_fullname_attribute or gidNumber, search_s returns a dict with
        # missing keys in the second element of the result tuple.
        #
        # Test missing user_fullname_attribute
        connection.search_s.return_value = [
            (
                "uid=john,ou=people,dc=corp,dc=org",
                {"gidNumber": [b"42"]},
            )
        ]
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to extract user full name with "
            f"{self.authentifier.user_fullname_attribute} attribute from user entries$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )
        # Test missing gidNumber
        connection.search_s.return_value = [
            (
                "uid=john,ou=people,dc=corp,dc=org",
                {"cn": [b"John Doe"]},
            )
        ]
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to extract user primary group with gidNumber attribute from user "
            "entries$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )

    def test_user_info_class_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If entries with class user_class is not found in user_base subtree,
        # search_s returns an empty list.
        connection.search_s.return_value = []
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^User not found in LDAP with class {self.authentifier.user_class}$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )

    def test_user_info_dn_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # When user DN is not found in LDAP, ldap module raises NO_SUCH_OBJECT
        # exception.
        connection.search_s.side_effect = ldap.NO_SUCH_OBJECT("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^Unable to find user DN uid=john,{self.authentifier.user_base}$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )

    def test_get_groups(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            ("cn=scientists,ou=groups,dc=corp,dc=org", {"cn": [b"scientists"]}),
            ("cn=biology,ou=groups,dc=corp,dc=org", {"cn": [b"biology"]}),
        ]
        groups = self.authentifier._get_groups(connection, "john", 42)
        self.assertEqual(groups, ["scientists", "biology"])

    def test_groups_base_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # When group base DN is not found in LDAP, ldap module raises NO_SUCH_OBJECT
        # exception.
        connection.search_s.side_effect = ldap.NO_SUCH_OBJECT("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^Unable to find group base {self.authentifier.group_base}$",
        ):
            self.authentifier._get_groups(connection, "john", 42)

    def test_get_groups_name_attribute_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        self.authentifier.group_name_attribute = "fail"
        # If the group entries in LDAP directory does not contain attributes whose name
        # matches group_name_attribute, search_s returns an empty dict in the second
        # element of the result tuple.
        connection.search_s.return_value = [
            ("cn=scientists,ou=groups,dc=corp,dc=org", {}),
            ("cn=biology,ou=groups,dc=corp,dc=org", {}),
        ]
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to extract group name with fail attribute from group entries$",
        ):
            self.authentifier._get_groups(connection, "john", 42)

    def test_get_groups_class_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If entries with posixGroup class is not found in group_base subtree, search_s
        # returns an empty list.
        connection.search_s.return_value = []
        with self.assertLogs("rfl.authentication.ldap", level="WARNING") as cm:
            groups = self.authentifier._get_groups(connection, "john", 42)
        self.assertEqual(groups, [])
        self.assertEqual(
            cm.output,
            [
                "WARNING:rfl.authentication.ldap:Unable to find groups in LDAP for user"
                " john or gidNumber 42"
            ],
        )
