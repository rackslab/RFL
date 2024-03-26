# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from unittest.mock import patch, Mock
from pathlib import Path
import urllib
import ssl

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
        # With classic ldap uri (no SSL/TLS)
        self.authentifier.connection()

    @patch("rfl.authentication.ldap.ldap")
    def test_connection_ssl_cert(self, mock_ldap):
        mock_ldap_object = mock_ldap.initialize.return_value

        # With ldap URI, check set_option is not called
        self.authentifier.connection()
        mock_ldap_object.set_option.assert_not_called()

        # With ldaps URI and no CA certificate path, check LDAP server certificate is
        # required and validated with default system OpenSSL certificates directory.
        self.authentifier.uri = urllib.parse.urlparse("ldaps://localhost")
        self.authentifier.connection()
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_REQUIRE_CERT, mock_ldap.OPT_X_TLS_DEMAND
        )
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_CACERTDIR, ssl.get_default_verify_paths().openssl_capath
        )
        mock_ldap_object.reset_mock()

        # With CA certificate path, check LDAP server certificate is required and
        # validated with provided CA certificate.
        cert = Path("/dev/null")
        self.authentifier.cacert = cert
        self.authentifier.connection()
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_REQUIRE_CERT, mock_ldap.OPT_X_TLS_DEMAND
        )
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_CACERTFILE, str(cert)
        )
        mock_ldap_object.reset_mock()

    @patch("rfl.authentication.ldap.ldap")
    def test_connection_starttls(self, mock_ldap):
        mock_ldap_object = mock_ldap.initialize.return_value

        # With ldaps URI (and starttls set to False by default), check LDAP server
        # certificate is required and start_tls_s is NOT called.
        self.authentifier.uri = urllib.parse.urlparse("ldaps://localhost")
        self.authentifier.connection()
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_REQUIRE_CERT, mock_ldap.OPT_X_TLS_DEMAND
        )
        mock_ldap_object.start_tls_s.assert_not_called()
        mock_ldap_object.reset_mock()

        # With ldap URI and starttls set to True, check LDAP server certificate is
        # required and start_tls_s is called.
        self.authentifier.uri = urllib.parse.urlparse("ldap://localhost")
        self.authentifier.starttls = True
        self.authentifier.connection()
        mock_ldap_object.set_option.assert_any_call(
            mock_ldap.OPT_X_TLS_REQUIRE_CERT, mock_ldap.OPT_X_TLS_DEMAND
        )
        mock_ldap_object.start_tls_s.assert_called_once()

    @patch.object(ldap.ldapobject.LDAPObject, "start_tls_s")
    def test_connection_tls_errors(self, mock_start_tls_s):
        self.authentifier.uri = urllib.parse.urlparse("ldap://localhost")
        self.authentifier.starttls = True
        mock_start_tls_s.side_effect = ldap.CONNECT_ERROR("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to connect to LDAP server with STARTTLS: fail$",
        ):
            self.authentifier.connection()
        mock_start_tls_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
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
        mock_get_groups.assert_called_once_with(
            mock_ldap_object, "john", "uid=john,ou=people,dc=corp,dc=org", 42
        )

        # verify return value
        self.assertEqual(user.login, "john")
        self.assertEqual(user.fullname, "John Doe")
        self.assertEqual(user.groups, ["group1", "group2"])

    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch("rfl.authentication.ldap.ldap")
    def test_login_not_in_restricted_group(
        self, mock_ldap, mock_get_groups, mock_get_user_info
    ):
        # setup mocks return values
        self.authentifier.restricted_groups = ["group3", "group4"]
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)

        # call method
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^User john is not member of restricted groups$",
        ):
            self.authentifier.login("john", "SECR3T")

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
        groups = self.authentifier._get_groups(
            connection, "john", "uid=john,ou=people,dc=corp,dc=org", 42
        )
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
            self.authentifier._get_groups(
                connection, "john", "uid=john,ou=people,dc=corp,dc=org", 42
            )

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
            self.authentifier._get_groups(
                connection, "john", "uid=john,ou=people,dc=corp,dc=org", 42
            )

    def test_get_groups_class_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If entries with posixGroup class is not found in group_base subtree, search_s
        # returns an empty list.
        connection.search_s.return_value = []
        with self.assertLogs("rfl.authentication.ldap", level="WARNING") as cm:
            groups = self.authentifier._get_groups(
                connection, "john", "uid=john,ou=people,dc=corp,dc=org", 42
            )
        self.assertEqual(groups, [])
        self.assertEqual(
            cm.output,
            [
                "WARNING:rfl.authentication.ldap:Unable to find groups in LDAP for user"
                " john or gidNumber 42"
            ],
        )

    def test_in_restricted_groups(self):
        # By default, restricted groups are unset, _in_restricted_groups must return
        # True in all cases.
        self.assertTrue(self.authentifier._in_restricted_groups([]))
        self.assertTrue(self.authentifier._in_restricted_groups(["users", "admins"]))

        # If restricted groups are set, _in_restricted_groups must return if at least
        # one group in argument matches one restricted group.

        # Test with one restricted group
        self.authentifier.restricted_groups = ["admins"]
        self.assertFalse(self.authentifier._in_restricted_groups([]))
        self.assertFalse(
            self.authentifier._in_restricted_groups(["users", "scientists"])
        )
        self.assertTrue(self.authentifier._in_restricted_groups(["admins"]))
        self.assertTrue(
            self.authentifier._in_restricted_groups(["users", "scientists", "admins"])
        )

        # Test with multiple restricted groups
        self.authentifier.restricted_groups = ["admins", "scientists"]
        self.assertFalse(self.authentifier._in_restricted_groups([]))
        self.assertFalse(self.authentifier._in_restricted_groups(["users"]))
        self.assertTrue(
            self.authentifier._in_restricted_groups(["users", "scientists"])
        )
        self.assertTrue(self.authentifier._in_restricted_groups(["admins"]))
        self.assertTrue(
            self.authentifier._in_restricted_groups(["users", "scientists", "admins"])
        )

    def test_list_user_dn(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            ("uid=john,ou=people,dc=corp,dc=org", {"uid": [b"john"]}),
            ("uid=marie,ou=people,dc=corp,dc=org", {"uid": [b"marie"]}),
        ]
        results = self.authentifier._list_user_dn(connection)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0], ("john", "uid=john,ou=people,dc=corp,dc=org"))
        self.assertEqual(results[1], ("marie", "uid=marie,ou=people,dc=corp,dc=org"))

    def test_list_user_dn_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # When user DN is not found in LDAP, ldap module raises NO_SUCH_OBJECT
        # exception.
        connection.search_s.side_effect = ldap.NO_SUCH_OBJECT("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to find user base ou=people,dc=corp,dc=org$",
        ):
            self.authentifier._list_user_dn(connection)

    def test_list_user_dn_no_result(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = []
        with self.assertLogs("rfl", level="WARNING") as lc:
            results = self.authentifier._list_user_dn(connection)
            self.assertEqual(
                [
                    "WARNING:rfl.authentication.ldap:Unable to find users in LDAP in "
                    "base ou=people,dc=corp,dc=org subtree"
                ],
                lc.output,
            )
        self.assertEqual(len(results), 0)

    def test_list_user_dn_no_uid(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            ("uid=john,ou=people,dc=corp,dc=org", {}),
        ]
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Unable to extract user uid from user entries$",
        ):
            self.authentifier._list_user_dn(connection)

    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch.object(LDAPAuthentifier, "_list_user_dn")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch("rfl.authentication.ldap.ldap")
    def test_users(
        self, mock_ldap, mock_get_user_info, mock_list_user_dn, mock_get_groups
    ):
        # Setup mocks return values
        mock_list_user_dn.return_value = [
            ("john", "uid=john,ou=people,dc=corp,dc=org"),
            ("marie", "uid=marie,ou=people,dc=corp,dc=org"),
        ]
        mock_get_user_info.side_effect = [("John Doe", 42), ("Marie Magic", 43)]
        mock_ldap_object = mock_ldap.initialize.return_value

        # Call method (without groups)
        users = self.authentifier.users()

        # Verify mock calls
        mock_ldap_object.unbind_s.assert_called_once()
        mock_list_user_dn.assert_called_once_with(mock_ldap_object)
        mock_get_user_info.assert_called()

        # Verify return value
        self.assertEqual(len(users), 2)
        self.assertEqual(users[0].login, "john")
        self.assertEqual(users[0].fullname, "John Doe")
        self.assertEqual(users[0].groups, [])
        self.assertEqual(users[1].login, "marie")
        self.assertEqual(users[1].fullname, "Marie Magic")
        self.assertEqual(users[1].groups, [])

        # Reset mock and re-inject side effects
        mock_ldap_object.reset_mock()
        mock_list_user_dn.reset_mock()
        mock_get_user_info.reset_mock()
        mock_get_user_info.side_effect = [("John Magic", 45), ("Marie Doe", 46)]
        mock_get_groups.side_effect = [["admin", "users"], ["biology", "users"]]

        # Call method (with groups)
        users = self.authentifier.users(True)

        # Verify mock calls
        mock_ldap_object.unbind_s.assert_called_once()
        mock_list_user_dn.assert_called_once_with(mock_ldap_object)
        mock_get_user_info.assert_called()

        # Verify return value
        self.assertEqual(len(users), 2)
        self.assertEqual(users[0].login, "john")
        self.assertEqual(users[0].fullname, "John Magic")
        self.assertEqual(users[0].groups, ["admin", "users"])
        self.assertEqual(users[1].login, "marie")
        self.assertEqual(users[1].fullname, "Marie Doe")
        self.assertEqual(users[1].groups, ["biology", "users"])

    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch.object(LDAPAuthentifier, "_list_user_dn")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch("rfl.authentication.ldap.ldap")
    def test_users_restricted_groups(
        self, mock_ldap, mock_get_user_info, mock_list_user_dn, mock_get_groups
    ):
        self.authentifier.restricted_groups = ["biology"]

        # Setup mocks return values
        mock_list_user_dn.return_value = [
            ("john", "uid=john,ou=people,dc=corp,dc=org"),
            ("marie", "uid=marie,ou=people,dc=corp,dc=org"),
        ]
        mock_get_user_info.side_effect = [("John Magic", 45), ("Marie Doe", 46)]
        mock_get_groups.side_effect = [["admin", "users"], ["biology", "users"]]

        # Call users method with groups retrieval
        with self.assertLogs("rfl", level="DEBUG") as lc:
            users = self.authentifier.users(True)

        # Verify return value. Only user Marie in restricted biology group must be
        # present.
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0].login, "marie")
        self.assertEqual(users[0].fullname, "Marie Doe")
        self.assertEqual(users[0].groups, ["biology", "users"])

        # Check debug message to indicate john is discarded has been sent
        self.assertEqual(
            [
                "DEBUG:rfl.authentication.ldap:Discarding user john not member of "
                "restricted groups"
            ],
            lc.output,
        )

    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch.object(LDAPAuthentifier, "_list_user_dn")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch("rfl.authentication.ldap.ldap")
    def test_users_bind_dn(
        self, mock_ldap, mock_get_user_info, mock_list_user_dn, mock_get_groups
    ):
        self.authentifier.bind_dn = "uid=hey,ou=people,dc=corp,dc=org"
        self.authentifier.bind_password = "secr3t"

        mock_ldap_object = mock_ldap.initialize.return_value

        # Call method
        self.authentifier.users()

        # Check simple_bind_s is called when bind_dn and bind_password are defined
        mock_ldap_object.simple_bind_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch("rfl.authentication.ldap.ldap")
    def test_users_bind_dn_missing_password(self, mock_ldap):
        self.authentifier.bind_dn = "uid=hey,ou=people,dc=corp,dc=org"

        # Check exception is raised when bind_dn is set without bind_password
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Password to authenticate with bind DN uid=hey,ou=people,dc=corp,dc=org "
            "is required$",
        ):
            self.authentifier.users()

    @patch.object(ldap, "initialize")
    def test_users_bind_dn_invalid_credentials(self, mock_ldap_initialize):
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS("fail")

        self.authentifier.bind_dn = "uid=hey,ou=people,dc=corp,dc=org"
        self.authentifier.bind_password = "secr3t"

        # Check exception is raised with LDAP fails due to invalid credential
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            "^Invalid bind DN or password$",
        ):
            self.authentifier.users()

    @patch.object(ldap.ldapobject.LDAPObject, "search_s")
    def test_users_ldap_errors(self, mock_search_s):
        mock_search_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            f"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
            self.authentifier.users()
