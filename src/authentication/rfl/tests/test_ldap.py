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
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
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
            r"^Unable to connect to LDAP server with STARTTLS: fail$",
        ):
            self.authentifier.connection()
        mock_start_tls_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
            self.authentifier.connection()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_disabled(self, mock_ldap_initialize):
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value

        self.assertEqual(
            self.authentifier._lookup_user_dn("john"),
            f"{self.authentifier.user_name_attribute}=john,"
            f"{self.authentifier.user_base}",
        )
        mock_ldap_object.simple_bind_s.assert_not_called()
        mock_ldap_object.search_s.assert_not_called()
        mock_ldap_object.unbind_s.assert_not_called()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled(self, mock_ldap_initialize):
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.search_s.return_value = [
            (
                f"uid=john,ou=admins,{self.authentifier.user_base}",
                {"cn": [b"John Doe"]},
            )
        ]

        self.assertEqual(
            self.authentifier._lookup_user_dn("john"),
            f"uid=john,ou=admins,{self.authentifier.user_base}",
        )
        mock_ldap_object.simple_bind_s.assert_not_called()
        mock_ldap_object.search_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled_bind_dn(self, mock_ldap_initialize):
        # define bind dn/password
        self.authentifier.bind_dn = "uid=read,ou=apps,dc=corp,dc=org"
        self.authentifier.bind_password = "uid=read,ou=apps,dc=corp,dc=org"
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.search_s.return_value = [
            (
                f"uid=john,ou=admins,{self.authentifier.user_base}",
                {"cn": [b"John Doe"]},
            )
        ]

        self.assertEqual(
            self.authentifier._lookup_user_dn("john"),
            f"uid=john,ou=admins,{self.authentifier.user_base}",
        )
        mock_ldap_object.simple_bind_s.assert_called_once_with(
            self.authentifier.bind_dn, self.authentifier.bind_password
        )
        mock_ldap_object.search_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled_bind_dn_missing_password(
        self, mock_ldap_initialize
    ):
        # define bind_dn without password
        self.authentifier.bind_dn = "uid=read,ou=apps,dc=corp,dc=org"
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value

        # Check exception is raised when bind_dn is set without bind_password
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Password to authenticate with bind DN uid=read,ou=apps,dc=corp,dc=org "
            r"is required$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_not_called()
        mock_ldap_object.unbind_s.assert_not_called()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled_bind_dn_invalid_credentials(
        self, mock_ldap_initialize
    ):
        # define bind dn/password
        self.authentifier.bind_dn = "uid=read,ou=apps,dc=corp,dc=org"
        self.authentifier.bind_password = "uid=read,ou=apps,dc=corp,dc=org"
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.simple_bind_s.side_effect = ldap.INVALID_CREDENTIALS("fail")

        # Check exception is raised with LDAP fails due to invalid credential
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Invalid bind DN or password$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_not_called()
        mock_ldap_object.unbind_s.assert_not_called()

    @patch.object(ldap, "initialize")
    def test_lookup_user_ldap_server_down_error(self, mock_ldap_initialize):
        # define bind dn/password
        self.authentifier.bind_dn = "uid=read,ou=apps,dc=corp,dc=org"
        self.authentifier.bind_password = "uid=read,ou=apps,dc=corp,dc=org"
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.simple_bind_s.side_effect = ldap.SERVER_DOWN("fail")

        # Check exception is raised due to LDAP server down
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_not_called()
        mock_ldap_object.unbind_s.assert_not_called()

    @patch.object(ldap, "initialize")
    def test_lookup_user_ldap_operations_error(self, mock_ldap_initialize):
        # define bind dn/password
        self.authentifier.bind_dn = "uid=read,ou=apps,dc=corp,dc=org"
        self.authentifier.bind_password = "uid=read,ou=apps,dc=corp,dc=org"
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.search_s.side_effect = ldap.OPERATIONS_ERROR("fail")

        # Check exception is raised due to LDAP server down
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Operations error on user DN lookup: fail$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled_not_found(self, mock_ldap_initialize):
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.search_s.return_value = []

        # Check exception is raised due to no result found
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Unable to find user john in base ou=people,dc=corp,dc=org$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch.object(ldap, "initialize")
    def test_lookup_user_dn_enabled_too_much_results(self, mock_ldap_initialize):
        # enable user DN lookup
        self.authentifier.lookup_user_dn = True
        # setup LDAP mock
        mock_ldap_object = mock_ldap_initialize.return_value
        mock_ldap_object.search_s.return_value = [
            (
                f"uid=john,ou=admins,{self.authentifier.user_base}",
                {"cn": [b"John Doe"]},
            ),
            (
                f"uid=alice,ou=admins,{self.authentifier.user_base}",
                {"cn": [b"Alice Doe"]},
            ),
        ]
        # Check exception is raised due to too many results found
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Too many users found \(2\) with username john in base "
            r"ou=people,dc=corp,dc=org$",
        ):
            self.authentifier._lookup_user_dn("john")
        mock_ldap_object.search_s.assert_called_once()
        mock_ldap_object.unbind_s.assert_called_once()

    @patch.object(LDAPAuthentifier, "_lookup_user_dn")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch("rfl.authentication.ldap.ldap")
    def test_login_ok(
        self, mock_ldap, mock_get_groups, mock_get_user_info, mock_lookup_user_dn
    ):
        # setup mocks return values
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)
        mock_lookup_user_dn.return_value = "uid=john,ou=people,dc=corp,dc=org"
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

    @patch.object(LDAPAuthentifier, "_lookup_user_dn")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch("rfl.authentication.ldap.ldap")
    def test_login_not_in_restricted_group(
        self, mock_ldap, mock_get_groups, mock_get_user_info, mock_lookup_user_dn
    ):
        # setup mocks return values
        self.authentifier.restricted_groups = ["group3", "group4"]
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)
        mock_lookup_user_dn.return_value = "uid=john,ou=people,dc=corp,dc=org"

        # call method
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^User john is not member of restricted groups$",
        ):
            self.authentifier.login("john", "SECR3T")

    def test_login_missing_user_or_password(self):
        with self.assertRaisesRegex(
            LDAPAuthenticationError, "Invalid authentication request"
        ):
            self.authentifier.login("john", None)
            self.authentifier.login(None, "SECR3T")

    @patch.object(LDAPAuthentifier, "_lookup_user_dn")
    @patch.object(ldap.ldapobject.LDAPObject, "simple_bind_s")
    def test_login_errors(self, mock_simple_bind_s, mock_lookup_user_dn):
        mock_lookup_user_dn.return_value = "uid=john,ou=people,dc=corp,dc=org"
        mock_simple_bind_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
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

    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_lookup_user_dn")
    @patch.object(LDAPAuthentifier, "_bind")
    @patch.object(LDAPAuthentifier, "connection")
    def test_login_no_bind_lookup_as_user_true(
        self,
        mock_connection,
        mock_bind,
        mock_lookup_user_dn,
        mock_get_user_info,
        mock_get_groups,
    ):
        # setup mocks return values
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)
        mock_lookup_user_dn.return_value = "uid=john,ou=people,dc=corp,dc=org"
        mock_connection.return_value.simple_bind_s.return_value = None

        # if lookup_as_user is False, login() must not call _bind().
        self.authentifier.lookup_as_user = True
        self.authentifier.login("john", "SECR3T")
        mock_bind.assert_not_called()
        mock_connection.return_value.simple_bind_s.assert_called_once_with(
            "uid=john,ou=people,dc=corp,dc=org", "SECR3T"
        )

    @patch.object(LDAPAuthentifier, "_get_groups")
    @patch.object(LDAPAuthentifier, "_get_user_info")
    @patch.object(LDAPAuthentifier, "_lookup_user_dn")
    @patch.object(LDAPAuthentifier, "_bind")
    @patch.object(LDAPAuthentifier, "connection")
    def test_login_single_bind_lookup_as_user_false(
        self,
        mock_connection,
        mock_bind,
        mock_lookup_user_dn,
        mock_get_user_info,
        mock_get_groups,
    ):
        # setup mocks return values
        mock_get_groups.return_value = ["group1", "group2"]
        mock_get_user_info.return_value = ("John Doe", 42)
        mock_lookup_user_dn.return_value = "uid=john,ou=people,dc=corp,dc=org"

        # if lookup_as_user is False, login() should call _bind() once.
        self.authentifier.lookup_as_user = False
        self.authentifier.login("john", "SECR3T")
        mock_bind.assert_called_once()
        mock_connection.return_value.simple_bind_s.assert_called_once_with(
            "uid=john,ou=people,dc=corp,dc=org", "SECR3T"
        )

    def test_user_info(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            (
                "uid=john,ou=people,dc=corp,dc=org",
                {"cn": [b"John Doe"], "gidNumber": [b"42"]},
            )
        ]
        fullname, gid = self.authentifier._get_user_info(
            connection, "uid=john,ou=people,dc=corp,dc=org"
        )
        self.assertEqual(fullname, "John Doe")
        self.assertEqual(gid, 42)

    def test_user_info_fullname_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If the user entries in LDAP directory do not contain attributes whose name
        # matches user_fullname_attribute or user_primary_group_attribute, search_s
        # returns a dict with missing keys in the second element of the result tuple.
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
            r"^Unable to extract user full name with "
            rf"{self.authentifier.user_fullname_attribute} attribute from user "
            r"entries$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )

    def test_user_info_primary_group_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # Test missing gidNumber
        connection.search_s.return_value = [
            (
                "uid=john,ou=people,dc=corp,dc=org",
                {"cn": [b"John Doe"]},
            )
        ]
        with self.assertLogs("rfl", level="WARNING") as log:
            fullname, gid = self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )
            self.assertEqual(
                [
                    "WARNING:rfl.authentication.ldap:Unable to extract user primary "
                    "group with gidNumber attribute from user entry"
                ],
                log.output,
            )
        self.assertEqual(fullname, "John Doe")
        self.assertIsNone(gid)

    def test_user_info_class_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If entries with class user_class is not found in user_base subtree,
        # search_s returns an empty list.
        connection.search_s.return_value = []
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^User not found in LDAP with class {self.authentifier.user_class}$",
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
            rf"^Unable to find user DN uid=john,{self.authentifier.user_base}$",
        ):
            self.authentifier._get_user_info(
                connection, "uid=john,ou=people,dc=corp,dc=org"
            )

    def test_custom_primary_attribute(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        self.authentifier.user_primary_group_attribute = "primaryGroupId"
        dn = "uid=jane,ou=people,dc=corp,dc=org"
        connection.search_s.return_value = [
            (
                dn,
                {
                    "cn": [b"Jane Smith"],
                    self.authentifier.user_primary_group_attribute: [b"42"],
                },
            )
        ]
        fullname, gid = self.authentifier._get_user_info(connection, dn)
        connection.search_s.assert_called_once_with(
            dn,
            ldap.SCOPE_BASE,
            f"(objectClass={self.authentifier.user_class})",
            [
                self.authentifier.user_fullname_attribute,
                self.authentifier.user_primary_group_attribute,
            ],
        )
        self.assertEqual(fullname, "Jane Smith")
        self.assertEqual(gid, 42)

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

    def test_get_groups_without_gid(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            ("cn=scientists,ou=groups,dc=corp,dc=org", {"cn": [b"scientists"]}),
            ("cn=biology,ou=groups,dc=corp,dc=org", {"cn": [b"biology"]}),
        ]
        user = "john"
        dn = "uid=john,ou=people,dc=corp,dc=org"
        gid = 42
        # First call with gid and check LDAP search filter.
        groups = self.authentifier._get_groups(connection, user, dn, gid)
        self.assertEqual(groups, ["scientists", "biology"])
        connection.search_s.assert_called_once_with(
            self.authentifier.group_base,
            ldap.SCOPE_SUBTREE,
            "(&(|(objectClass=posixGroup)(objectClass=groupOfNames))"
            f"(|(memberUid={user})(member={dn})(gidNumber={gid})))",
            [self.authentifier.group_name_attribute],
        )
        connection.search_s.reset_mock()
        # Then a second call with undefined gid must remove gidNumber from LDAP search
        # filter.
        groups = self.authentifier._get_groups(connection, user, dn, None)
        self.assertEqual(groups, ["scientists", "biology"])
        connection.search_s.assert_called_once_with(
            self.authentifier.group_base,
            ldap.SCOPE_SUBTREE,
            "(&(|(objectClass=posixGroup)(objectClass=groupOfNames))"
            f"(|(memberUid={user})(member={dn})))",
            [self.authentifier.group_name_attribute],
        )

    def test_groups_base_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # When group base DN is not found in LDAP, ldap module raises NO_SUCH_OBJECT
        # exception.
        connection.search_s.side_effect = ldap.NO_SUCH_OBJECT("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^Unable to find group base {self.authentifier.group_base}$",
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
            r"^Unable to extract group name with fail attribute from group entries$",
        ):
            self.authentifier._get_groups(
                connection, "john", "uid=john,ou=people,dc=corp,dc=org", 42
            )

    def test_get_groups_class_not_found(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # If entries with one of group_object_classes is not found in group_base
        # subtree, search_s returns an empty list.
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
        # Test log message without gid
        with self.assertLogs("rfl.authentication.ldap", level="WARNING") as cm:
            groups = self.authentifier._get_groups(
                connection, "john", "uid=john,ou=people,dc=corp,dc=org", None
            )
        self.assertEqual(groups, [])
        self.assertEqual(
            cm.output,
            [
                "WARNING:rfl.authentication.ldap:Unable to find groups in LDAP for user"
                " john"
            ],
        )

    def test_custom_group_object_classes(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        connection.search_s.return_value = [
            ("cn=scientists,ou=groups,dc=corp,dc=org", {"cn": [b"scientists"]}),
            ("cn=biology,ou=groups,dc=corp,dc=org", {"cn": [b"biology"]}),
        ]
        group_object_class = "group"
        login = "john"
        gid = 42
        self.authentifier.group_object_classes = [group_object_class]
        groups = self.authentifier._get_groups(
            connection, login, f"uid={login},ou=people,dc=corp,dc=org", gid
        )
        connection.search_s.assert_called_once_with(
            self.authentifier.group_base,
            ldap.SCOPE_SUBTREE,
            f"(&(|(objectClass={group_object_class}))(|(memberUid={login})"
            f"(member=uid={login},ou=people,dc=corp,dc=org)(gidNumber={gid})))",
            [self.authentifier.group_name_attribute],
        )
        self.assertEqual(groups, ["scientists", "biology"])

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
            r"^Unable to find user base ou=people,dc=corp,dc=org$",
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

    def test_list_user_dn_no_user_name_attribute(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # All results miss the user name attribute, _list_user_dn() is expected to raise
        # LDAPAuthenticationError.
        connection.search_s.return_value = [
            ("uid=john,ou=people,dc=corp,dc=org", {}),
            ("uid=jane,ou=people,dc=corp,dc=org", {}),
        ]
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Unable to extract user uid from user entries$",
        ):
            self.authentifier._list_user_dn(connection)

    def test_list_user_dn_missing_user_name_attribute(self):
        connection = Mock(spec=ldap.ldapobject.LDAPObject)
        # At least one result has the user name attribute, _list_user_dn() must return
        # these results and log warning message for other dn that miss this attribute.
        connection.search_s.return_value = [
            ("uid=john,ou=people,dc=corp,dc=org", {}),
            ("uid=jane,ou=people,dc=corp,dc=org", {"uid": [b"jane"]}),
        ]
        with self.assertLogs("rfl", level="INFO") as lc:
            results = self.authentifier._list_user_dn(connection)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0], ("jane", "uid=jane,ou=people,dc=corp,dc=org"))

        # Check warning message to indicate user name attribute has not been found in
        # john user entry has been sent
        self.assertEqual(
            [
                "WARNING:rfl.authentication.ldap:Unable to find uid from user entry "
                "uid=john,ou=people,dc=corp,dc=org"
            ],
            lc.output,
        )

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
            r"^Password to authenticate with bind DN uid=hey,ou=people,dc=corp,dc=org "
            r"is required$",
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
            r"^Invalid bind DN or password$",
        ):
            self.authentifier.users()

    @patch.object(ldap.ldapobject.LDAPObject, "search_s")
    def test_users_ldap_server_down_error(self, mock_search_s):
        mock_search_s.side_effect = ldap.SERVER_DOWN("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            rf"^LDAP server {self.authentifier.uri.geturl()} is unreachable$",
        ):
            self.authentifier.users()

    @patch.object(ldap.ldapobject.LDAPObject, "search_s")
    def test_users_ldap_operations_error(self, mock_search_s):
        mock_search_s.side_effect = ldap.OPERATIONS_ERROR("fail")
        with self.assertRaisesRegex(
            LDAPAuthenticationError,
            r"^Operations error on users search: fail$",
        ):
            self.authentifier.users()


class TestLDAPAuthentifierInit(unittest.TestCase):
    def test_lookup_as_user_auto_bind_dn(self):
        # lookup_as_user is None, bind_dn and bind_password are set, should do lookup
        # with service credentials.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            bind_dn="uid=read,ou=apps,dc=corp,dc=org",
            bind_password="SECR3T",
            lookup_as_user=None,
        )
        self.assertFalse(auth.lookup_as_user)

    def test_lookup_as_user_auto_no_bind_user(self):
        # lookup_as_user is None, bind_dn and bind_password are not set, should do
        # lookup as user.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            bind_dn=None,
            bind_password=None,
            lookup_as_user=None,
        )
        self.assertTrue(auth.lookup_as_user)

    def test_lookup_as_user_auto_no_bind_dn(self):
        # lookup_as_user is None, bind_dn is not set, should do lookup as user.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            bind_dn=None,
            bind_password="SECR3T",
            lookup_as_user=None,
        )
        self.assertTrue(auth.lookup_as_user)

    def test_lookup_as_user_auto_no_bind_password(self):
        # lookup_as_user is None, bind_password is not set, should do lookup as user.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            bind_dn="uid=read,ou=apps,dc=corp,dc=org",
            bind_password=None,
            lookup_as_user=None,
        )
        self.assertTrue(auth.lookup_as_user)

    def test_lookup_as_user_enabled(self):
        # lookup_as_user is True, should do lookup as user.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            lookup_as_user=True,
        )
        self.assertTrue(auth.lookup_as_user)

    def test_lookup_as_user_disabled(self):
        # lookup_as_user is False, should do lookup with service credentials.
        auth = LDAPAuthentifier(
            uri=urllib.parse.urlparse("ldap://localhost"),
            user_base="ou=people,dc=corp,dc=org",
            group_base="ou=groups,dc=corp,dc=org",
            lookup_as_user=False,
        )
        self.assertFalse(auth.lookup_as_user)
