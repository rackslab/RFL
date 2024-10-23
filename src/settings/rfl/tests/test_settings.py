# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from pathlib import Path
from io import StringIO
from unittest.mock import patch
import ipaddress

from rfl.settings.definition import SettingsDefinition, SettingsDefinitionLoaderYaml
from rfl.settings.loaders import RuntimeSettingsSiteLoaderIni
from rfl.settings import RuntimeSettings, RuntimeSettingsSection

from rfl.settings.errors import SettingsDefinitionError, SettingsOverrideError

VALID_DEFINITION = """
---
section1:
  param_str:
    type: str
    default: value1

section2:
    param_int:
        type: int
        default: 10
        doc: documentation of param2
        ex: 500
        choices:
        - 10
        - 100
        - 500
    param_path:
        type: path
        default: /path/to/file
        doc: documentation of param3
        ex: /other/path/to/file
    param_uri:
        type: uri
        default: https://localhost:5900/resources
    param_float:
        type: float
    param_bool:
        type: bool
        default: yes
    param_list:
        type: list
        content: str
        default:
        - value1
        - value2
    param_required:
        type: str
        required: true
    param_password:
        type: password
    param_ip:
        type: ip
    param_network:
        type: network
"""

VALID_SITE = """
[section1]
param_str = site_value1

[section2]
param_path = /site/path/to/file
param_list =
  value3
  #value4
  value5
param_required = required_value
param_password = SECR3T
param_ip = 127.0.0.1
param_network = 127.0.0.0/24
"""


class TestSettingsDefinition(unittest.TestCase):
    def test_valid_content(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        self.assertEqual(loader.name, "definition:yaml:raw")
        definition = SettingsDefinition(loader)
        self.assertTrue(definition.has_section("section1"))
        self.assertFalse(definition.has_section("unknown"))
        self.assertTrue(definition.section("section1").has_parameter("param_str"))
        self.assertFalse(definition.section("section1").has_parameter("unknown"))
        self.assertEqual(
            definition.section("section1").parameter("param_str").default, "value1"
        )
        self.assertEqual(
            definition.section("section2").parameter("param_int").example, 500
        )
        self.assertEqual(
            len(definition.section("section2").parameter("param_int").choices), 3
        )
        self.assertEqual(
            definition.section("section2").parameter("param_uri")._type, "uri"
        )

    def test_invalid_yaml(self):
        with self.assertRaisesRegex(
            SettingsDefinitionError, r"^Invalid YAML settings definition: "
        ):
            SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION + "\n fail")
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^YAML scanner error: mapping values are not allowed here.*",
        ):
            SettingsDefinitionLoaderYaml(raw="fail: again: ")

    def test_unsupported_property(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["unknown"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Unsupported properties found for \[section2\]>param_int: unknown$",
        ):
            SettingsDefinition(loader)

    def test_unsupported_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["type"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Unsupported type fail for \[section2\]>param_int$",
        ):
            SettingsDefinition(loader)

    def test_required_not_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_required"]["required"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Invalid boolean value of \[section2\]>param_required required property$",
        ):
            SettingsDefinition(loader)

    def test_default_valid_type_int(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = 10
        definition = SettingsDefinition(loader)
        self.assertEqual(
            definition.section("section2").parameter("param_int").default, 10
        )

    def test_default_valid_type_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_bool"]["default"] = True
        definition = SettingsDefinition(loader)
        self.assertEqual(
            definition.section("section2").parameter("param_bool").default, True
        )

    def test_default_valid_type_ip(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_ip"]["default"] = "192.168.0.10"
        definition = SettingsDefinition(loader)
        self.assertEqual(
            definition.section("section2").parameter("param_ip").default,
            ipaddress.ip_address("192.168.0.10"),
        )

    def test_default_valid_type_network(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_network"]["default"] = "192.168.0.0/24"
        definition = SettingsDefinition(loader)
        self.assertEqual(
            definition.section("section2").parameter("param_network").default,
            ipaddress.ip_network("192.168.0.0/24"),
        )

    def test_default_invalid_type_int(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value fail for parameter \[section2\]>param_int has not the "
            r"expected type int$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_bool"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value fail for parameter \[section2\]>param_bool has not the "
            r"expected type bool$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_ip(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_ip"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Invalid default ip address value for parameter \[section2\]>param_ip$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_network(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_network"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Invalid default ip network value for parameter "
            r"\[section2\]>param_network$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_choice(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = 12
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value 12 for parameter \[section2\]>param_int is not one of "
            r"possible choices \[10, 100, 500\]$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_list(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value fail for parameter \[section2\]>param_list is not a valid "
            r"list$",
        ):
            SettingsDefinition(loader)

    def test_type_list_without_content(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        del loader.content["section2"]["param_list"]["content"]
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^List content type for parameter \[section2\]>param_list must be "
            r"defined$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_content_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["content"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Unsupported list content type fail for \[section2\]>param_list$",
        ):
            SettingsDefinition(loader)
        loader.content["section2"]["param_list"]["content"] = "list"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Unsupported list content type list for \[section2\]>param_list$",
        ):
            SettingsDefinition(loader)

    def test_type_content_on_other_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["type"] = "str"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Content property is forbidden for parameter \[section2\]>param_list "
            r"with type str$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_default_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["content"] = "bool"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value value1 for parameter \[section2\]>param_list has not the "
            r"expected type bool$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_choice(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["choices"] = ["value1", "value3"]
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            r"^Default value value2 for parameter \[section2\]>param_list is not one "
            r"of possible choices \['value1', 'value3'\]$",
        ):
            SettingsDefinition(loader)


class TestRuntimeSettings(unittest.TestCase):
    def test_valid_settings(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(loader)
        settings = RuntimeSettings(definition)
        self.assertEqual(settings.section1.param_str, "value1")
        self.assertEqual(settings.section2.param_int, 10)
        self.assertEqual(settings.section2.param_path, Path("/path/to/file"))
        self.assertIsInstance(settings.section2.param_uri, tuple)
        self.assertEqual(settings.section2.param_uri.scheme, "https")
        self.assertIsInstance(settings.section1, RuntimeSettingsSection)
        self.assertEqual(type(settings.section1).__name__, "RuntimeSettingsSection1")

    def test_site_overrides(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        self.assertEqual(site_loader.name, "site:ini:raw")
        settings.override(site_loader)
        self.assertEqual(settings.section1.param_str, "site_value1")
        self.assertEqual(settings.section2.param_path, Path("/site/path/to/file"))
        self.assertEqual(settings.section2.param_list, ["value3", "value5"])
        self.assertIsInstance(settings.section2.param_ip, ipaddress.IPv4Address)
        self.assertEqual(str(settings.section2.param_ip), "127.0.0.1")
        self.assertTrue(settings.section2.param_ip.is_loopback)
        self.assertIsInstance(settings.section2.param_network, ipaddress.IPv4Network)
        self.assertEqual(str(settings.section2.param_network), "127.0.0.0/24")
        self.assertTrue(settings.section2.param_network.is_loopback)

    def test_site_override_invalid_section(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["big"] = {}
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Section big loaded in settings overrides is not defined in "
            r"settings definition$",
        ):
            settings.override(site_loader)

    def test_site_override_invalid_parameter(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["unknown"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Parameter unknown loaded in settings overrides is not defined in "
            r"section section2 of settings definition$",
        ):
            settings.override(site_loader)

    def test_site_override_invalid_type_int(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_int"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid integer value 'fail' for \[section2\]>param_int in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_invalid_type_float(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_float"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid float value 'fail' for \[section2\]>param_float in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_invalid_type_bool(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_bool"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid boolean value 'fail' for \[section2\]>param_bool in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_type_ip_ipv6(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_ip"] = "::1"
        settings.override(site_loader)
        self.assertIsInstance(settings.section2.param_ip, ipaddress.IPv6Address)
        self.assertEqual(str(settings.section2.param_ip), "::1")
        self.assertTrue(settings.section2.param_ip.is_loopback)

    def test_site_override_invalid_type_ip(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_ip"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid ip address value 'fail' for \[section2\]>param_ip in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_type_network_ipv6(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        addr = "fd1a:aa9b:7d8b:cfbe::/64"  # Use random private network for this test
        site_loader.content["section2"]["param_network"] = addr
        settings.override(site_loader)
        self.assertIsInstance(settings.section2.param_network, ipaddress.IPv6Network)
        self.assertEqual(str(settings.section2.param_network), addr)
        self.assertTrue(settings.section2.param_network.is_private)

    def test_site_override_invalid_type_network(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_network"] = "fail"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid ip network value 'fail' for \[section2\]>param_network in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_invalid_choice(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["section2"]["param_int"] = "12"
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Value 12 for parameter \[section2\]>param_int in site overrides is not "
            r"one of possible choices \[10, 100, 500\]$",
        ):
            settings.override(site_loader)

    def test_site_override_undefined_required(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        del site_loader.content["section2"]["param_required"]
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Parameter \[section2\]>param_required is missing but required in "
            r"settings overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_list_invalid_content_type(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        def_loader.content["section2"]["param_list"]["content"] = "int"
        def_loader.content["section2"]["param_list"]["default"] = [2, 5]
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Invalid integer value 'value3' for \[section2\]>param_list in site "
            r"overrides$",
        ):
            settings.override(site_loader)

    def test_site_override_list_invalid_choice(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        def_loader.content["section2"]["param_list"]["choices"] = ["value1", "value2"]
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        with self.assertRaisesRegex(
            SettingsOverrideError,
            r"^Value value3 for parameter \[section2\]>param_list in site overrides is "
            r"not one of possible choices \['value1', 'value2'\]$",
        ):
            settings.override(site_loader)

    @patch("sys.stdout", new_callable=StringIO)
    def test_dump(self, mock_stdout):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        settings.override(site_loader)
        settings.dump()
        self.assertEqual(
            mock_stdout.getvalue(),
            "[section1]\n"
            "  param_str: site_value1 (site:ini:raw)\n"
            "[section2]\n"
            "  param_int: 10 (definition:yaml:raw)\n"
            "  param_path: /site/path/to/file (site:ini:raw)\n"
            "  param_uri: ParseResult(scheme='https', netloc='localhost:5900', "
            "path='/resources', params='', query='', fragment='') "
            "(definition:yaml:raw)\n"
            "  param_float: None (definition:yaml:raw)\n"
            "  param_bool: True (definition:yaml:raw)\n"
            "  param_list: ['value3', 'value5'] (site:ini:raw)\n"
            "  param_required: required_value (site:ini:raw)\n"
            "  param_password: •••••• (site:ini:raw)\n"
            "  param_ip: 127.0.0.1 (site:ini:raw)\n"
            "  param_network: 127.0.0.0/24 (site:ini:raw)\n",
        )
