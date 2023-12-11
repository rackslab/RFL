# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from pathlib import Path

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
"""


class TestSettingsDefinition(unittest.TestCase):
    def test_valid_content(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
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
            SettingsDefinitionError, "^Invalid YAML settings definition: "
        ):
            SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION + "\n fail")
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^YAML scanner error: mapping values are not allowed here.*",
        ):
            SettingsDefinitionLoaderYaml(raw="fail: again: ")

    def test_unsupported_property(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["unknown"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Unsupported properties found for \[section2\]>param_int: unknown$",
        ):
            SettingsDefinition(loader)

    def test_unsupported_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["type"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Unsupported type fail for \[section2\]>param_int$",
        ):
            SettingsDefinition(loader)

    def test_required_not_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_required"]["required"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Invalid boolean value of \[section2\]>param_required required property$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_int(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value fail for parameter \[section2\]>param_int has not the "
            "expected type int$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_bool"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value fail for parameter \[section2\]>param_bool has not the "
            "expected type bool$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_choice(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = 12
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value 12 for parameter \[section2\]>param_int is not one of "
            "possible choices \[10, 100, 500\]$",
        ):
            SettingsDefinition(loader)

    def test_default_invalid_type_list(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value fail for parameter \[section2\]>param_list is not a valid "
            "list$",
        ):
            SettingsDefinition(loader)

    def test_type_list_without_content(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        del loader.content["section2"]["param_list"]["content"]
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^List content type for parameter \[section2\]>param_list must be defined$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_content_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["content"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Unsupported list content type fail for \[section2\]>param_list$",
        ):
            SettingsDefinition(loader)
        loader.content["section2"]["param_list"]["content"] = "list"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Unsupported list content type list for \[section2\]>param_list$",
        ):
            SettingsDefinition(loader)

    def test_type_content_on_other_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["type"] = "str"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Content property is forbidden for parameter \[section2\]>param_list with "
            "type str$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_default_type(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["content"] = "bool"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value value1 for parameter \[section2\]>param_list has not the "
            "expected type bool$",
        ):
            SettingsDefinition(loader)

    def test_type_list_invalid_choice(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_list"]["choices"] = ["value1", "value3"]
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value value2 for parameter \[section2\]>param_list is not one of "
            "possible choices \['value1', 'value3'\]$",
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
        settings.override(site_loader)
        self.assertEqual(settings.section1.param_str, "site_value1")
        self.assertEqual(settings.section2.param_path, Path("/site/path/to/file"))
        self.assertEqual(settings.section2.param_list, ["value3", "value5"])

    def test_site_override_invalid_section(self):
        def_loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        definition = SettingsDefinition(def_loader)
        settings = RuntimeSettings(definition)
        site_loader = RuntimeSettingsSiteLoaderIni(VALID_SITE)
        site_loader.content["big"] = {}
        with self.assertRaisesRegex(
            SettingsOverrideError,
            "^Section big loaded in settings overrides is not defined in "
            "settings definition$",
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
            "^Parameter unknown loaded in settings overrides is not defined in "
            "section section2 of settings definition$",
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
            "^Invalid integer value 'fail' for \[section2\]>param_int in site "
            "overrides$",
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
            "^Invalid float value 'fail' for \[section2\]>param_float in site "
            "overrides$",
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
            "^Invalid boolean value 'fail' for \[section2\]>param_bool in site "
            "overrides$",
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
            "^Value 12 for parameter \[section2\]>param_int in site overrides is not "
            "one of possible choices \[10, 100, 500\]$",
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
            "^Parameter \[section2\]>param_required is missing but required in "
            "settings overrides$",
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
            "^Invalid integer value 'value3' for \[section2\]>param_list in site "
            "overrides$",
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
            "^Value value3 for parameter \[section2\]>param_list in site overrides is "
            "not one of possible choices \['value1', 'value2'\]$",
        ):
            settings.override(site_loader)
