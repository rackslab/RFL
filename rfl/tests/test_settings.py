# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import copy
from pathlib import Path
import urllib

from ..settings.definition import SettingsDefinition, SettingsDefinitionLoaderYaml
from ..settings.loaders import RuntimeSettingsSiteLoaderIni
from ..settings import RuntimeSettings, RuntimeSettingsSection

from ..errors import SettingsDefinitionError, SettingsOverrideError

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
"""

VALID_SITE = """
[section1]
param_str = site_value1

[section2]
param_path = /site/path/to/file
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

    def test_default_invalid_type_int(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value fail for parameter param_int has not the expected type "
            "int$",
        ):
            definition = SettingsDefinition(loader)

    def test_default_invalid_type_bool(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_bool"]["default"] = "fail"
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value fail for parameter param_bool has not the expected type "
            "bool$",
        ):
            definition = SettingsDefinition(loader)

    def test_default_invalid_choice(self):
        loader = SettingsDefinitionLoaderYaml(raw=VALID_DEFINITION)
        loader.content["section2"]["param_int"]["default"] = 12
        with self.assertRaisesRegex(
            SettingsDefinitionError,
            "^Default value 12 for parameter param_int is not one of possible choices "
            "\[10, 100, 500\]$",
        ):
            definition = SettingsDefinition(loader)


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
