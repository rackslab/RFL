# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import urllib

import yaml

from .errors import SettingsDefinitionError


class SettingsDefinitionLoader:
    pass


class SettingsDefinitionLoaderYaml(SettingsDefinitionLoader):
    def __init__(self, raw: str = None, path: Path = None):
        try:
            if raw is not None:
                self.content = yaml.safe_load(raw)
            elif path is not None:
                try:
                    with open(path) as fh:
                        self.content = yaml.safe_load(fh)
                except FileNotFoundError:
                    raise SettingsDefinitionError(
                        f"Settings definition file {path} not found"
                    )
            else:
                raise SettingsDefinitionError(
                    "Either a raw string value or a path must be given to load YAML "
                    "settings definition"
                )
        except yaml.parser.ParserError as err:
            raise SettingsDefinitionError(
                f"Invalid YAML settings definition: {str(err)}"
            ) from err


class SettingsParameterDefinition:
    # Map properties that can be found in definition file with corresponding
    # object attributes names.
    POSSIBLE_PROPERTIES = {
        "type": "_type",
        "default": "default",
        "choices": "choices",
        "doc": "doc",
        "ex": "example",
    }
    EXPECTED_TYPES = {
        "str": str,
        "int": int,
        "float": float,
        "path": Path,
        "bool": bool,
        "uri": urllib.parse.ParseResult,
    }

    def __init__(self, section: str, name: str, properties: dict):
        self.section = section
        self.name = name
        for _property, attribute in self.POSSIBLE_PROPERTIES.items():
            value = None
            if _property in properties:
                value = properties[_property]
            setattr(self, attribute, value)
        # If the default value is defined, convert advanced type and ensure default
        # value matches type if defined.
        if self.default is not None:
            # Advanced types such as path and uri are read as native strings, they must
            # be converted manually to the expected type.
            if self._type == "path":
                self.default = Path(self.default)
            elif self._type == "uri":
                self.default = urllib.parse.urlparse(self.default)
            if not isinstance(self.default, self.EXPECTED_TYPES[self._type]):
                raise SettingsDefinitionError(
                    f"Default value {self.default} for parameter {self.name} has not "
                    f"the expected type {self._type}"
                )
            # Check default is present among possible choices
            if self.choices is not None and self.default not in self.choices:
                raise SettingsDefinitionError(
                    f"Default value {self.default} for parameter {self.name} is not "
                    f"one of possible choices {self.choices}"
                )

    def __str__(self):
        return f"[{self.section}]>{self.name}"


class SettingsSectionDefinition:
    def __init__(self, section: str, parameters: dict):
        self.name = section
        self.parameters = [
            SettingsParameterDefinition(section, parameter, properties)
            for parameter, properties in parameters.items()
        ]

    def has_parameter(self, name: str) -> bool:
        for parameter in self.parameters:
            if parameter.name == name:
                return True
        return False

    def parameter(self, name: str):
        for parameter in self.parameters:
            if parameter.name == name:
                return parameter
        return None


class SettingsDefinition:
    def __init__(self, loader: SettingsDefinitionLoader):
        self.sections = [
            SettingsSectionDefinition(section, parameters)
            for section, parameters in loader.content.items()
        ]

    def has_section(self, name: str) -> bool:
        for section in self.sections:
            if section.name == name:
                return True
        return False

    def section(self, name: str):
        for section in self.sections:
            if section.name == name:
                return section
        return None
