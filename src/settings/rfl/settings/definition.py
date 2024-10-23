# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import urllib
import ipaddress

import yaml

from .errors import SettingsDefinitionError


class SettingsDefinitionLoader:
    pass


class SettingsDefinitionLoaderYaml(SettingsDefinitionLoader):
    def __init__(self, raw: str = None, path: Path = None):
        try:
            if raw is not None:
                self.content = yaml.safe_load(raw)
                self.name = "definition:yaml:raw"
            elif path is not None:
                try:
                    with open(path) as fh:
                        self.content = yaml.safe_load(fh)
                except FileNotFoundError as err:
                    raise SettingsDefinitionError(
                        f"Settings definition file {path} not found"
                    ) from err
                self.name = f"def:yaml:{path}"
            else:
                raise SettingsDefinitionError(
                    "Either a raw string value or a path must be given to load YAML "
                    "settings definition"
                )
        except yaml.parser.ParserError as err:
            raise SettingsDefinitionError(
                f"Invalid YAML settings definition: {str(err)}"
            ) from err
        except yaml.scanner.ScannerError as err:
            raise SettingsDefinitionError(f"YAML scanner error: {str(err)}") from err


class SettingsParameterDefinition:
    # Map properties that can be found in definition file with corresponding
    # object attributes names.
    POSSIBLE_PROPERTIES = {
        "type": "_type",
        "content": "content",
        "default": "default",
        "choices": "choices",
        "doc": "doc",
        "ex": "example",
        "required": "required",
    }
    EXPECTED_TYPES = {
        "str": str,
        "password": str,
        "int": int,
        "float": float,
        "path": Path,
        "bool": bool,
        "uri": urllib.parse.ParseResult,
        "ip": ipaddress._BaseAddress,
        "network": ipaddress._BaseNetwork,
        "list": list,
    }

    def __init__(self, section: str, name: str, properties: dict):
        self.section = section
        self.name = name

        # Check for unsupported properties
        unsupported_properties = list(
            set(properties.keys()).difference(self.POSSIBLE_PROPERTIES.keys())
        )
        if len(unsupported_properties):
            raise SettingsDefinitionError(
                f"Unsupported properties found for {str(self)}: "
                f"{','.join(unsupported_properties)}"
            )

        for _property, attribute in self.POSSIBLE_PROPERTIES.items():
            value = None
            if _property in properties:
                value = properties[_property]
            setattr(self, attribute, value)

        # Check the type of defined parameter is actually supported
        if self._type not in self.EXPECTED_TYPES:
            raise SettingsDefinitionError(
                f"Unsupported type {self._type} for {str(self)}"
            )

        # Check content property is defined for list and check content type is actually
        # supported.
        if self._type == "list":
            if "content" not in properties:
                raise SettingsDefinitionError(
                    f"List content type for parameter {str(self)} must be defined"
                )
            elif self.content not in set(self.EXPECTED_TYPES.keys()) - {"list"}:
                raise SettingsDefinitionError(
                    f"Unsupported list content type {self.content} for {str(self)}"
                )
        # Check content property is not defined if not list
        if "content" in properties and self._type != "list":
            raise SettingsDefinitionError(
                f"Content property is forbidden for parameter {str(self)} with type "
                f"{self._type}"
            )

        # If the default value is defined, convert to the expected type and validate it
        # is a valid choice.
        if self.default is not None:
            if self._type == "list":
                if not isinstance(self.default, list):
                    raise SettingsDefinitionError(
                        f"Default value {self.default} for parameter {str(self)} is "
                        "not a valid list"
                    )
                self.default = [
                    self._load_default(self.content, default)
                    for default in self.default
                ]
                for item in self.default:
                    self._validate_choice(item)
            else:
                self.default = self._load_default(self._type, self.default)
                self._validate_choice(self.default)

        if self.required is None:
            self.required = False
        elif not isinstance(self.required, bool):
            raise SettingsDefinitionError(
                f"Invalid boolean value of {str(self)} required property"
            )

    def _load_default(self, _type, default):
        """Verify default has the expected type and convert to advanded type if
        needed."""
        if _type == "path":
            return Path(default)
        elif _type == "uri":
            return urllib.parse.urlparse(default)
        elif _type == "ip":
            try:
                return ipaddress.ip_address(default)
            except ValueError as err:
                raise SettingsDefinitionError(
                    f"Invalid default ip address value for parameter {str(self)}"
                ) from err
        elif _type == "network":
            try:
                return ipaddress.ip_network(default)
            except ValueError as err:
                raise SettingsDefinitionError(
                    f"Invalid default ip network value for parameter {str(self)}"
                ) from err
        if not isinstance(default, self.EXPECTED_TYPES[_type]):
            raise SettingsDefinitionError(
                f"Default value {default} for parameter {str(self)} has not "
                f"the expected type {_type}"
            )
        return default

    def _validate_choice(self, default):
        """Check default is a valid choice or raise SettingsDefinitionError."""
        if self.choices is not None and default not in self.choices:
            raise SettingsDefinitionError(
                f"Default value {default} for parameter {str(self)} is not "
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
        self.loader = loader
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
