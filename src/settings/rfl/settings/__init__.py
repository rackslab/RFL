# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import urllib
import ipaddress

import logging

from .definition import (
    SettingsDefinition,
    SettingsSectionDefinition,
    SettingsParameterDefinition,
    SettingsDefinitionLoaderYaml,
)
from .loaders import RuntimeSettingsSiteLoader, RuntimeSettingsSiteLoaderIni
from .errors import SettingsOverrideError

logger = logging.getLogger(__name__)


class RuntimeSettingsSection:
    def __init__(self, section: SettingsSectionDefinition, origin: str):
        self._name = section.name
        self._origin = {}
        for parameter in section.parameters:
            setattr(self, parameter.name, parameter.default)
            self._origin[parameter.name] = origin


class RuntimeSettings:
    def __init__(self, definition: SettingsDefinition):
        # set to hold all sections names
        self._sections = set()
        self._definition = definition
        for section in definition.sections:
            o_section = type(
                f"{self.__class__.__name__}{section.name.capitalize()}",
                (RuntimeSettingsSection,),
                dict(),
            )(section, definition.loader.name)
            setattr(self, o_section._name, o_section)
            self._sections.add(o_section._name)

    def override(self, loader: RuntimeSettingsSiteLoader):
        # load site ini file and check it matches definition
        for section_name in loader.content.sections():
            if not self._definition.has_section(section_name):
                raise SettingsOverrideError(
                    f"Section {section_name} loaded in settings overrides is not "
                    "defined in settings definition"
                )
            section = self._definition.section(section_name)
            for parameter_name in loader.content[section.name]:
                if not section.has_parameter(parameter_name):
                    raise SettingsOverrideError(
                        f"Parameter {parameter_name} loaded in settings overrides is "
                        f"not defined in section {section.name} of settings definition"
                    )
                parameter = section.parameter(parameter_name)
                self._override_parameter(loader, section, parameter)

        # check required parameters
        self._check_required()

    def _check_required(self):
        """Verify that all parameters declared as required in settings definition are
        properly defined with a real value or raise SettingsOverrideError."""
        for section in self._definition.sections:
            for parameter in section.parameters:
                if (
                    parameter.required
                    and getattr(getattr(self, parameter.section), parameter.name)
                    is None
                ):
                    raise SettingsOverrideError(
                        f"Parameter {str(parameter)} is missing but required in "
                        "settings overrides"
                    )

    def _override_parameter(
        self,
        loader: RuntimeSettingsSiteLoader,
        section: SettingsSectionDefinition,
        parameter: SettingsParameterDefinition,
    ) -> None:
        """Load value from INI file, convert it to expected type, verify it is a valid
        choice and set corresponding object attribute. Special logic is applied for list
        to iterate over the items."""
        raw = loader.content[section.name].get(parameter.name)
        if parameter._type == "list":
            value = [
                self._load_parameter_value(parameter, parameter.content, raw)
                for raw in raw.strip().split("\n")
            ]
            for item in value:
                self._validate_choice(parameter, item)
        else:
            value = self._load_parameter_value(parameter, parameter._type, raw)
            self._validate_choice(parameter, value)
        setattr(getattr(self, section.name), parameter.name, value)
        getattr(self, section.name)._origin[parameter.name] = loader.name

    def _load_parameter_value(self, parameter, _type: str, raw: str):
        """Try to convert raw value to expected type or raise SettingsOverrideError."""
        if _type == "path":
            # Converting a string to a pathlib.Path basically never fails.
            return Path(raw)
        elif _type == "uri":
            # Converting a string to a urllib.ParseResult basically never fails.
            return urllib.parse.urlparse(raw)
        elif _type == "ip":
            try:
                return ipaddress.ip_address(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid ip address value '{raw}' for {parameter} in site "
                    "overrides"
                ) from err
        elif _type == "network":
            try:
                return ipaddress.ip_network(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid ip network value '{raw}' for {parameter} in site "
                    "overrides"
                ) from err
        elif _type == "int":
            try:
                return int(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid integer value '{raw}' for {parameter} in site overrides"
                ) from err
        elif _type == "float":
            try:
                return float(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid float value '{raw}' for {parameter} in site overrides"
                ) from err
        elif _type == "bool":
            if raw.lower() in ["1", "yes", "true", "on"]:
                return True
            elif raw.lower() in ["0", "no", "false", "off"]:
                return False
            else:
                raise SettingsOverrideError(
                    f"Invalid boolean value '{raw}' for {parameter} in site overrides"
                )
        else:
            # Return unmodified value
            return raw

    def _validate_choice(self, parameter, value):
        """Validate value is in parameter choices or raise SettingsOverrideError."""
        if parameter.choices is not None and value not in parameter.choices:
            raise SettingsOverrideError(
                f"Value {value} for parameter {parameter} in site overrides is "
                f"not one of possible choices {parameter.choices}"
            )

    def dump(self):
        """Print configuration parameters grouped by section, with the origin of their
        value (definition or site) on standard output."""
        for section_name in sorted(self._sections):
            print(f"[{section_name}]")
            section = getattr(self, section_name)
            for parameter_name, origin in section._origin.items():
                value = getattr(section, parameter_name)
                # Hide passwords
                if value is not None and (
                    self._definition.section(section_name)
                    .parameter(parameter_name)
                    ._type
                    == "password"
                ):
                    value = "•" * len(value)
                if value is not None and (
                    self._definition.section(section_name)
                    .parameter(parameter_name)
                    ._type
                    == "password"
                ):
                    value = "•" * len(value)
                print(
                    f"  {parameter_name}: {value} " f"({origin})",
                )

    def override_ini(self, path: Path) -> None:
        self.override(RuntimeSettingsSiteLoaderIni(path=path))

    @classmethod
    def yaml_definition(cls, path: Path):
        return cls(SettingsDefinition(SettingsDefinitionLoaderYaml(path=path)))
