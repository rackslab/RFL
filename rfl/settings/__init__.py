# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from pathlib import Path
import urllib

import logging

import yaml

from .definition import (
    SettingsDefinition,
    SettingsSectionDefinition,
    SettingsParameterDefinition,
    SettingsDefinitionLoaderYaml,
)
from .loaders import RuntimeSettingsSiteLoader, RuntimeSettingsSiteLoaderIni
from ..errors import SettingsDefinitionError, SettingsOverrideError

logger = logging.getLogger(__name__)


class RuntimeSettingsSection:
    def __init__(self, section: SettingsSectionDefinition):
        self._name = section.name
        for parameter in section.parameters:
            setattr(self, parameter.name, parameter.default)


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
            )(section)
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

    def _override_parameter(
        self,
        loader: RuntimeSettingsSiteLoader,
        section: SettingsSectionDefinition,
        parameter: SettingsParameterDefinition,
    ) -> None:
        # check type, choices and convert to advanced types
        raw = loader.content[section.name].get(parameter.name)
        if parameter._type == "path":
            value = Path(raw)
        elif parameter._type == "uri":
            value = urllib.parse.urlparse(raw)
        elif parameter._type == "int":
            try:
                value = int(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid integer value '{raw}' for {parameter} in site overrides"
                ) from err
        elif parameter._type == "float":
            try:
                value = float(raw)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid float value '{raw}' for {parameter} in site overrides"
                ) from err
        elif parameter._type == "bool":
            try:
                value = loader.content[section.name].getboolean(parameter.name)
            except ValueError as err:
                raise SettingsOverrideError(
                    f"Invalid boolean value '{raw}' for {parameter} in site overrides"
                ) from err
        else:
            value = raw
        if parameter.choices is not None and value not in parameter.choices:
            raise SettingsOverrideError(
                f"Value {value} for parameter {parameter} in site overrides is "
                f"not one of possible choices {parameter.choices}"
            )
        setattr(getattr(self, section.name), parameter.name, value)

    def override_ini(self, path: Path):
        self.override(RuntimeSettingsSiteLoaderIni(path=path))

    @classmethod
    def definition_yaml(cls, path: Path):
        return cls(SettingsDefinition(SettingsDefinitionLoaderYaml(path=path)))
