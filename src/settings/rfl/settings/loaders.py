# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import configparser
from pathlib import Path
import logging

from .errors import SettingsSiteLoaderError

logger = logging.getLogger(__name__)


class RuntimeSettingsSiteLoader:
    pass


class RuntimeSettingsSiteLoaderIni(RuntimeSettingsSiteLoader):
    def __init__(self, raw: str = None, path: Path = None):
        self.content = configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation()
        )
        try:
            if raw is not None:
                logger.debug("Loading site settings in INI format from raw value")
                self.content.read_string(raw)
                self.name = "site:ini:raw"
            elif path is not None:
                logger.debug("Loading site settings file %s", path)
                self.content.read(path)
                self.name = f"site:ini:{path}"
            else:
                raise SettingsSiteLoaderError(
                    "Either a raw string value or a path must be given to load site "
                    "settings"
                )
        except configparser.Error as error:
            raise SettingsSiteLoaderError(error)
