# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later


class SettingsError(Exception):
    pass


class SettingsDefinitionError(SettingsError):
    pass


class SettingsSiteLoaderError(SettingsError):
    pass


class SettingsOverrideError(SettingsError):
    pass
