# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from rfl.core.errors import RFLError


class SettingsError(RFLError):
    pass


class SettingsDefinitionError(SettingsError):
    pass


class SettingsSiteLoaderError(SettingsError):
    pass


class SettingsOverrideError(SettingsError):
    pass
