# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Union, List


class AuthenticatedUser:
    def __init__(
        self, login: str, fullname: Union[str, None] = None, groups: List[str] = []
    ):
        self.login = login
        self.fullname = fullname
        self.groups = groups

    def __str__(self) -> str:
        return f"{self.login} ({self.fullname or '∅'}) [{', '.join(self.groups)}]"
