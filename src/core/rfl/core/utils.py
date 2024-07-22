# Copyright (c) 2024 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List
import shlex


def shlex_join(cmd: List[str]) -> str:
    """Backport of shlex.join() required for Python <= 3.8"""
    return " ".join(shlex.quote(arg) for arg in cmd)
