# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import os
from pathlib import Path
import shutil


def main():
    """Install setup.py script provided by RFL.build package in scripts/ subfolder in
    the current working directory."""
    orig = Path(os.path.realpath(__file__)).parent.joinpath("scripts", "setup")
    dest = Path(os.getcwd()).joinpath("setup.py")
    print(f"Copying file {orig} to {dest}")
    shutil.copy(orig, dest)
