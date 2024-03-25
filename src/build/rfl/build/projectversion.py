# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This tiny utility loads pyproject.toml file of current working directory project,
looking for this file in parents directory recursively up to filesystem root. If the
file is found, print the version of the project on stdout. Else, print an error.
"""

import sys
from pathlib import Path

# First try to import Python standard toml library (available in Python 3.11+) and
# fallback to external library.
try:
    import tomllib
except ImportError:
    import tomli as tomllib

from .errors import BuildError


def project_version():
    current_dir = Path.cwd()
    found = False
    while True:
        pyproject_path = current_dir.joinpath("pyproject.toml")
        if pyproject_path.exists():
            found = True
            break
        else:
            # Stop iteration when filesystem root is reached.
            if str(current_dir) == current_dir.root:
                break
            # Jump to parent directory.
            current_dir = current_dir.parent

    if not found:
        raise BuildError(
            "Unable to find project pyproject.toml file of current working directory",
        )
    content = tomllib.load(open(pyproject_path, "rb"))
    try:
        return content["project"]["version"]
    except KeyError as err:
        raise BuildError(
            f"Unable to extract version from project file {pyproject_path}"
        ) from err


def main():
    try:
        print(project_version())
    except BuildError as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
