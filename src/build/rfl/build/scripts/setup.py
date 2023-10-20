# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This setup.py loads parameter defined in pyproject.toml and calls setuptools.setup()
with these parameters. This script is especially useful to build modern PEP 518 Python
projects that provide pyproject.toml with old versions of pip/python (eg. python 3.6)
without support PEP 518.
"""

from setuptools import setup, find_packages

import tomli

with open("pyproject.toml", "rb") as fh:
    pyproject = tomli.load(fh)

kwargs = {}
if "scripts" in pyproject["project"]:
    kwargs["entry_points"] = {
        "console_scripts": [
            f"{executable}={caller}"
            for executable, caller in pyproject["project"]["scripts"].items()
        ]
    }

setup(
    name=pyproject["project"]["name"],
    version=pyproject["project"]["version"],
    packages=find_packages(),
    author=pyproject["project"]["authors"][0]["name"],
    author_email=pyproject["project"]["authors"][0]["email"],
    license=pyproject["project"]["license"]["text"],
    url=pyproject["project"]["urls"]["Homepage"],
    platforms=["GNU/Linux"],
    install_requires=pyproject["project"]["dependencies"],
    **kwargs,
)
