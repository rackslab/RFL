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
import os

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

# Python Packaging User Guide suggests using find_namespace_packages(…) to support
# namespace packages:
#
# https://packaging.python.org/en/latest/guides/packaging-namespace-packages/#native-namespace-packages
#
# Unfortunately, this function is not support in setuptools < v40.1.0 that is provided
# on systems with Python 3.6 where this setup.py script is required (el8). The
# alternative solution is to explicitely list the packages to install. Then the
# following logic detects if there is a native namespace (when one topfolder declared in
# [tool.setuptools.packages.find] include directive does not contain an __init__.py). In
# this case, the subpackages are explicity declared (without wildcard) in setup(). If no
# namespace is detected, the packages are automatically detected with find_packages().

autofind = True
packages = []
for include in pyproject["tool"]["setuptools"]["packages"]["find"]["include"]:
    if "." not in include:
        continue
    topfolder = include.split(".", 1)[0]
    if "__init__.py" not in os.listdir(topfolder):
        autofind = False
    packages.append(include.replace("*",""))

if autofind:
    kwargs["packages"] = find_packages()
else:
    kwargs["packages"] = packages

setup(
    name=pyproject["project"]["name"],
    version=pyproject["project"]["version"],
    author=pyproject["project"]["authors"][0]["name"],
    author_email=pyproject["project"]["authors"][0]["email"],
    license=pyproject["project"]["license"]["text"],
    url=pyproject["project"]["urls"]["Homepage"],
    platforms=["GNU/Linux"],
    install_requires=pyproject["project"]["dependencies"],
    **kwargs,
)
