# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import os
import tempfile
import textwrap
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from setuptools import find_packages


def _setup_script_path():
    return Path(__file__).resolve().parents[1] / "build" / "scripts" / "setup"


def _write_pyproject(tmpdir, content):
    Path(tmpdir).joinpath("pyproject.toml").write_text(content, encoding="utf-8")


def _run_setup_script():
    path = _setup_script_path()
    code = path.read_text(encoding="utf-8")
    exec(compile(code, str(path), "exec"), {"__name__": "__main__"})


def _minimal_pyproject(extra="", license_line='license = "LGPL-3.0-or-later"'):
    content = textwrap.dedent(
        f"""\
        [project]
        name = "test-pkg"
        version = "1.0.0"
        {license_line}
        authors = [
            {{name = "Test Author", email = "test@example.com"}},
        ]
        """
    )
    if extra:
        content += textwrap.dedent(extra)
    return content


@contextmanager
def _project_dir(pyproject_content, layout=None):
    previous_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_pyproject(tmpdir, pyproject_content)
        if layout:
            layout(Path(tmpdir))
        os.chdir(tmpdir)
        try:
            yield tmpdir
        finally:
            os.chdir(previous_cwd)


class TestSetupScript(unittest.TestCase):
    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_missing_project_section_exits(self, mock_setup, mock_exit):
        mock_exit.side_effect = SystemExit
        pyproject = textwrap.dedent(
            """\
            [build-system]
            requires = ['setuptools']
            """
        )
        with _project_dir(pyproject):
            with self.assertRaises(SystemExit):
                _run_setup_script()

        mock_exit.assert_called_once_with(0)
        mock_setup.assert_not_called()

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_minimal_project_metadata(self, mock_setup, mock_exit):
        with _project_dir(_minimal_pyproject()):
            _run_setup_script()

        mock_exit.assert_not_called()
        mock_setup.assert_called_once_with(
            name="test-pkg",
            version="1.0.0",
            author="Test Author",
            author_email="test@example.com",
            platforms=["GNU/Linux"],
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_console_scripts_entry_points(self, mock_setup, mock_exit):
        extra = """
        [project.scripts]
        my-cmd = "mypkg.cli:main"
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        kwargs = mock_setup.call_args[1]
        self.assertEqual(
            kwargs["entry_points"],
            {"console_scripts": ["my-cmd=mypkg.cli:main"]},
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_namespace_packages_explicit_list(self, mock_setup, mock_exit):
        extra = """
        [tool.setuptools.packages.find]
        include = ["rfl.build*"]
        """

        def layout(root):
            rfl_build = root / "rfl" / "build"
            rfl_build.mkdir(parents=True)
            rfl_build.joinpath("__init__.py").write_text("", encoding="utf-8")

        with _project_dir(_minimal_pyproject(extra), layout=layout):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(mock_setup.call_args[1]["packages"], ["rfl.build"])

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_autofind_packages(self, mock_setup, mock_exit):
        extra = """
        [tool.setuptools.packages.find]
        include = ["mypkg.*"]
        """

        def layout(root):
            mypkg = root / "mypkg"
            mypkg.mkdir()
            mypkg.joinpath("__init__.py").write_text("", encoding="utf-8")

        with _project_dir(_minimal_pyproject(extra), layout=layout):
            _run_setup_script()
            expected_packages = find_packages()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["packages"],
            expected_packages,
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_explicit_packages_without_find(self, mock_setup, mock_exit):
        extra = """
        [tool.setuptools]
        packages = ["pkg.a", "pkg.b"]
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["packages"],
            ["pkg.a", "pkg.b"],
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_package_data(self, mock_setup, mock_exit):
        extra = """
        [tool.setuptools.package-data]
        "pkg.data" = ["*.json"]
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        kwargs = mock_setup.call_args[1]
        self.assertEqual(kwargs["package_data"], {"pkg.data": ["*.json"]})
        self.assertTrue(kwargs["include_package_data"])

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_install_requires(self, mock_setup, mock_exit):
        extra = """
        dependencies = [
            "dep-a",
            "dep-b",
        ]
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["install_requires"],
            ["dep-a", "dep-b"],
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_extras_require(self, mock_setup, mock_exit):
        extra = """
        [project.optional-dependencies]
        dev = ["pytest"]
        docs = ["sphinx"]
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["extras_require"],
            {"dev": ["pytest"], "docs": ["sphinx"]},
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_license_text(self, mock_setup, mock_exit):
        with _project_dir(
            _minimal_pyproject(license_line='license = { text = "MIT" }')
        ):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(mock_setup.call_args[1]["license"], "MIT")

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_license_file(self, mock_setup, mock_exit):
        with _project_dir(
            _minimal_pyproject(license_line='license = { file = "LICENSE" }')
        ):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["license_files"],
            ["LICENSE"],
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_homepage_url(self, mock_setup, mock_exit):
        extra = """
        [project.urls]
        Homepage = "https://example.com"
        """
        with _project_dir(_minimal_pyproject(extra)):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(
            mock_setup.call_args[1]["url"],
            "https://example.com",
        )

    @patch("sys.exit")
    @patch("setuptools.setup")
    def test_skip_bare_include_pattern(self, mock_setup, mock_exit):
        extra = """
        [tool.setuptools.packages.find]
        include = ["rfl", "rfl.build*"]
        """

        def layout(root):
            rfl_build = root / "rfl" / "build"
            rfl_build.mkdir(parents=True)
            rfl_build.joinpath("__init__.py").write_text("", encoding="utf-8")

        with _project_dir(_minimal_pyproject(extra), layout=layout):
            _run_setup_script()

        mock_setup.assert_called_once()
        self.assertEqual(mock_setup.call_args[1]["packages"], ["rfl.build"])
