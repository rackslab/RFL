# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import unittest
from unittest import mock
import os
import sys
import logging

from rfl.log.pager import AutoPager, PagerError, enable_auto_paging


class TestAutoPagerInit(unittest.TestCase):
    """Test the AutoPager constructor."""

    def test_init_default_parameters(self):
        """Test AutoPager initialization with default parameters."""
        pager = AutoPager()
        self.assertIsNone(pager.pager)
        self.assertTrue(pager.fallback_to_cat)
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)
        self.assertIsNone(pager._pager_process)
        self.assertIsNone(pager._pipe_read)
        self.assertIsNone(pager._pipe_write)
        self.assertEqual(pager._logging_handlers_original_streams, [])

    def test_init_custom_parameters(self):
        """Test AutoPager initialization with custom parameters."""
        pager = AutoPager(pager="less", fallback_to_cat=False)
        self.assertEqual(pager.pager, "less")
        self.assertFalse(pager.fallback_to_cat)

    def test_init_pager_none(self):
        """Test AutoPager initialization with pager=None."""
        pager = AutoPager(pager=None)
        self.assertIsNone(pager.pager)


class TestAutoPagerStart(unittest.TestCase):
    """Test the AutoPager.start() method."""

    def setUp(self):
        """Set up test environment."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.original_environ = os.environ.copy()

    def tearDown(self):
        """Clean up test environment."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        os.environ.clear()
        os.environ.update(self.original_environ)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    def test_start_no_tty(self, mock_env_get, mock_isatty):
        """Test start() when not connected to a TTY."""
        mock_isatty.return_value = False
        mock_env_get.return_value = None

        pager = AutoPager()
        pager.start()

        # Should not start paging when not a TTY
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    def test_start_no_pager_env_var(self, mock_env_get, mock_isatty):
        """Test start() when NO_PAGER environment variable is set."""
        mock_isatty.return_value = True
        mock_env_get.side_effect = lambda key: "1" if key == "NO_PAGER" else None

        pager = AutoPager()
        pager.start()

        # Should not start paging when NO_PAGER is set
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_start_successful(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test successful start() with pager detection."""
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)  # read_fd, write_fd
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = AutoPager()
        pager.start()

        # Should have started paging
        self.assertEqual(pager._original_stdout, self.original_stdout)
        self.assertEqual(pager._original_stderr, self.original_stderr)
        self.assertEqual(pager._pager_process, mock_process)
        # _pipe_read is set to None after os.close() is called
        self.assertIsNone(pager._pipe_read)
        self.assertEqual(pager._pipe_write, 4)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    def test_start_no_pager_available(self, mock_which, mock_env_get, mock_isatty):
        """Test start() when no pager is available and fallback is disabled."""
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = None

        pager = AutoPager(fallback_to_cat=False)
        pager.start()

        # Should not start paging when no pager is available
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_start_with_specific_pager(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test start() with a specific pager command."""
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/more"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = AutoPager(pager="more")
        pager.start()

        # Should have started with the specific pager
        mock_popen.assert_called_once()
        call_args = mock_popen.call_args[0][0]
        self.assertEqual(call_args, ["more"])

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    def test_start_specific_pager_not_found(
        self, mock_which, mock_env_get, mock_isatty
    ):
        """Test start() when specific pager is not found."""
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = None

        pager = AutoPager(pager="nonexistent_pager")
        pager.start()

        # Should not start paging when specific pager is not found
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)


class TestAutoPagerStop(unittest.TestCase):
    """Test the AutoPager.stop() method."""

    def setUp(self):
        """Set up test environment."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    def tearDown(self):
        """Clean up test environment."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    def test_stop_not_started(self):
        """Test stop() when pager was not started."""
        pager = AutoPager()
        # Don't call start()
        pager.stop()

        # Should not raise any errors
        self.assertIsNone(pager._original_stdout)

    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_stop_successful(
        self,
        mock_fdopen,
        mock_close,
        mock_which,
        mock_env_get,
        mock_isatty,
        mock_pipe,
        mock_popen,
    ):
        """Test successful stop() after start()."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = AutoPager()
        pager.start()
        pager.stop()

        # Should have restored original streams
        self.assertEqual(sys.stdout, self.original_stdout)
        self.assertEqual(sys.stderr, self.original_stderr)
        # Should have waited for pager process
        mock_process.wait.assert_called_once()

    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_stop_process_wait_error(
        self,
        mock_fdopen,
        mock_close,
        mock_which,
        mock_env_get,
        mock_isatty,
        mock_pipe,
        mock_popen,
    ):
        """Test stop() when process.wait() raises an exception."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_process.wait.side_effect = Exception("Process error")
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = AutoPager()
        pager.start()

        # Should raise PagerError when process.wait() fails
        with self.assertRaises(PagerError) as context:
            pager.stop()
        self.assertIn("Failed to wait for pager process", str(context.exception))


class TestAutoPagerContextManager(unittest.TestCase):
    """Test the AutoPager context manager functionality."""

    def setUp(self):
        """Set up test environment."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    def tearDown(self):
        """Clean up test environment."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_context_manager_success(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test context manager with successful pager start/stop."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        with AutoPager() as pager:
            # Should have started paging
            self.assertEqual(pager._original_stdout, self.original_stdout)
            self.assertEqual(pager._original_stderr, self.original_stderr)

        # Should have restored streams after context exit
        self.assertEqual(sys.stdout, self.original_stdout)
        self.assertEqual(sys.stderr, self.original_stderr)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_context_manager_exception(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test context manager with exception during execution."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        with self.assertRaises(ValueError):
            with AutoPager() as pager:
                # Should have started paging
                self.assertEqual(pager._original_stdout, self.original_stdout)
                raise ValueError("Test exception")

        # Should have restored streams even after exception
        self.assertEqual(sys.stdout, self.original_stdout)
        self.assertEqual(sys.stderr, self.original_stderr)


class TestEnableAutoPaging(unittest.TestCase):
    """Test the enable_auto_paging() function."""

    def setUp(self):
        """Set up test environment."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    def tearDown(self):
        """Clean up test environment."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_enable_auto_paging_default(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test enable_auto_paging() with default parameters."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = enable_auto_paging()

        # Should return an AutoPager instance
        self.assertIsInstance(pager, AutoPager)
        # Should have started paging
        self.assertEqual(pager._original_stdout, self.original_stdout)
        self.assertEqual(pager._original_stderr, self.original_stderr)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_enable_auto_paging_custom(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test enable_auto_paging() with custom parameters."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/more"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        pager = enable_auto_paging(pager="more", fallback_to_cat=False)

        # Should return an AutoPager instance with custom parameters
        self.assertIsInstance(pager, AutoPager)
        self.assertEqual(pager.pager, "more")
        self.assertFalse(pager.fallback_to_cat)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    def test_enable_auto_paging_no_tty(self, mock_env_get, mock_isatty):
        """Test enable_auto_paging() when not connected to a TTY."""
        mock_isatty.return_value = False
        mock_env_get.return_value = None

        pager = enable_auto_paging()

        # Should return an AutoPager instance but not start paging
        self.assertIsInstance(pager, AutoPager)
        self.assertIsNone(pager._original_stdout)
        self.assertIsNone(pager._original_stderr)


class TestAutoPagerLoggingHandlers(unittest.TestCase):
    """Test logging handler redirection functionality."""

    def setUp(self):
        """Set up test environment."""
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        # Clear any existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    def tearDown(self):
        """Clean up test environment."""
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr
        # Clear any existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

    @mock.patch("sys.stdout.isatty")
    @mock.patch("os.environ.get")
    @mock.patch("shutil.which")
    @mock.patch("subprocess.Popen")
    @mock.patch("os.pipe")
    @mock.patch("os.close")
    @mock.patch("os.fdopen")
    def test_logging_handler_redirection(
        self,
        mock_fdopen,
        mock_close,
        mock_pipe,
        mock_popen,
        mock_which,
        mock_env_get,
        mock_isatty,
    ):
        """Test that logging handlers are properly redirected and restored."""
        # Setup mocks
        mock_isatty.return_value = True
        mock_env_get.return_value = None
        mock_which.return_value = "/usr/bin/less"
        mock_pipe.return_value = (3, 4)
        mock_process = mock.MagicMock()
        mock_process.wait.return_value = 0
        mock_popen.return_value = mock_process
        mock_file = mock.MagicMock()
        mock_fdopen.return_value = mock_file

        # Create a logging handler that writes to stdout
        handler = logging.StreamHandler(sys.stdout)
        root_logger = logging.getLogger()
        root_logger.addHandler(handler)

        pager = AutoPager()
        pager.start()

        # Handler should be redirected to the pager pipe
        self.assertEqual(handler.stream, mock_file)
        self.assertEqual(len(pager._logging_handlers_original_streams), 1)

        pager.stop()

        # Handler should be restored to original stream
        self.assertEqual(handler.stream, self.original_stdout)
        self.assertEqual(len(pager._logging_handlers_original_streams), 0)
