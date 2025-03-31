# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
from unittest import mock
import os
import logging

from rfl.log.formatters import (
    auto_formatter,
    TTYFormatter,
    DaemonFormatter,
    LOG_LEVEL_ANSI_STYLES,
)

RECORD = logging.LogRecord("rfl", logging.INFO, "/test.py", 0, "test record", (), None)


class TestAutoFormatter(unittest.TestCase):
    def test_auto_formatter_no_tty(self):
        self.assertEqual(auto_formatter(), DaemonFormatter)

    def test_auto_formatter_tty(self):
        with mock.patch("sys.stdout.isatty") as mock_isatty:
            mock_isatty.return_value = True
            self.assertEqual(auto_formatter(), TTYFormatter)


class TestTTYFormatter(unittest.TestCase):
    def test_format(self):
        formatter = TTYFormatter()
        msg = formatter.format(RECORD)
        self.assertIn(LOG_LEVEL_ANSI_STYLES[RECORD.levelno].start, msg)
        self.assertIn("INFO ⸬ test record", msg)
        self.assertIn(LOG_LEVEL_ANSI_STYLES[RECORD.levelno].end, msg)

    def test_format_no_color(self):
        os.environ["NO_COLOR"] = "1"
        formatter = TTYFormatter()
        msg = formatter.format(RECORD)
        self.assertEqual("INFO ⸬ test record", msg)
        del os.environ["NO_COLOR"]

    def test_format_no_color_empty(self):
        os.environ["NO_COLOR"] = ""
        formatter = TTYFormatter()
        msg = formatter.format(RECORD)
        # When NO_COLOR environment variable is an empty string, colors are enabled.
        self.assertIn(LOG_LEVEL_ANSI_STYLES[RECORD.levelno].start, msg)
        del os.environ["NO_COLOR"]

    def test_format_debug(self):
        formatter = TTYFormatter(debug=True)
        msg = formatter.format(RECORD)
        self.assertIn(LOG_LEVEL_ANSI_STYLES[RECORD.levelno].start, msg)
        self.assertIn("[INFO]  ⸬rfl:0", msg)
        self.assertIn("↦ test record", msg)
        self.assertIn(LOG_LEVEL_ANSI_STYLES[RECORD.levelno].end, msg)

    def test_format_debug_no_color(self):
        os.environ["NO_COLOR"] = "1"
        formatter = TTYFormatter(debug=True)
        msg = formatter.format(RECORD)
        self.assertEqual("[INFO]  ⸬rfl:0                          ↦ test record", msg)
        del os.environ["NO_COLOR"]


class TestDaemonFormatter(unittest.TestCase):
    def test_format(self):
        formatter = DaemonFormatter()
        msg = formatter.format(RECORD)
        self.assertEqual(msg, "MainThread: [INFO] test record")

    def test_format_debug(self):
        formatter = DaemonFormatter(debug=True)
        msg = formatter.format(RECORD)
        self.assertEqual(msg, "MainThread: [INFO] rfl test record")
