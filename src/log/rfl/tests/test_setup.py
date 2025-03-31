# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import logging

from rfl.log import setup_logger, enforce_debug
from rfl.log.formatters import DaemonFormatter


class TestLogFilterer(unittest.TestCase):
    def assertLogRecordNotFiltered(self, handler, attrdict):
        record = logging.makeLogRecord(attrdict)
        try:
            self.assertTrue(handler.filter(record))
        except AssertionError:
            self.assertIsInstance(handler.filter(record), logging.LogRecord)

    def assertLogRecordFiltered(self, handler, attrdict):
        self.assertFalse(handler.filter(logging.makeLogRecord(attrdict)), False)


class TestSetupLogger(TestLogFilterer):
    def test_setup(self):
        setup_logger()
        # get root logger
        logger = logging.getLogger()
        # check root logger level
        self.assertEqual(logger.level, logging.INFO)
        # get stream handler and check its level
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.INFO)
        # check formatter
        self.assertIsInstance(handler.formatter, DaemonFormatter)
        # check custom filter
        self.assertEqual(len(handler.filters), 1)

    def test_setup_debug(self):
        setup_logger(debug=True)
        # get root logger
        logger = logging.getLogger()
        # check root logger level
        self.assertEqual(logger.level, logging.DEBUG)
        # get stream handler and check its level
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.DEBUG)

    def test_setup_filter(self):
        setup_logger(log_flags=["rfl"])
        # get root logger
        logger = logging.getLogger()
        # get stream handler
        handler = logger.handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )

    def test_setup_filter_debug_flags(self):
        setup_logger(debug=True, log_flags=["rfl"], debug_flags=["test"])
        # get root logger
        logger = logging.getLogger()
        # get stream handler
        handler = logger.handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "test.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )

    def test_setup_filter_debug_all(self):
        setup_logger(debug=True, log_flags=["ALL"], debug_flags=["ALL"])
        # get root logger
        logger = logging.getLogger()
        # get stream handler
        handler = logger.handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )


class TestEnforceLogger(TestLogFilterer):
    def setUp(self):
        setup_logger()

    def test_enforce_debug_flags(self):
        enforce_debug(log_flags=["rfl"], debug_flags=["test"])
        # get root logger
        logger = logging.getLogger()
        # get stream handler
        handler = logger.handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "test.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )

    def test_enforce_debug_all(self):
        enforce_debug(log_flags=["ALL"], debug_flags=["ALL"])
        # get root logger
        logger = logging.getLogger()
        # get stream handler
        handler = logger.handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
