# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import io
import sys
import unittest
import logging

from rfl.log import setup_logger, enforce_debug, component_flag_filter
from rfl.log.formatters import DaemonFormatter


class TestLogFilterer(unittest.TestCase):
    def assertLogRecordNotFiltered(self, handler, attrdict):
        record = logging.makeLogRecord(attrdict)
        self.assertGreaterEqual(record.levelno, handler.level)
        try:
            self.assertTrue(handler.filter(record))
        except AssertionError:
            self.assertIsInstance(handler.filter(record), logging.LogRecord)

    def assertLogRecordFiltered(self, handler, attrdict):
        record = logging.makeLogRecord(attrdict)
        if record.levelno < handler.level:
            return
        self.assertFalse(handler.filter(record), False)


class TestComponentFlagFilter(TestLogFilterer):
    def _handler(self, log_flags=None, debug_flags=None):
        handler = logging.StreamHandler(io.StringIO())
        handler.addFilter(component_flag_filter(log_flags, debug_flags))
        return handler

    def test_none_defaults_drop_records(self):
        handler = self._handler()
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )

    def test_log_flags_component(self):
        handler = self._handler(log_flags=["rfl"])
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "fail.pkg", "levelno": logging.WARNING, "msg": "test"}
        )

    def test_debug_flags_component(self):
        handler = self._handler(debug_flags=["test"])
        self.assertLogRecordNotFiltered(
            handler, {"name": "test.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "test.pkg", "levelno": logging.INFO, "msg": "test"}
        )

    def test_all_keeps_every_component(self):
        handler = self._handler(log_flags=["ALL"], debug_flags=["ALL"])
        for name in ("rfl.pkg", "fail.pkg"):
            for level in (logging.DEBUG, logging.INFO, logging.WARNING):
                self.assertLogRecordNotFiltered(
                    handler, {"name": name, "levelno": level, "msg": "test"}
                )

    def test_dotted_name_matches_first_segment_only(self):
        handler = self._handler(log_flags=["rfl"], debug_flags=["rfl"])
        self.assertLogRecordNotFiltered(
            handler,
            {"name": "rfl.pkg.module", "levelno": logging.INFO, "msg": "test"},
        )
        self.assertLogRecordNotFiltered(
            handler,
            {"name": "rfl.pkg.module", "levelno": logging.DEBUG, "msg": "test"},
        )
        self.assertLogRecordFiltered(
            handler, {"name": "other.rfl", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "pkg.rfl", "levelno": logging.DEBUG, "msg": "test"}
        )


class TestSetupLogger(TestLogFilterer):
    def test_setup(self):
        setup_logger()
        # get root logger
        logger = logging.getLogger()
        # check root logger level
        self.assertEqual(logger.level, logging.INFO)
        # get stream handler and check its level
        handler = logger.handlers[-1]
        self.assertEqual(len(logger.handlers), 1)
        self.assertIs(handler.stream, sys.stderr)
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

    def test_setup_warning(self):
        setup_logger(level=logging.WARNING)
        logger = logging.getLogger()
        self.assertEqual(logger.level, logging.WARNING)
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.WARNING)

    def test_setup_error(self):
        setup_logger(level=logging.ERROR)
        logger = logging.getLogger()
        self.assertEqual(logger.level, logging.ERROR)
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.ERROR)

    def test_setup_level_string(self):
        setup_logger(level="WARNING")
        logger = logging.getLogger()
        self.assertEqual(logger.level, logging.WARNING)
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.WARNING)

    def test_setup_level_overrides_debug(self):
        setup_logger(level=logging.WARNING, debug=True)
        logger = logging.getLogger()
        self.assertEqual(logger.level, logging.WARNING)
        handler = logger.handlers[-1]
        self.assertEqual(handler.level, logging.WARNING)

    def test_setup_invalid_level(self):
        with self.assertRaisesRegex(ValueError, r"Unknown log level: NOTALEVEL"):
            setup_logger(level="NOTALEVEL")

    def test_setup_invalid_level_type(self):
        with self.assertRaisesRegex(TypeError, r"Unsupported log level type: float"):
            setup_logger(level=1.5)

    def test_setup_applies_component_filter(self):
        setup_logger(debug=True, log_flags=["rfl"], debug_flags=["test"])
        handler = logging.getLogger().handlers[-1]
        self.assertLogRecordNotFiltered(
            handler, {"name": "rfl.pkg", "levelno": logging.INFO, "msg": "test"}
        )
        self.assertLogRecordNotFiltered(
            handler, {"name": "test.pkg", "levelno": logging.DEBUG, "msg": "test"}
        )
        self.assertLogRecordFiltered(
            handler, {"name": "other.pkg", "levelno": logging.INFO, "msg": "test"}
        )

    def test_setup_clears_handlers(self):
        setup_logger()
        setup_logger()
        logger = logging.getLogger()
        self.assertEqual(len(logger.handlers), 1)

    def test_setup_clear_false_stacks_handlers(self):
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
            handler.close()
        setup_logger(clear=False)
        setup_logger(clear=False)
        self.assertEqual(len(root_logger.handlers), 2)

    def test_setup_custom_stream_is_not_split(self):
        buf = io.StringIO()
        setup_logger(log_flags=["ALL"], stream=buf)
        logger = logging.getLogger()
        self.assertEqual(len(logger.handlers), 1)
        self.assertIs(logger.handlers[-1].stream, buf)
        logging.getLogger("rfl.pkg").info("info-line")
        logging.getLogger("rfl.pkg").warning("warn-line")
        text = buf.getvalue()
        self.assertIn("info-line", text)
        self.assertIn("warn-line", text)

    def test_split_defaults_info_stream_to_stdout(self):
        err = io.StringIO()
        setup_logger(error_stream=err)
        handlers = logging.getLogger().handlers
        self.assertEqual(len(handlers), 2)
        self.assertIs(handlers[0].stream, sys.stdout)
        self.assertIs(handlers[1].stream, err)
        self.assertIs(handlers[0].formatter, handlers[1].formatter)
        self.assertEqual(handlers[0].level, logging.INFO)
        self.assertEqual(handlers[1].level, logging.WARNING)

    def test_split_routes_by_level(self):
        setup_logger(
            debug=True,
            log_flags=["ALL"],
            debug_flags=["ALL"],
            stream=io.StringIO(),
            error_stream=io.StringIO(),
        )
        info_handler, error_handler = logging.getLogger().handlers
        for level in (logging.DEBUG, logging.INFO):
            record = {"name": "rfl.pkg", "levelno": level, "msg": "test"}
            self.assertLogRecordNotFiltered(info_handler, record)
            self.assertLogRecordFiltered(error_handler, record)
        for level in (logging.WARNING, logging.ERROR, logging.CRITICAL):
            record = {"name": "rfl.pkg", "levelno": level, "msg": "test"}
            self.assertLogRecordFiltered(info_handler, record)
            self.assertLogRecordNotFiltered(error_handler, record)


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

    def test_enforce_debug_preserves_split(self):
        setup_logger(
            log_flags=["ALL"], stream=io.StringIO(), error_stream=io.StringIO()
        )
        enforce_debug(log_flags=["ALL"], debug_flags=["ALL"])
        info_handler, error_handler = logging.getLogger().handlers
        self.assertEqual(info_handler.level, logging.DEBUG)
        self.assertEqual(error_handler.level, logging.WARNING)
        debug_record = {"name": "rfl.pkg", "levelno": logging.DEBUG, "msg": "test"}
        warning_record = {"name": "rfl.pkg", "levelno": logging.WARNING, "msg": "test"}
        self.assertLogRecordNotFiltered(info_handler, debug_record)
        self.assertLogRecordFiltered(error_handler, debug_record)
        self.assertLogRecordFiltered(info_handler, warning_record)
        self.assertLogRecordNotFiltered(error_handler, warning_record)

    def test_enforce_debug_leaves_non_info_handler(self):
        buf = io.StringIO()
        setup_logger(level=logging.WARNING, log_flags=["ALL"], stream=buf)
        enforce_debug(log_flags=["ALL"], debug_flags=["ALL"])
        handler = logging.getLogger().handlers[-1]
        self.assertEqual(handler.level, logging.WARNING)
        logging.getLogger("rfl.pkg").info("info-line")
        logging.getLogger("rfl.pkg").warning("warn-line")
        text = buf.getvalue()
        self.assertNotIn("info-line", text)
        self.assertIn("warn-line", text)
