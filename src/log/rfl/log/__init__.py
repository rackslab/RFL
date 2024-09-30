# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import Optional, List
import logging

from .formatters import TTYFormatter, DaemonFormatter, auto_formatter

__all__ = [TTYFormatter, DaemonFormatter, auto_formatter]


def setup_logger(
    debug: bool = False,
    log_flags: Optional[List[str]] = None,
    debug_flags: Optional[List[str]] = None,
    formatter: logging.Formatter = auto_formatter(),
) -> None:
    """Setup root logger debug level, debug flags and formatter."""
    if debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    if log_flags is None:
        log_flags = []
    if debug_flags is None:
        debug_flags = []

    root_logger = logging.getLogger()
    root_logger.setLevel(logging_level)
    handler = logging.StreamHandler()
    handler.setLevel(logging_level)
    formatter = formatter(debug)
    handler.setFormatter(formatter)

    # filter out all libs logs not enabled in flags
    def custom_filter(record):
        component = record.name.split(".")[0]
        if record.levelno == logging.DEBUG:
            if "ALL" in debug_flags or component in debug_flags:
                return 1
            return 0
        if "ALL" in log_flags or component in log_flags:
            return 1
        return 0

    handler.addFilter(custom_filter)
    root_logger.addHandler(handler)


def enforce_debug(
    log_flags: Optional[List[str]] = None,
    debug_flags: Optional[List[str]] = None,
) -> None:
    """Enforce root logger debug level and debug flags."""
    root_logger = logging.getLogger()
    root_logger.setLevel(level=logging.DEBUG)

    if log_flags is None:
        log_flags = []
    if debug_flags is None:
        debug_flags = []

    # filter out all libs logs not enabled in flags
    def custom_filter(record):
        component = record.name.split(".")[0]
        if record.levelno == logging.DEBUG:
            if "ALL" in debug_flags or component in debug_flags:
                return 1
            return 0
        if "ALL" in log_flags or component in log_flags:
            return 1
        return 0

    # For all handlers, set log level, enable debug in formatter and replace filter.
    for handler in root_logger.handlers:
        handler.setLevel(logging.DEBUG)
        handler.formatter.debug = True
        for filter in handler.filters:
            handler.removeFilter(filter)
            handler.addFilter(custom_filter)
