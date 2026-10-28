# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

from typing import IO, Callable, List, Optional, Tuple, Union
import logging
import sys

from .formatters import TTYFormatter, DaemonFormatter, auto_formatter
from .pager import AutoPager, enable_auto_paging, PagerError

__all__ = [
    TTYFormatter,
    DaemonFormatter,
    auto_formatter,
    AutoPager,
    enable_auto_paging,
    PagerError,
]


class _BelowLevelFilter(logging.Filter):
    """Drop log records at or above a level.

    StreamHandler.setLevel only sets a floor, so the below-WARNING handler
    needs this to keep WARNING and above off that stream.
    """

    def __init__(self, level):
        super(_BelowLevelFilter, self).__init__()
        self.level = level

    def filter(self, record):
        return record.levelno < self.level


def _component_filter(log_flags, debug_flags):
    """Return a filter that keeps records enabled by component flags."""

    def custom_filter(record):
        component = record.name.split(".")[0]
        if record.levelno == logging.DEBUG:
            if "ALL" in debug_flags or component in debug_flags:
                return 1
            return 0
        if "ALL" in log_flags or component in log_flags:
            return 1
        return 0

    return custom_filter


def _add_stream_handler(
    root_logger: logging.Logger,
    stream: Optional[IO],
    level: int,
    formatter: logging.Formatter,
    component_filter: Callable[[logging.LogRecord], int],
    extra_filters: Tuple[logging.Filter, ...] = (),
) -> logging.StreamHandler:
    """Attach one stream handler. stream=None selects stderr."""
    handler = logging.StreamHandler(stream)
    handler.setLevel(level)
    handler.setFormatter(formatter)
    handler.addFilter(component_filter)
    for extra_filter in extra_filters:
        handler.addFilter(extra_filter)
    root_logger.addHandler(handler)
    return handler


def setup_logger(
    debug: bool = False,
    level: Optional[Union[int, str]] = None,
    log_flags: Optional[List[str]] = None,
    debug_flags: Optional[List[str]] = None,
    formatter: logging.Formatter = auto_formatter(),
    component: Optional[str] = None,
    clear: bool = True,
    stream: Optional[IO] = None,
    error_stream: Optional[IO] = None,
) -> None:
    """Setup root logger level, debug flags and formatter.

    Log level is resolved in this order: explicit level argument, then
    debug=True (DEBUG), otherwise INFO. The debug flag also controls
    formatter verbosity, independent of the resolved log level.

    When clear is True (default), existing root logger handlers are removed
    before adding a new one, similarly to logging.basicConfig(force=True).

    By default, one handler writes every accepted record to stderr, or to
    stream when that argument is set. When error_stream is set, records
    below WARNING go to stream (stdout if stream is omitted) and WARNING and
    above go to error_stream. The error handler level is at least WARNING
    and at least the resolved level.
    """
    if level is not None:
        if isinstance(level, str):
            logging_level = getattr(logging, level.upper(), None)
            if not isinstance(logging_level, int):
                raise ValueError(f"Unknown log level: {level}")
        elif isinstance(level, int):
            logging_level = level
        else:
            raise TypeError(f"Unsupported log level type: {type(level).__name__}")
    elif debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    if log_flags is None:
        log_flags = []
    if debug_flags is None:
        debug_flags = []

    root_logger = logging.getLogger()
    if clear:
        for existing_handler in root_logger.handlers[:]:
            root_logger.removeHandler(existing_handler)
            existing_handler.close()
    root_logger.setLevel(logging_level)
    formatter = formatter(debug, component)
    component_filter = _component_filter(log_flags, debug_flags)

    # No split: one handler receives every accepted level on stream, or stderr
    # when stream is omitted.
    if error_stream is None:
        _add_stream_handler(
            root_logger, stream, logging_level, formatter, component_filter
        )
        return

    # Split streams: records below WARNING go to stream (stdout when omitted)
    # and WARNING and above go to error_stream. setLevel only sets a floor, so
    # the filter drops WARNING and above from this handler.
    info_stream = sys.stdout if stream is None else stream
    _add_stream_handler(
        root_logger,
        info_stream,
        logging_level,
        formatter,
        component_filter,
        extra_filters=(_BelowLevelFilter(logging.WARNING),),
    )
    _add_stream_handler(
        root_logger,
        error_stream,
        max(logging_level, logging.WARNING),
        formatter,
        component_filter,
    )


def enforce_debug(
    log_flags: Optional[List[str]] = None,
    debug_flags: Optional[List[str]] = None,
) -> None:
    """Enforce root logger debug level and debug flags.

    Handlers at INFO are lowered to DEBUG. Handlers at any other level stay
    as they are, so an error stream at WARNING or above keeps the split.
    """
    root_logger = logging.getLogger()
    root_logger.setLevel(level=logging.DEBUG)

    if log_flags is None:
        log_flags = []
    if debug_flags is None:
        debug_flags = []

    component_filter = _component_filter(log_flags, debug_flags)

    # Replace the component filter and keep the below-WARNING filter. Only
    # INFO handlers are lowered to DEBUG; a WARNING error stream stays put.
    for handler in root_logger.handlers:
        if handler.level == logging.INFO:
            handler.setLevel(logging.DEBUG)
        handler.formatter.debug = True
        preserved = [
            existing
            for existing in handler.filters
            if isinstance(existing, _BelowLevelFilter)
        ]
        for existing in handler.filters[:]:
            handler.removeFilter(existing)
        handler.addFilter(component_filter)
        for existing in preserved:
            handler.addFilter(existing)
