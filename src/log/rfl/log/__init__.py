# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

from typing import List
import logging

from .formatters import TTYFormatter, DaemonFormatter, auto_formatter

__all__ = [TTYFormatter, DaemonFormatter, auto_formatter]


def setup_logger(
    debug: bool = False,
    flags: List[str] = [],
    formatter: logging.Formatter = auto_formatter(),
) -> None:
    if debug:
        logging_level = logging.DEBUG
    else:
        logging_level = logging.INFO

    root_logger = logging.getLogger()
    root_logger.setLevel(logging_level)
    handler = logging.StreamHandler()
    handler.setLevel(logging_level)
    formatter = formatter(debug)
    handler.setFormatter(formatter)
    # filter out all libs logs not enabled in flags
    def custom_filter(record):
        if "ALL" in flags:
            return 1
        if record.name.split(".")[0] not in flags:
            return 0
        return 1

    handler.addFilter(custom_filter)
    root_logger.addHandler(handler)
