# Copyright (c) 2023 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import typing as t
import sys
import os
import logging


def auto_formatter():
    """Automatically select the most appropriate formatter class by checking if stdout
    is connected to a TTY."""
    if sys.stdout.isatty():
        return TTYFormatter
    else:
        return DaemonFormatter


class NOANSIStyle:
    def __init__(self):
        self.start = ""
        self.end = ""


class ANSIStyle:
    def __init__(self, fg, bg=None):
        self.fg = fg
        self.bg = bg

    @property
    def start(self):
        bg_s = ""
        if self.bg is not None:
            bg_s = f"\033[48;5;{self.bg}m"
        return bg_s + f"\033[38;5;{self.fg}m"

    @property
    def end(self):
        return "\033[0;0m"


LOG_LEVEL_ANSI_STYLES = {
    logging.CRITICAL: ANSIStyle(fg=15, bg=160),  # white on red
    logging.ERROR: ANSIStyle(fg=160),  # red
    logging.WARNING: ANSIStyle(fg=208),  # orange
    logging.INFO: ANSIStyle(fg=28),  # dark green
    logging.DEBUG: ANSIStyle(fg=62),  # light mauve
    logging.NOTSET: ANSIStyle(fg=8),  # grey
}


class TTYFormatter(logging.Formatter):
    def __init__(self, debug: bool = False, component: t.Optional[str] = None):
        super().__init__("%(message)s")
        self.debug = debug
        self.component = component
        self.colored = True
        if os.environ.get("NO_COLOR", ""):
            self.colored = False

    def format(self, record):
        _msg = record.getMessage()
        if self.colored:
            style = LOG_LEVEL_ANSI_STYLES[record.levelno]
        else:
            style = NOANSIStyle()
        prefix = ""
        if self.debug:
            prefix = "{level:8s}⸬{where:30s} ↦ ".format(
                level="[" + record.levelname + "]",
                where=record.name + ":" + str(record.lineno),
            )
        elif record.levelno >= logging.INFO:
            # prefix with level if over info
            prefix = "{level} ⸬ ".format(level=record.levelname)

        if self.component:
            prefix = f"❬{self.component:15}❭ {prefix}"

        return style.start + prefix + _msg + style.end


class DaemonFormatter(logging.Formatter):
    def __init__(self, debug: bool = False, component: t.Optional[str] = None):
        if debug:
            _fmt = "%(threadName)s: [%(levelname)s] %(name)s %(message)s"
        else:
            _fmt = "%(threadName)s: [%(levelname)s] %(message)s"
        if component:
            _fmt = f"❬{component}❭ {_fmt}"
        super().__init__(_fmt)
