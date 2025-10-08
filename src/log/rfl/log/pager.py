# Copyright (c) 2025 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import os
import sys
import subprocess
import shutil
import typing as t
import logging
import atexit

from rfl.core.errors import RFLError


class PagerError(RFLError):
    """Exception raised when pager operations fail."""

    pass


class AutoPager:
    """
    Auto-paging utility that redirects all program output (stdout/stderr) to a pager.

    This class provides automatic paging functionality for all program outputs,
    including both logging and non-logging output. It automatically detects
    the best available pager and handles terminal capabilities.
    """

    def __init__(
        self,
        pager: t.Optional[str] = None,
        auto_detect: bool = True,
        fallback_to_cat: bool = True,
    ):
        """
        Initialize the pager.

        Args:
            pager: Specific pager command to use (e.g., 'less', 'more', 'cat')
            auto_detect: Whether to automatically detect the best available pager
            fallback_to_cat: Whether to fallback to 'cat' if no pager is found
        """
        self.pager = pager
        self.auto_detect = auto_detect
        self.fallback_to_cat = fallback_to_cat
        self._original_stdout = None
        self._original_stderr = None
        self._pager_process = None
        self._pipe_read = None
        self._pipe_write = None
        self._logging_handlers_original_streams = []

    def _detect_pager(self) -> str:
        """
        Detect the best available pager for the current environment.

        Returns:
            The pager command to use

        Raises:
            PagerError: If no suitable pager is found
        """
        # Check if a specific pager was requested
        if self.pager:
            if shutil.which(self.pager):
                return self.pager
            else:
                raise PagerError(f"Requested pager '{self.pager}' not found")

        # Check environment variables
        env_pager = os.environ.get("PAGER")
        if env_pager and shutil.which(env_pager):
            return env_pager

        # Check common pagers in order of preference
        preferred_pagers = ["pager", "less", "more", "most", "pg"]
        for pager in preferred_pagers:
            if shutil.which(pager):
                return pager

        # Fallback to cat if enabled
        if self.fallback_to_cat and shutil.which("cat"):
            return "cat"

        raise PagerError("No suitable pager found")

    def _is_tty(self) -> bool:
        """Check if stdout is connected to a TTY."""
        return sys.stdout.isatty()

    def _should_page(self) -> bool:
        """
        Determine if output should be paged.

        Returns:
            True if output should be paged, False otherwise
        """
        # Don't page if not a TTY
        if not self._is_tty():
            return False

        # Don't page if explicitly disabled
        if os.environ.get("NO_PAGER"):
            return False

        return True

    def start(self) -> None:
        """
        Start the pager and redirect stdout/stderr to it.

        Raises:
            PagerError: If pager cannot be started
        """
        if not self._should_page():
            return

        try:
            pager_cmd = self._detect_pager()
        except PagerError:
            # If no pager is available, continue without paging
            return

        # Store original streams
        self._original_stdout = sys.stdout
        self._original_stderr = sys.stderr

        # Create anonymous pipe
        self._pipe_read, self._pipe_write = os.pipe()

        # Prepare environment for pager with enhanced settings
        pager_env = os.environ.copy()
        # Selected environment variables for better user experience:
        #   LESS:
        #   - F: quit if less than one screen
        #   - R: interpret raw control chars (eg. ANSI colors)
        #   - X: disable termcap init/deinit
        #   MORE:
        #   - F: quit if less than one screen
        #   - R: interpret raw control chars (eg. ANSI colors)
        #   - X: disable termcap init/deinit
        #   LV:
        #   - C: color mode
        pager_env.update({"LESS": "FRX", "MORE": "FRX", "LV": "C"})

        # Start pager process
        self._pager_process = subprocess.Popen(
            [pager_cmd],
            stdin=self._pipe_read,
            stdout=self._original_stdout,
            stderr=self._original_stderr,
            text=True,
            env=pager_env,
        )

        # Close the read end in parent process
        os.close(self._pipe_read)
        self._pipe_read = None

        # Redirect stdout and stderr to the write end of the pipe
        # Use line buffering to ensure short-lived outputs are flushed promptly
        sys.stdout = os.fdopen(self._pipe_write, "w", buffering=1)
        sys.stderr = sys.stdout

        # Redirect logging handlers that were writing to the original streams
        self._redirect_logging_handlers()

        # Ensure pager is stopped and output flushed on interpreter exit
        atexit.register(self.stop)

    def stop(self) -> None:
        """
        Stop the pager and restore original stdout/stderr.
        """
        # If paging was started (original streams saved), we must restore and flush
        if self._original_stdout is None:
            return

        # Close the write end of the pipe to signal EOF to pager
        if sys.stdout != self._original_stdout:
            sys.stdout.close()

        # Restore original streams
        sys.stdout = self._original_stdout
        sys.stderr = self._original_stderr

        # Restore logging handler streams
        self._restore_logging_handlers()

        # Wait for pager process to complete
        if self._pager_process:
            try:
                self._pager_process.wait()
            except Exception as e:
                raise PagerError(f"Failed to wait for pager process: {e}")

        # Clean up pipe write end if still open
        if self._pipe_write is not None:
            try:
                os.close(self._pipe_write)
            except OSError:
                pass  # Already closed

    def _redirect_logging_handlers(self) -> None:
        """Redirect handlers targeting original std streams to the pager pipe.

        Stores original handler streams for later restoration.
        """
        self._logging_handlers_original_streams = []
        try:
            root_logger = logging.getLogger()
            for handler in getattr(root_logger, "handlers", []):
                handler_stream = getattr(handler, "stream", None)
                if handler_stream in (
                    self._original_stdout,
                    self._original_stderr,
                ):
                    self._logging_handlers_original_streams.append(
                        (handler, handler_stream)
                    )
                    handler.stream = sys.stdout
        except Exception:
            # Logging configuration may be unusual; fail safe and continue
            self._logging_handlers_original_streams = []

    def _restore_logging_handlers(self) -> None:
        """Restore logging handler streams saved during redirection."""
        for handler, original_stream in self._logging_handlers_original_streams:
            try:
                handler.stream = original_stream
            except Exception:
                # Best-effort restoration
                pass
        self._logging_handlers_original_streams = []

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()

    def __del__(self):
        """Cleanup on destruction."""
        if self._pipe_write is not None:
            try:
                os.close(self._pipe_write)
            except OSError:
                pass  # Already closed
        if self._pager_process and self._pager_process.poll() is None:
            try:
                self._pager_process.terminate()
            except OSError:
                pass  # Process already terminated


def enable_auto_paging(
    pager: t.Optional[str] = None,
    auto_detect: bool = True,
    fallback_to_cat: bool = True,
) -> AutoPager:
    """
    Enable auto-paging for the current program.

    This function starts paging immediately and returns a AutoPager instance
    that should be stopped when paging is no longer needed.

    Args:
        pager: Specific pager command to use
        auto_detect: Whether to automatically detect the best available pager
        fallback_to_cat: Whether to fallback to 'cat' if no pager is found

    Returns:
        AutoPager instance that can be used to stop paging

    Example:
        >>> from rfl.log import enable_auto_paging
        >>> pager = enable_auto_paging()
        >>> print("This will be paged")
        >>> pager.stop()
    """
    pager_instance = AutoPager(
        pager=pager, auto_detect=auto_detect, fallback_to_cat=fallback_to_cat
    )
    pager_instance.start()
    return pager_instance
