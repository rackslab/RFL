# RFL: log package

Logging utility.

## setup_logger()

Configure the root logger with a stream handler, formatter, and per-component
filtering.

### Basic usage

```python
import logging
from rfl.log import setup_logger

setup_logger()                          # INFO level (default)
setup_logger(debug=True)                # DEBUG level
setup_logger(level=logging.WARNING)     # WARNING and above
setup_logger(level="ERROR")             # string level names also accepted
```

### Log level

Level is resolved in this order:

1. `level` argument (int constant or string name: `DEBUG`, `INFO`, `WARNING`,
   `ERROR`, `CRITICAL`)
2. `debug=True` → `DEBUG` (when `level` is omitted)
3. default → `INFO`

The `debug` flag also controls formatter verbosity (detailed prefixes), independent
of the resolved log level.

### Component filtering

By default, only log records from components listed in `log_flags` are shown for
INFO and above. DEBUG records require `debug_flags`.

```python
setup_logger(log_flags=["rfl"])                    # INFO+ from rfl only
setup_logger(debug=True, debug_flags=["network"])  # DEBUG from network only
setup_logger(log_flags=["ALL"], debug_flags=["ALL"])  # show everything
```

Component names are derived from the first segment of the logger name
(e.g. `rfl.pkg.module` → `rfl`).

### Other options

- `component`: prefix log lines with a fixed component label in the formatter
- `formatter`: formatter class factory (default: TTY or daemon auto-selection)
- `clear`: when `True` (default), remove existing root handlers before setup;
  set `clear=False` to stack handlers
