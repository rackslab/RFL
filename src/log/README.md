# RFL: log package

Logging utility.

## setup_logger()

Configure the root logger with one or two stream handlers, a formatter, and
per-component filtering.

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

### Streams

By default, one handler writes every accepted record to stderr. Pass `stream`
to send that single handler somewhere else. Every accepted level still goes to
that stream.

```python
import sys

setup_logger(stream=sys.stdout)        # single handler on stdout
setup_logger(error_stream=sys.stderr)  # below WARNING → stdout, WARNING+ → stderr
```

When `error_stream` is set, records below WARNING go to `stream` (`sys.stdout`
when `stream` is omitted) and WARNING and above go to `error_stream`. The error
handler level is at least WARNING, and at least the configured level, so a
level of ERROR still suppresses WARNING. Both handlers share the formatter and
the component filters.

### Other options

- `component`: prefix log lines with a fixed component label in the formatter
- `formatter`: formatter class factory (default: TTY or daemon auto-selection)
- `clear`: when `True` (default), remove existing root handlers before setup;
  set `clear=False` to stack handlers

## component_flag_filter()

Build the same component allow-list used by `setup_logger()` and
`enforce_debug()`, and attach it to a handler those functions do not create
(an OTLP bridge, an extra stream, and so on).

```python
import logging
from rfl.log import component_flag_filter

handler = logging.StreamHandler()
handler.addFilter(component_flag_filter(log_flags=["rfl"], debug_flags=["rfl"]))
logging.getLogger().addHandler(handler)
```

`log_flags` selects components for INFO and above. `debug_flags` selects
components for DEBUG only. `"ALL"` matches every component. Omit either list
(or pass `None`) to drop records at that level. The component is the first
segment of the logger name (`rfl.pkg.module` → `rfl`). The filter returns `1`
to keep a record and `0` to drop it.
