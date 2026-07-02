# RFL: build package

Utilities to help backport builds of Python projects.

## PEP 517 setup converter

Some platforms ship `pip` and `setuptools` without full [PEP 517](https://peps.python.org/pep-0517/)
support — they cannot build a package by invoking the `[build-system]` backend declared in
`pyproject.toml` (for example Python 3.6 on Rocky Linux 8, Ubuntu Jammy, or openSUSE Leap
15). The setup converter is a small `setup.py` shim that reads `pyproject.toml` from the
current working directory and calls `setuptools.setup()` with mapped parameters.

The script is shipped as package data in `rfl.build.scripts` and is meant to be copied
next to `pyproject.toml` as `setup.py` before running legacy `pip install`.

### Usage

Copy the converter into a package tree with `pyproject.toml`:

```bash
rfl-install-setup-generator
```

This writes `./setup.py` in the current working directory.

When installing RFL from source, `install.sh` can copy the converter into every package
under `src/` automatically:

```bash
PEP517_SETUP_WRAPPER=1 bash install.sh
```

### Supported `pyproject.toml` fields

The converter maps a subset of modern metadata to `setuptools.setup()` keyword
arguments:

| Source | `setup()` argument |
|--------|-------------------|
| `[project]` `name`, `version` | `name`, `version` |
| `[project]` `authors[0]` | `author`, `author_email` |
| `[project]` `scripts` | `entry_points["console_scripts"]` |
| `[project]` `dependencies` | `install_requires` |
| `[project]` `optional-dependencies` | `extras_require` |
| `[project]` `license.text` | `license` |
| `[project]` `license.file` | `license_files` |
| `[project.urls]` `Homepage` | `url` |
| `[tool.setuptools]` `packages` (explicit list) | `packages` |
| `[tool.setuptools.packages.find]` `include` | `packages` (namespace detection; filtered discovery only when `where != "."`) |
| `[tool.setuptools.packages.find]` `where` | `packages` via `find_packages(where=…)` when not `"."`; sets `package_dir={"": where}` |
| `[tool.setuptools.packages.find]` `exclude` | passed to `find_packages(exclude=…)` when `where != "."` |
| `[tool.setuptools]` `package-data` | `package_data`, `include_package_data=True` |
| `[tool.setuptools]` `data-files` | `data_files` (with glob expansion) |

`platforms` is always set to `["GNU/Linux"]`.

The `[tool.setuptools]` section is optional. If `[project]` is missing, the script
prints a message and exits with code 0.

### Package discovery

`[tool.setuptools.packages.find]` supports `where`, `include`, and `exclude`:

- `where` (default `["."]`): directory searched for packages. Use `where = ["src"]`
  for src-layout projects without an explicit `include`.
- `include` (default `["*"]`): on flat layout (`where` is `"."`), used only for
  namespace detection (see below), not passed to `find_packages()`. On src layout,
  glob patterns are passed to `find_packages(include=…)`.
- `exclude` (default `[]`): passed to `find_packages(exclude=…)` on src layout only.
- When `where` is not `"."`, the converter also sets `package_dir = {"": where}` so
  setuptools 39 can locate packages under `src/` (PEP 517 backends infer this
  automatically; the shim must set it explicitly).
- Only the first `where` entry is used when multiple directories are listed.

When `include` patterns contain a dot (for example `rfl.build*`), entries without a
dot are ignored. For each dotted pattern, the converter inspects the top-level
directory under `where` (the part before the first dot). If that directory has no
`__init__.py`, it is treated as a native namespace package. In that case, wildcard
characters are stripped from include patterns and the resulting names are passed
explicitly to `setup()` — `find_packages()` is not used.

If every inspected top-level directory contains an `__init__.py`, `find_packages()`
is used. On flat layout it is called without filters (legacy behaviour). On src
layout it is called with the configured `where`, `include`, and `exclude` values.

This workaround exists because `find_namespace_packages()` requires setuptools ≥
40.1.0 and is unavailable on Rocky Linux 8 (setuptools 39.2.0).

### Data files

`[tool.setuptools.data-files]` maps install destinations to source path lists.
Glob patterns (`*`, `?`, `[…]`) are expanded relative to the project root before
calling `setup()`. Setuptools 39 does not expand globs in `data_files` natively;
the converter mirrors modern PEP 517 behaviour.

Example:

```toml
[tool.setuptools.data-files]
"myapp/conf" = ["conf/app.yml", "conf/app.ini.example"]
"myapp/templates" = ["web/templates/*"]
```

### Limits

The converter is intentionally minimal. It does **not** map many common
`pyproject.toml` fields, including:

- `description`, `readme`, `requires-python`, `keywords`, `classifiers`
- license metadata as a plain SPDX string (only `license.text` and `license.file`
  tables are handled explicitly)
- project URLs other than `Homepage`
- entry points other than `[project.scripts]` console scripts
- dynamic metadata, `pyproject.toml` `[build-system]` options, and most
  `[tool.setuptools]` directives beyond packages, package data, and data files
- `[tool.setuptools]` `package-dir` as an explicit pyproject key (only inferred from
  `where`)

Only the first `[project]` author entry is used.

The script must be executed from the directory that contains `pyproject.toml`. It
requires `tomllib` (Python 3.11+) or the `tomli` package on older Python versions.

On modern toolchains with full PEP 517 support, prefer building directly from
`pyproject.toml` and do not copy this shim.

## `rfl.build.testing` subpackage

The `rfl.build.testing` subpackage provides reusable helpers for writing unit tests in
downstream projects. It is installable library code shipped with `RFL.build`.

This is distinct from `rfl.tests` under `src/build/rfl/tests/`, which contains unit
tests for the build package itself.

## Unittest parameterization (`rfl.build.testing.params`)

The `params` module provides the `expand` decorator to run the same test logic with
multiple argument sets, as a maintained alternative to the unmaintained third-party
[`parameterized`](https://pypi.org/project/parameterized/) library.

Import:

```python
from rfl.build.testing.params import expand
```

Apply `expand` on a test method with a case list. Each case is passed as positional
arguments to the method (a scalar is wrapped in a one-tuple):

```python
import unittest

from rfl.build.testing.params import expand


class TestValues(unittest.TestCase):
    @expand([1, 2, 3])
    def test_is_positive(self, value):
        self.assertGreater(value, 0)
```

`cases` may be an iterable or a callable returning an iterable. At decoration time,
`expand` injects one test method per case into the enclosing namespace. The template
method is not collected by unittest (`__test__` is set to `False` and the binding is
not kept).

Generated names follow `{method}_{index:03d}_{slug}`, where `slug` is derived from all
case values (for example `test_is_positive_001_1` and `test_is_positive_002_2`).

Options:

- `name_func(func, index, case)` — return the generated method name. `index` is the
  1-based case index.
- `skip_on_empty=True` — when `cases` is empty, mark the template as non-runnable
  instead of raising `ValueError`.

Example with multiple argument tuples:

```python
class TestApi(unittest.TestCase):
    @expand([("1.0", "a"), ("2.0", "b")])
    def test_response(self, version, variant):
        ...
```

The result of `expand(cases)` is itself a decorator and may be assigned to a name to
reuse the same case list on several test methods (similar to `parameterized.expand`):

```python
http_verbs = expand(["get", "post"])


class TestHttpMethods(unittest.TestCase):
    @http_verbs
    def test_endpoint(self, verb):
        response = self.client.open("/resource", method=verb)
        self.assertEqual(response.status_code, 200)
```

A callable case source works the same way when building a shared decorator:

```python
def version_combinations():
    return [("1.0", "a"), ("2.0", "b")]


all_versions = expand(version_combinations)


class TestApi(unittest.TestCase):
    @all_versions
    def test_response(self, version, variant):
        ...
```
