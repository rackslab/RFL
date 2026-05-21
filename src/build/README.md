# RFL: build package

Utilities to help backport builds of Python projects.

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
