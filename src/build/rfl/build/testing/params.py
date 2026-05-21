# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import functools
import inspect
import re


def _normalize_case(case):
    if isinstance(case, tuple):
        return case
    return (case,)


def _slugify_case(case):
    text = "_".join(str(item) for item in _normalize_case(case))
    slug = re.sub(r"[^0-9a-zA-Z]+", "_", text).strip("_").lower()
    return slug or "case"


def _expanded_test_name(name, index, case):
    slug = _slugify_case(case)
    return "{name}_{index:03d}_{slug}".format(name=name, index=index, slug=slug)


def _make_expanded_test(func, args):
    @functools.wraps(func)
    def expanded(self):
        return func(self, *args)

    return expanded


def expand(cases, name_func=None, skip_on_empty=False):
    """Build a decorator that turns one unittest method into several test methods.

    This is an alternative to the third-party parameterized library. Apply the returned
    decorator on a unittest.TestCase method, or assign it to a name and reuse it on
    multiple methods (for example http_verbs = expand(["get", "post"])).

    At class definition time, each entry in cases becomes a separate test method
    injected into the enclosing namespace. The template method is left in place but
    marked as non-runnable (__test__ = False), so unittest does not collect it.
    Expanded methods call the template with fixed positional arguments: a scalar case
    is passed as a single argument, a tuple is unpacked as positional arguments.

    Default names follow {method}_{index:03d}_{slug}, where slug is built from all
    case values (for example test_endpoint_001_get).

    cases is an iterable of parameter values, or a callable returning such an
    iterable. The callable form is evaluated once when the decorator is applied,
    which is useful when the list depends on runtime data (assets on disk, versions,
    and so on).

    name_func, when provided, is called as name_func(func, index, case) and must
    return the generated method name. index is the 1-based index of the case. When
    omitted, the default naming scheme described above is used.

    skip_on_empty, when true and cases is empty, marks the template method as
    non-runnable instead of raising ValueError. When false (the default), an empty
    cases iterable raises ValueError with a short hint about skip_on_empty.
    """

    def decorator(func):
        if callable(cases):
            parameters = list(cases())
        else:
            parameters = list(cases)

        if not parameters:
            if skip_on_empty:
                func.__test__ = False
                return
            raise ValueError(
                "Parameters iterable is empty (hint: use expand([], "
                "skip_on_empty=True) to skip this test when the input is empty)"
            )

        frame_locals = inspect.currentframe().f_back.f_locals

        for index, case in enumerate(parameters, start=1):
            args = _normalize_case(case)
            if name_func is not None:
                expanded_name = name_func(func, index, case)
            else:
                expanded_name = _expanded_test_name(func.__name__, index, case)
            frame_locals[expanded_name] = _make_expanded_test(func, args)

        func.__test__ = False

    return decorator
