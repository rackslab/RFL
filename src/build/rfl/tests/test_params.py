# Copyright (c) 2026 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: LGPL-3.0-or-later

import unittest

from rfl.build.testing.params import expand


class TestExpand(unittest.TestCase):
    def test_expand_scalar_cases(self):
        recorded = []

        class ExampleTest(unittest.TestCase):
            @expand(["alpha", "beta"])
            def test_value(self, value):
                recorded.append(value)

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 2)
        suite.run(unittest.TestResult())
        self.assertEqual(recorded, ["alpha", "beta"])
        self.assertIsNone(ExampleTest.__dict__.get("test_value"))

    def test_expand_tuple_cases(self):
        recorded = []

        class ExampleTest(unittest.TestCase):
            @expand([("1.0", "a"), ("2.0", "b")])
            def test_versions(self, version, variant):
                recorded.append((version, variant))

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 2)
        suite.run(unittest.TestResult())
        self.assertEqual(recorded, [("1.0", "a"), ("2.0", "b")])

    def test_expand_http_verbs(self):
        recorded = []

        class ExampleTest(unittest.TestCase):
            @expand(["get", "post"])
            def test_http_verb(self, verb):
                recorded.append(verb)

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 2)
        suite.run(unittest.TestResult())
        self.assertEqual(recorded, ["get", "post"])
        self.assertIn("test_http_verb_001_get", ExampleTest.__dict__)
        self.assertIn("test_http_verb_002_post", ExampleTest.__dict__)

    def test_expand_tuple_naming(self):
        class ExampleTest(unittest.TestCase):
            @expand([(1, "a"), (2, "b")])
            def test_tuple_args(self, number, label):
                pass

        self.assertIn("test_tuple_args_001_1_a", ExampleTest.__dict__)
        self.assertIn("test_tuple_args_002_2_b", ExampleTest.__dict__)

    def test_expand_callable_cases(self):
        recorded = []

        def cases():
            return ["x", "y"]

        class ExampleTest(unittest.TestCase):
            @expand(cases)
            def test_value(self, value):
                recorded.append(value)

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 2)
        suite.run(unittest.TestResult())
        self.assertEqual(recorded, ["x", "y"])

    def test_expand_shared_decorator(self):
        recorded = []
        http_verbs = expand(["get", "post"])

        class ExampleTest(unittest.TestCase):
            @http_verbs
            def test_first(self, verb):
                recorded.append(("first", verb))

            @http_verbs
            def test_second(self, verb):
                recorded.append(("second", verb))

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 4)
        suite.run(unittest.TestResult())
        self.assertEqual(
            recorded,
            [
                ("first", "get"),
                ("first", "post"),
                ("second", "get"),
                ("second", "post"),
            ],
        )

    def test_expand_empty_skip_on_empty(self):
        class ExampleTest(unittest.TestCase):
            @expand([], skip_on_empty=True)
            def test_value(self, value):
                raise AssertionError("should not run")

        suite = unittest.TestLoader().loadTestsFromTestCase(ExampleTest)
        self.assertEqual(suite.countTestCases(), 0)

    def test_expand_empty_raises(self):
        with self.assertRaises(ValueError):

            class ExampleTest(unittest.TestCase):
                @expand([])
                def test_value(self, value):
                    pass

    def test_expand_default_naming(self):
        class ExampleTest(unittest.TestCase):
            @expand(["alpha"])
            def test_value(self, value):
                pass

        self.assertIn("test_value_001_alpha", ExampleTest.__dict__)

    def test_expand_custom_name_func(self):
        class ExampleTest(unittest.TestCase):
            @expand(
                ["alpha"],
                name_func=lambda func, index, case: "{}_custom_{}".format(
                    func.__name__, case
                ),
            )
            def test_value(self, value):
                pass

        self.assertIn("test_value_custom_alpha", ExampleTest.__dict__)
