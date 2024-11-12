# Copyright (c) 2024 Rackslab
#
# This file is part of RFL.
#
# SPDX-License-Identifier: GPL-3.0-or-later

import unittest
import asyncio

from rfl.core.asyncio import asyncio_run


async def async_success():
    pass


async def async_fail():
    raise RuntimeError("fail")


async def async_sleep():
    await asyncio.sleep(0.5)


async def multiple_sleeps():
    async_sleep()
    async_sleep()
    async_sleep()


class TestAsyncIO(unittest.TestCase):
    def test_run_success(self):
        asyncio_run(async_success())

    def test_run_failure(self):
        with self.assertRaisesRegex(RuntimeError, "^fail$"):
            asyncio_run(async_fail())

    def test_run_sleep(self):
        asyncio_run(multiple_sleeps())
