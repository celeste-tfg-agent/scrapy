"""Regression tests for issue #16: process_spider_exception() must be
invoked exactly once per exception raised by a spider callback, even when
the callback (a generator) yielded output before raising, and the chain
contains a process_spider_output-defining middleware positioned before
the process_spider_exception-defining one.
"""

from __future__ import annotations

import asyncio
from typing import Any

from scrapy.core.spidermw import SpiderMiddlewareManager
from scrapy.http import Request, Response
from scrapy.spiders import Spider
from scrapy.utils.asyncgen import collect_asyncgen
from scrapy.utils.misc import build_from_crawler
from scrapy.utils.test import get_crawler


def _build_manager() -> SpiderMiddlewareManager:
    crawler = get_crawler(Spider, {"SPIDER_MIDDLEWARES_BASE": {}})
    crawler.spider = crawler._create_spider("foo")
    return build_from_crawler(SpiderMiddlewareManager, crawler)


class PassthroughOutputMiddleware:
    """A middleware that only defines process_spider_output(); it does not
    handle any exception itself, it just forwards items along.
    """

    async def process_spider_output(
        self, response: Response, result: Any
    ) -> Any:
        async for r in result:
            yield r


class RecordExceptionMiddleware:
    """A middleware that only defines process_spider_exception(); it
    records every exception it is offered and never handles any of them
    (it always returns None, meaning "I didn't handle it, keep looking").
    """

    def __init__(self) -> None:
        self.calls: list[Exception] = []

    def process_spider_exception(
        self, response: Response, exception: Exception
    ) -> None:
        self.calls.append(exception)
        return None


def _add_middlewares_with_output_before_exception(
    mwman: SpiderMiddlewareManager, record_mw: RecordExceptionMiddleware
) -> None:
    """Add both middlewares so that, once SpiderMiddlewareManager's
    _add_middleware() (which uses appendleft() internally) has processed
    them, PassthroughOutputMiddleware's process_spider_output ends up
    positioned *before* RecordExceptionMiddleware's
    process_spider_exception in the chain -- the ordering that triggers
    the bug: the middleware added *last* ends up *first*.
    """
    mwman._add_middleware(record_mw)
    mwman._add_middleware(PassthroughOutputMiddleware())


async def _run_scenario(callback: Any) -> RecordExceptionMiddleware:
    mwman = _build_manager()
    request = Request("http://example.com/index.html")
    response = Response(request.url, request=request)

    record_mw = RecordExceptionMiddleware()
    _add_middlewares_with_output_before_exception(mwman, record_mw)

    async def scrape_func(resp: Any, req: Any) -> Any:
        return callback()

    it = await mwman.scrape_response_async(scrape_func, response, request)
    try:
        await collect_asyncgen(it)
    except ValueError:
        pass
    else:
        raise AssertionError("expected the ValueError raised by the callback to propagate")

    return record_mw


def test_exception_handled_once_after_yield() -> None:
    """The callback yields an item and then raises: process_spider_exception()
    must still be invoked exactly once for that exception.
    """

    def callback() -> Any:
        yield {"foo": 1}
        raise ValueError("boom")

    record_mw = asyncio.run(_run_scenario(callback))

    assert len(record_mw.calls) == 1, (
        f"process_spider_exception() was called {len(record_mw.calls)} times "
        "for a single exception raised after a yield; it must be called "
        "exactly once"
    )


def test_exception_handled_once_without_yield() -> None:
    """Same as above, but the callback (still a generator function) raises
    before reaching any yield. This must behave identically to the case
    where output was yielded first.
    """

    def callback() -> Any:
        if False:
            yield  # pylint: disable=unreachable  # keeps this a generator function
        raise ValueError("boom")

    record_mw = asyncio.run(_run_scenario(callback))

    assert len(record_mw.calls) == 1, (
        f"process_spider_exception() was called {len(record_mw.calls)} times "
        "for a single exception raised without a prior yield; it must be "
        "called exactly once"
    )


if __name__ == "__main__":
    # Allow running this module directly (python tests/test_spidermiddleware_exception_dedup.py)
    # in environments where pytest's own collection cannot be used, e.g. because
    # other test modules in the same run require plugins (pytest-twisted,
    # pytest-asyncio) that aren't installed.
    test_exception_handled_once_after_yield()
    test_exception_handled_once_without_yield()
    print("OK")
