"""Tests for scrapy.core.downloader.handlers.http11.HTTP11DownloadHandler."""

from __future__ import annotations

import sys
from ipaddress import IPv4Address
from socket import gethostbyname
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import pytest
from cryptography.x509 import load_der_x509_certificate
from twisted.internet.ssl import Certificate

from scrapy import Spider
from scrapy.core.downloader.handlers.http11 import HTTP11DownloadHandler
from scrapy.crawler import Crawler
from scrapy.exceptions import NotConfigured
from scrapy.utils.misc import build_from_crawler
from scrapy.utils.test import get_crawler
from tests.spiders import SingleRequestSpider
from tests.utils.bases.download_handlers_http import (
    TestHttpBase,
    TestHttpProxyBase,
    TestHttpsBase,
    TestHttpsCustomCiphersBase,
    TestHttpsInvalidDNSIdBase,
    TestHttpsInvalidDNSPatternBase,
    TestHttpsTLSVersionBase,
    TestHttpsWrongHostnameBase,
    TestHttpWithCrawlerBase,
    TestMitmProxyBase,
    TestRealWebsiteBase,
    TestSimpleHttpsBase,
)
from tests.utils.decorators import coroutine_test

if TYPE_CHECKING:
    from scrapy.core.downloader.handlers import DownloadHandlerProtocol
    from tests.mockserver.http import MockServer


pytestmark = pytest.mark.requires_reactor  # HTTP11DownloadHandler requires a reactor


class HTTP11DownloadHandlerMixin:
    @property
    def download_handler_cls(self) -> type[DownloadHandlerProtocol]:
        return HTTP11DownloadHandler

    @property
    def settings_dict(self) -> dict[str, Any] | None:
        return {
            "DOWNLOAD_HANDLERS": {
                "http": "scrapy.core.downloader.handlers.http11.HTTP11DownloadHandler",
                "https": "scrapy.core.downloader.handlers.http11.HTTP11DownloadHandler",
            }
        }


def test_not_configured_without_reactor() -> None:
    crawler = Crawler(Spider, {"TWISTED_REACTOR_ENABLED": False})
    with pytest.raises(NotConfigured):
        build_from_crawler(HTTP11DownloadHandler, crawler)


class TestHttp(HTTP11DownloadHandlerMixin, TestHttpBase):
    pass


class TestHttps(HTTP11DownloadHandlerMixin, TestHttpsBase):
    pass


class TestSimpleHttps(HTTP11DownloadHandlerMixin, TestSimpleHttpsBase):
    pass


class TestHttpsWrongHostname(HTTP11DownloadHandlerMixin, TestHttpsWrongHostnameBase):
    pass


class TestHttpsInvalidDNSId(HTTP11DownloadHandlerMixin, TestHttpsInvalidDNSIdBase):
    pass


class TestHttpsInvalidDNSPattern(
    HTTP11DownloadHandlerMixin, TestHttpsInvalidDNSPatternBase
):
    pass


class TestHttpsCustomCiphers(HTTP11DownloadHandlerMixin, TestHttpsCustomCiphersBase):
    pass


class TestHttpsTLSVersion(HTTP11DownloadHandlerMixin, TestHttpsTLSVersionBase):
    pass


class TestHttpWithCrawler(HTTP11DownloadHandlerMixin, TestHttpWithCrawlerBase):
    # --- Regression tests for the empty-body TLS/IP info bug -------------
    #
    # HTTP11DownloadHandler._cb_bodyready() takes a shortcut for responses
    # whose body is empty (Content-Length: 0), because calling
    # txresponse.deliverBody() hangs when there is no body data to deliver.
    # That shortcut used to skip _ResponseReader entirely, which is where
    # response.certificate and response.ip_address are normally captured
    # (in its connectionMade() callback). As a result, both attributes were
    # always None for responses with an empty body -- e.g. 204 No Content,
    # HEAD requests, or bodyless redirects -- even over HTTPS.
    #
    # /status?n=204 on the mock server returns an empty body with
    # Content-Length: 0, so it exercises exactly that shortcut.

    @pytest.mark.filterwarnings(
        r"ignore:.*You should use cryptography's X\.509 APIs:DeprecationWarning"
    )
    @coroutine_test
    async def test_response_ssl_certificate_empty_body(
        self, mockserver: MockServer
    ) -> None:
        if not self.is_secure:
            pytest.skip("Only applies to HTTPS")
        crawler = get_crawler(SingleRequestSpider, self.settings_dict)
        url = mockserver.url("/status?n=204", is_secure=self.is_secure)
        await crawler.crawl_async(seed=url, mockserver=mockserver)
        assert isinstance(crawler.spider, SingleRequestSpider)
        response = crawler.spider.meta["responses"][0]
        assert response.body == b""
        cert = response.certificate
        assert cert is not None
        if isinstance(cert, Certificate):  # Twisted
            assert cert.getSubject().commonName == b"localhost"
            assert cert.getIssuer().commonName == b"localhost"
        elif isinstance(cert, bytes):  # DER bytes
            cert_x509 = load_der_x509_certificate(cert)
            assert cert_x509.subject.rfc4514_string() == "CN=localhost,O=Scrapy,C=IE"
            assert cert_x509.issuer.rfc4514_string() == "CN=localhost,O=Scrapy,C=IE"

    @coroutine_test
    async def test_response_ip_address_empty_body(
        self, mockserver: MockServer
    ) -> None:
        crawler = get_crawler(SingleRequestSpider, self.settings_dict)
        url = mockserver.url("/status?n=204", is_secure=self.is_secure)
        expected_netloc, _ = urlparse(url).netloc.split(":")
        await crawler.crawl_async(seed=url, mockserver=mockserver)
        assert isinstance(crawler.spider, SingleRequestSpider)
        response = crawler.spider.meta["responses"][0]
        assert response.body == b""
        ip_address = response.ip_address
        assert isinstance(ip_address, IPv4Address)
        assert str(ip_address) == gethostbyname(expected_netloc)


class TestHttpsWithCrawler(TestHttpWithCrawler):
    is_secure = True


class TestHttpProxy(HTTP11DownloadHandlerMixin, TestHttpProxyBase):
    pass


class TestHttpsProxy(HTTP11DownloadHandlerMixin, TestHttpProxyBase):
    is_secure = True
    # not implemented
    handler_supports_tls_in_tls = False


@pytest.mark.requires_mitmproxy
class TestMitmProxy(HTTP11DownloadHandlerMixin, TestMitmProxyBase):
    # not implemented
    handler_supports_tls_in_tls = False


@pytest.mark.requires_internet
class TestRealWebsite(HTTP11DownloadHandlerMixin, TestRealWebsiteBase):
    @property
    def platform_cert_store_works(self) -> bool:
        return sys.platform != "win32"
