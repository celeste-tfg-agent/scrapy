"""Regression tests for scrapy.utils.idna.

See issue #17: Twisted's own hostname-to-ASCII encoding (used both to
resolve the TCP connection and to set the TLS SNI / hostname-verification
value) is stricter than what DNS and web browsers accept in practice, and
rejects hostnames that are nonetheless valid, such as:

* hostnames with underscores (common in auto-generated subdomains), e.g.
  ``mediaworld_it_api2.frosmo.com``;
* internationalized hostnames using code points outside the restrictive
  IDNA2008 "PVALID" allow-list, such as emoji, e.g.
  ``\U0001f40d.example.com``.
"""

from __future__ import annotations

import idna
import pytest

from scrapy.utils.idna import install_lenient_idna_patch, lenient_idna_encode

UNDERSCORE_HOSTNAME = "mediaworld_it_api2.frosmo.com"
EMOJI_HOSTNAME = "\U0001f40d.example.com"


class TestLenientIdnaEncode:
    def test_ascii_hostname_with_underscore_is_kept_as_is(self) -> None:
        # Underscores are common in auto-generated subdomains, and are
        # accepted by DNS resolvers and browsers, even though they are
        # technically invalid per strict IDNA rules.
        assert (
            lenient_idna_encode(UNDERSCORE_HOSTNAME)
            == UNDERSCORE_HOSTNAME.encode("ascii")
        )

    def test_plain_ascii_hostname_is_unchanged(self) -> None:
        assert lenient_idna_encode("example.com") == b"example.com"

    def test_emoji_hostname_is_punycode_encoded(self) -> None:
        assert lenient_idna_encode(EMOJI_HOSTNAME) == b"xn--4n8h.example.com"

    def test_already_punycoded_hostname_is_unchanged(self) -> None:
        assert (
            lenient_idna_encode("xn--e28h.example.com") == b"xn--e28h.example.com"
        )

    def test_standard_unicode_hostname_matches_strict_idna(self) -> None:
        # For hostnames that *are* strictly valid IDNA, the lenient encoder
        # must still produce the same result as strict encoding.
        assert lenient_idna_encode("m\xfcnchen.de") == idna.encode("m\xfcnchen.de")

    def test_trailing_dot_is_preserved(self) -> None:
        assert lenient_idna_encode("example.com.") == b"example.com."

    def test_empty_host_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            lenient_idna_encode("")


class TestInstallLenientIdnaPatch:
    """These tests exercise the actual Twisted classes that raised
    idna.core.InvalidCodepoint / UnicodeError before the fix, to make sure
    the monkeypatch is effective end-to-end and not just at the level of
    the standalone encoding helper.
    """

    def test_hostname_endpoint_accepts_underscore_hostname(self) -> None:
        install_lenient_idna_patch()
        from twisted.internet import reactor
        from twisted.internet.endpoints import HostnameEndpoint

        endpoint = HostnameEndpoint(reactor, UNDERSCORE_HOSTNAME, 443)
        assert endpoint._badHostname is False

    def test_hostname_endpoint_accepts_emoji_hostname(self) -> None:
        install_lenient_idna_patch()
        from twisted.internet import reactor
        from twisted.internet.endpoints import HostnameEndpoint

        endpoint = HostnameEndpoint(reactor, EMOJI_HOSTNAME, 443)
        assert endpoint._badHostname is False

    def test_tls_sni_hostname_accepts_underscore_hostname(self) -> None:
        # Exercise the actual entry point Scrapy uses to build the TLS SNI
        # / hostname-verification value: _ScrapyClientContextFactory
        # .creatorForNetloc(), which internally builds a ClientTLSOptions
        # (or its 26.4.0+ counterpart) instance. Going through this
        # entry point, rather than instantiating the private Twisted class
        # directly, keeps the test correct across the Twisted versions
        # that changed that private class's constructor signature.
        install_lenient_idna_patch()
        from scrapy.core.downloader.contextfactory import (
            _ScrapyClientContextFactory,
        )

        factory = _ScrapyClientContextFactory()
        options = factory.creatorForNetloc(UNDERSCORE_HOSTNAME.encode("ascii"), 443)
        assert options._hostnameASCII == UNDERSCORE_HOSTNAME
