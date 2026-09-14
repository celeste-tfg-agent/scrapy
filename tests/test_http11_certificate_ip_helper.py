"""Synchronous unit tests for
scrapy.core.downloader.handlers.http11._get_certificate_and_ip_address().

Regression coverage for issue #13: HTTP11DownloadHandler never populated
response.certificate / response.ip_address for responses with an empty
body (e.g. Content-Length: 0, such as 204 No Content responses), because
_cb_bodyready() short-circuits before txresponse.deliverBody() is called,
so _ResponseReader.connectionMade() -- where these attributes are normally
captured -- never runs.

The fix extracts that capture logic into _get_certificate_and_ip_address()
and calls it directly on txresponse._transport for empty-body responses.
This module tests that helper directly, since it needs neither a Twisted
reactor nor pytest-asyncio (unlike the full integration-level regression
tests in tests/test_downloader_handler_twisted_http11.py, which exercise
the fix end-to-end through a real crawl over HTTP/HTTPS).
"""

from __future__ import annotations

import datetime
from ipaddress import ip_address
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
from twisted.internet.ssl import Certificate

from scrapy.core.downloader.handlers.http11 import _get_certificate_and_ip_address


def _self_signed_cert(common_name: str = "localhost") -> crypto.X509:
    """Build a throwaway self-signed certificate, mirroring what
    getPeerCertificate() returns on a real TLS connection.

    Built with the ``cryptography`` APIs (rather than pyOpenSSL's own, now
    deprecated, key-generation/signing calls) and then wrapped as an
    ``OpenSSL.crypto.X509`` object, which is what ``ssl.Certificate()``
    expects.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    return crypto.load_certificate(crypto.FILETYPE_ASN1, der_bytes)


def _mock_transport(*, with_certificate: bool, host: str) -> Mock:
    """Build a stand-in for the ``txresponse._transport`` object exposed by
    twisted.web._newclient.Response, exposing only what
    _get_certificate_and_ip_address() is allowed to rely on.

    When ``with_certificate`` is False, accessing ``getPeerCertificate``
    raises AttributeError, exactly like the real transport does for plain
    (non-TLS) HTTP connections.
    """
    producer_spec = ["getPeer"]
    if with_certificate:
        producer_spec.append("getPeerCertificate")
    producer = Mock(spec=producer_spec)
    peer = Mock()
    peer.host = host
    producer.getPeer.return_value = peer
    if with_certificate:
        producer.getPeerCertificate.return_value = _self_signed_cert()

    transport = Mock(spec=["_producer"])
    transport._producer = producer
    return transport


def test_https_transport_returns_certificate_and_ip_address() -> None:
    transport = _mock_transport(with_certificate=True, host="127.0.0.1")

    certificate, ip = _get_certificate_and_ip_address(transport)

    assert isinstance(certificate, Certificate)
    assert certificate.getSubject().commonName == b"localhost"
    assert ip == ip_address("127.0.0.1")


def test_plain_http_transport_returns_no_certificate_but_has_ip_address() -> None:
    # Plain (non-TLS) transports don't expose getPeerCertificate(), so
    # certificate must stay None while ip_address is still populated.
    transport = _mock_transport(with_certificate=False, host="127.0.0.1")

    certificate, ip = _get_certificate_and_ip_address(transport)

    assert certificate is None
    assert ip == ip_address("127.0.0.1")


def test_ipv6_peer_address_is_parsed() -> None:
    transport = _mock_transport(with_certificate=False, host="::1")

    _, ip = _get_certificate_and_ip_address(transport)

    assert ip == ip_address("::1")
