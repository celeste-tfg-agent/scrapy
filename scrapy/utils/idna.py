"""Lenient hostname-to-ASCII (IDNA/UTS-46-style) encoding.

Both the IDNA2003 codec built into the Python standard library
(``str.encode("idna")``) and the third-party ``idna`` package that Twisted
uses internally for IDNA2008 (see :mod:`twisted.internet._idna`) are
considerably stricter than what DNS, web browsers and real-world servers
accept in practice:

* Hostnames with underscores (surprisingly common in auto-generated
  subdomains, e.g. ``mediaworld_it_api2.frosmo.com``) are rejected outright,
  even though they resolve fine via DNS and any browser will happily
  connect to them.
* Internationalized hostnames using code points outside the restrictive set
  that the IDNA2008 standard considers "PVALID" (such as emoji, e.g.
  ``\U0001f40d.example.com``) are rejected outright too, even though such
  domains are registered and used in production by some sites, and browsers
  resolve/connect to them without complaint.

The hostname-to-ASCII conversion that actually matters for us -- setting up
the TCP connection and the TLS SNI / certificate-verification hostname --
happens deep inside Twisted:

* :class:`twisted.internet.endpoints.HostnameEndpoint` (used by
  :class:`twisted.web.client.Agent` for every plain request) calls
  ``twisted.internet._idna._idnaBytes``, which is imported into
  ``twisted.internet.endpoints`` as ``_idnaBytes``.
* :class:`twisted.internet._sslverify.ClientTLSOptions` (used for the TLS
  handshake, including by :func:`twisted.internet.ssl.optionsForClientTLS`)
  calls the very same helper, imported into ``twisted.internet._sslverify``
  under the same name.

Twisted does not expose a public, per-request hook to relax this behaviour,
so this module provides a permissive drop-in replacement for that helper
and monkeypatches it into both places. Hostnames that are already valid
IDNA keep encoding exactly the same way; hostnames that are "non-standard
but valid in practice" (underscores, emoji, ...) are still turned into a
usable ASCII/Punycode form instead of raising.
"""

from __future__ import annotations

import idna

__all__ = ["install_lenient_idna_patch", "lenient_idna_encode"]


def _lenient_alabel(label: str) -> bytes:
    """Encode a single hostname label into its ASCII ("A-label") form,
    without enforcing strict IDNA2008 per-codepoint validity.
    """
    try:
        # Already ASCII. This also covers hostnames that are already
        # Punycode-encoded (e.g. "xn--e28h") and hostnames using
        # characters that are technically invalid per strict IDNA, like
        # underscores: keep them exactly as given, the same way a
        # browser would.
        return label.encode("ascii")
    except UnicodeEncodeError:
        pass
    # Non-ASCII label: apply the UTS #46 character mapping (case
    # folding, Unicode normalization, full-width dot normalization,
    # etc.) without the extra "STD3 ASCII rules" restriction, then
    # Punycode-encode the result. This mirrors how browsers turn a
    # Unicode hostname into its ASCII form (loosely, the WHATWG URL
    # "domain to ASCII" algorithm), rather than the strict per-codepoint
    # IDNA2008 validation that ``idna.encode()`` (and
    # ``str.encode("idna")``) perform, which rejects code points such as
    # emoji even though UTS #46 itself does not consider them invalid.
    mapped = idna.uts46_remap(label, std3_rules=False)
    try:
        return mapped.encode("ascii")
    except UnicodeEncodeError:
        return b"xn--" + mapped.encode("punycode")


def lenient_idna_encode(host: str) -> bytes:
    """Encode *host* into its ASCII/Punycode form, leniently.

    This is a more permissive drop-in replacement for
    ``host.encode("idna")`` / ``idna.encode(host)``: hostnames that do not
    strictly conform to IDNA2003/IDNA2008 but are nonetheless valid in
    practice (hostnames with underscores, or internationalized hostnames
    using code points outside the strict IDNA2008 allow-list, such as
    emoji) are still encoded to a usable ASCII/Punycode form, matching what
    DNS resolvers and web browsers actually accept, instead of raising.
    """
    if not host:
        raise ValueError("Cannot IDNA-encode an empty host")
    trailing_dot = len(host) > 1 and host.endswith(".")
    core = host[:-1] if trailing_dot else host
    encoded = b".".join(_lenient_alabel(label) for label in core.split("."))
    return encoded + b"." if trailing_dot else encoded


_patched = False


def install_lenient_idna_patch() -> None:
    """Make Twisted use :func:`lenient_idna_encode` instead of its own
    strict hostname-to-ASCII encoding, both for the TCP connection
    (:class:`twisted.internet.endpoints.HostnameEndpoint`) and for the TLS
    SNI / hostname-verification value
    (:class:`twisted.internet._sslverify.ClientTLSOptions`, and anything
    built on top of it, such as
    :func:`twisted.internet.ssl.optionsForClientTLS`).

    Idempotent: safe to call multiple times (e.g. once per download handler
    instantiation).
    """
    global _patched
    if _patched:
        return

    import twisted.internet._sslverify as _sslverify
    import twisted.internet.endpoints as _endpoints

    # Both modules did ``from twisted.internet._idna import _idnaBytes``,
    # which binds the name in *their own* namespace, so patching
    # ``twisted.internet._idna._idnaBytes`` alone would not affect either
    # of them: each module-level name needs to be patched directly.
    _endpoints._idnaBytes = lenient_idna_encode
    _sslverify._idnaBytes = lenient_idna_encode
    _patched = True
