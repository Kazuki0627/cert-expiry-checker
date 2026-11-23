#!/usr/bin/env python3
"""SSL certificate and domain registration expiry checker.

Standard library only (Python 3.11+).

Usage:
    python3 cert_checker.py example.com google.com
    python3 cert_checker.py --file domains.txt --json --warn-days 14
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

__version__ = "1.1.0"

try:
    import truststore as _truststore
except ImportError:  # optional dependency; see create_verify_context()
    _truststore = None  # type: ignore[assignment]


def create_verify_context() -> ssl.SSLContext:
    """Return a TLS client context that verifies against a trust store.

    When the optional ``truststore`` package is installed, verification uses
    the operating system's trust store (via an explicitly constructed
    ``truststore.SSLContext``; ``inject_into_ssl`` is never used), matching
    how browsers verify. This fixes sites whose root CA is available to the
    OS but missing from Python's bundled store (e.g. "SSL.com TLS ECC Root
    CA 2022" on Windows). Without truststore, falls back to
    ``ssl.create_default_context()``.
    """
    if _truststore is not None:
        return _truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    return ssl.create_default_context()

RDAP_BASE_URL = "https://rdap.org/domain/"
DEFAULT_PORT = 443
DEFAULT_TIMEOUT = 10.0
DEFAULT_WARN_DAYS = 30
USER_AGENT = f"cert-expiry-checker/{__version__} (python-urllib)"

# AIA (Authority Information Access) chain completion
AIA_MAX_INTERMEDIATES = 3
AIA_MAX_BYTES = 64 * 1024
AIA_NOTE = "chain completed via AIA"

# OpenSSL X509_V_ERR_* codes that indicate an incomplete chain (not a bad cert).
_CHAIN_ERROR_CODES = {
    2,   # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
    19,  # X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    20,  # X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    21,  # X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
}
_CHAIN_ERROR_MESSAGES = (
    "unable to get local issuer certificate",
    "unable to get issuer certificate",
    "unable to verify the first certificate",
    "self-signed certificate in certificate chain",
    "self signed certificate in certificate chain",
)

# Status values
OK = "OK"
WARNING = "WARNING"
EXPIRED = "EXPIRED"
UNKNOWN = "UNKNOWN"
ERROR = "ERROR"

# Higher number = more severe (used to combine cert + domain statuses)
_SEVERITY = {OK: 0, UNKNOWN: 1, WARNING: 2, ERROR: 3, EXPIRED: 4}

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_WARNING = 2


# --------------------------------------------------------------------------
# Data classes
# --------------------------------------------------------------------------

@dataclass
class CertInfo:
    status: str = UNKNOWN
    not_after: str | None = None  # ISO 8601 (UTC)
    days_remaining: int | None = None
    issuer: str | None = None
    subject_cn: str | None = None
    sans: list[str] = field(default_factory=list)
    verified: bool | None = None
    error: str | None = None
    note: str | None = None  # informational, e.g. "chain completed via AIA"


@dataclass
class DomainInfo:
    status: str = UNKNOWN
    expiration: str | None = None  # ISO 8601 (UTC)
    days_remaining: int | None = None
    rdap_url: str | None = None
    error: str | None = None


@dataclass
class CheckResult:
    domain: str
    port: int = DEFAULT_PORT
    status: str = UNKNOWN
    cert: CertInfo = field(default_factory=CertInfo)
    registration: DomainInfo = field(default_factory=DomainInfo)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# Date parsing / status logic
# --------------------------------------------------------------------------

def parse_cert_date(value: str) -> datetime:
    """Parse an OpenSSL-style certificate date, e.g. 'Jun  1 12:00:00 2025 GMT'.

    Returns an aware datetime in UTC. Raises ValueError on bad input.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid certificate date: {value!r}")
    try:
        ts = ssl.cert_time_to_seconds(value.strip())
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"invalid certificate date: {value!r}") from exc
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def parse_rdap_date(value: str) -> datetime:
    """Parse an RDAP (RFC 3339 / ISO 8601) date string into an aware UTC datetime.

    Accepts forms such as '2025-08-13T04:00:00Z', '2025-08-13T04:00:00.123Z',
    '2025-08-13T04:00:00+09:00' and '2025-08-13'. Naive values are assumed UTC.
    Raises ValueError on bad input.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"invalid RDAP date: {value!r}")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid RDAP date: {value!r}") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def days_remaining(expiry: datetime, now: datetime | None = None) -> int:
    """Whole days from `now` until `expiry` (floored; negative once expired)."""
    if now is None:
        now = datetime.now(timezone.utc)
    delta = expiry - now
    # floor division so that e.g. -1 hour => -1 day (already expired)
    return int(delta.total_seconds() // 86400)


def compute_status(days: int | None, warn_days: int) -> str:
    """Map days-remaining to a status string."""
    if days is None:
        return UNKNOWN
    if days < 0:
        return EXPIRED
    if days <= warn_days:
        return WARNING
    return OK


def combine_status(*statuses: str) -> str:
    """Return the most severe of the given statuses."""
    return max(statuses, key=lambda s: _SEVERITY.get(s, 0)) if statuses else UNKNOWN


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


# --------------------------------------------------------------------------
# TLS certificate check
# --------------------------------------------------------------------------

def _name_to_dict(name: Iterable[Iterable[tuple[str, str]]] | None) -> dict[str, str]:
    """Flatten ssl's nested RDN tuple structure into a simple dict."""
    result: dict[str, str] = {}
    for rdn in name or ():
        for key, val in rdn:
            result.setdefault(key, val)
    return result


def summarize_issuer(issuer: dict[str, str]) -> str | None:
    parts = [issuer[k] for k in ("organizationName", "commonName") if issuer.get(k)]
    return " / ".join(parts) if parts else None


def parse_peer_cert(cert: dict[str, Any]) -> dict[str, Any]:
    """Extract the interesting fields from an ssl.getpeercert() dict."""
    subject = _name_to_dict(cert.get("subject"))
    issuer = _name_to_dict(cert.get("issuer"))
    sans = [v for (k, v) in cert.get("subjectAltName", ()) if k == "DNS"]
    not_after_raw = cert.get("notAfter")
    if not not_after_raw:
        raise ValueError("certificate has no notAfter field")
    return {
        "not_after": parse_cert_date(not_after_raw),
        "issuer": summarize_issuer(issuer),
        "subject_cn": subject.get("commonName"),
        "sans": sans,
    }


def _decode_der_cert(der: bytes) -> dict[str, Any]:
    """Decode a DER certificate into the getpeercert() dict format.

    Used only as a fallback for certificates that fail verification (e.g.
    already expired or self-signed) so that we can still report their dates.
    Relies on CPython's internal ssl._ssl._test_decode_cert helper.
    """
    decoder = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decoder is None:
        raise RuntimeError("certificate decoding not supported by this Python build")
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        return decoder(path)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _verify_message(exc: ssl.SSLCertVerificationError) -> str:
    return exc.verify_message or str(exc)


def is_chain_error(exc: ssl.SSLCertVerificationError) -> bool:
    """True if a verification error means "incomplete chain" (AIA may help).

    Hostname mismatch, expiry, a self-signed leaf etc. are NOT chain errors and
    must never be retried.
    """
    code = getattr(exc, "verify_code", None)
    message = (getattr(exc, "verify_message", None) or str(exc)).lower()
    if code == 62 or "hostname mismatch" in message:  # X509_V_ERR_HOSTNAME_MISMATCH
        return False
    if code in _CHAIN_ERROR_CODES:
        return True
    return any(m in message for m in _CHAIN_ERROR_MESSAGES)


def _get_verified_cert(host: str, port: int, timeout: float,
                       ctx: ssl.SSLContext) -> dict[str, Any]:
    """Verified TLS handshake (hostname checked by ctx); returns getpeercert()."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert()


def _get_unverified_der(host: str, port: int, timeout: float) -> bytes:
    insecure = ssl.create_default_context()
    insecure.check_hostname = False
    insecure.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with insecure.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError("server did not present a certificate")
    return der


def extract_ca_issuers(cert: dict[str, Any] | None) -> list[str]:
    """Return the http(s) caIssuers URIs from a decoded cert dict (others ignored)."""
    if not isinstance(cert, dict):
        return []
    raw = cert.get("caIssuers") or ()
    if isinstance(raw, str):
        raw = (raw,)
    uris: list[str] = []
    for uri in raw:
        if not isinstance(uri, str):
            continue
        uri = uri.strip()
        if uri.lower().startswith(("http://", "https://")) and uri not in uris:
            uris.append(uri)
    return uris


class _HttpOnlyRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to http/https URLs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        if not newurl.lower().startswith(("http://", "https://")):
            raise urllib.error.HTTPError(newurl, code, "refusing non-http(s) redirect",
                                         headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _open_aia_url(url: str, timeout: float):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(_HttpOnlyRedirectHandler)
    return opener.open(req, timeout=timeout)


def cert_bytes_to_pem(data: bytes) -> str:
    """Convert a downloaded certificate (PEM or DER) to a normalized PEM string.

    For PEM input only the first CERTIFICATE block is used. Raises ValueError
    if the data is neither.
    """
    if not data:
        raise ValueError("empty certificate data")
    begin, end = b"-----BEGIN CERTIFICATE-----", b"-----END CERTIFICATE-----"
    start = data.find(begin)
    if start != -1:
        stop = data.find(end, start)
        if stop == -1:
            raise ValueError("truncated PEM certificate")
        block = data[start:stop + len(end)].decode("ascii")
        der = ssl.PEM_cert_to_DER_cert(block)  # validates base64
    else:
        der = data
        # DER certificates start with an ASN.1 SEQUENCE tag
        if der[:1] != b"\x30":
            raise ValueError("not a DER or PEM certificate")
    return ssl.DER_cert_to_PEM_cert(der)


def download_ca_issuer(url: str, timeout: float = DEFAULT_TIMEOUT,
                       max_bytes: int = AIA_MAX_BYTES) -> str:
    """Download a caIssuers certificate and return it as PEM."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError(f"unsupported AIA URI scheme: {url!r}")
    with _open_aia_url(url, timeout) as resp:
        data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"AIA certificate larger than {max_bytes} bytes")
    return cert_bytes_to_pem(data)


def _aia_context(pems: list[str]) -> ssl.SSLContext:
    """Default verifying context plus the downloaded intermediates.

    VERIFY_X509_PARTIAL_CHAIN (enabled by default since Python 3.13) is cleared so
    that a downloaded intermediate can never act as a trust anchor by itself: the
    chain must still end at a root from the system trust store.
    """
    ctx = create_verify_context()
    partial = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
    if partial:
        ctx.verify_flags &= ~partial
    ctx.load_verify_locations(cadata="\n".join(pems))
    return ctx


def complete_chain_via_aia(host: str, port: int, timeout: float,
                           leaf: dict[str, Any]) -> tuple[dict[str, Any] | None, int, str | None]:
    """Try to verify host by fetching missing intermediates via AIA caIssuers.

    Returns (verified_cert_dict, n_intermediates, None) on success, or
    (None, 0, error) on failure, where `error` is a more specific verification
    error seen on retry (e.g. expired / hostname mismatch) or None. Never raises.
    """
    pems: list[str] = []
    tried: set[str] = set()
    uris = extract_ca_issuers(leaf)
    try:
        while uris and len(pems) < AIA_MAX_INTERMEDIATES:
            pem = decoded = None
            for uri in uris:
                if uri in tried:
                    continue
                tried.add(uri)
                try:
                    pem = download_ca_issuer(uri, timeout)
                    decoded = _decode_der_cert(ssl.PEM_cert_to_DER_cert(pem))
                    break
                except Exception:  # noqa: BLE001 - try next URI
                    pem = decoded = None
            if pem is None or decoded is None:
                return None, 0, None
            # A self-signed download would become a trust anchor: never load one.
            if _name_to_dict(decoded.get("subject")) == _name_to_dict(decoded.get("issuer")):
                return None, 0, None
            pems.append(pem)
            try:
                cert = _get_verified_cert(host, port, timeout, _aia_context(pems))
                return cert, len(pems), None
            except ssl.SSLCertVerificationError as exc:
                if not is_chain_error(exc):
                    return None, 0, _verify_message(exc)
            uris = extract_ca_issuers(decoded)
    except Exception:  # noqa: BLE001 - AIA is best effort
        return None, 0, None
    return None, 0, None


def fetch_peer_cert(host: str, port: int = DEFAULT_PORT,
                    timeout: float = DEFAULT_TIMEOUT) -> tuple[Any, ...]:
    """Connect via TLS and return (cert_dict, verified, verify_error[, note]).

    First tries a fully verified connection. If verification fails, reconnects
    without verification to still read the certificate's dates. If the failure
    was due to an incomplete chain, tries to complete it via AIA caIssuers and
    re-verifies; on success the 4th element is a note describing that.
    """
    try:
        return _get_verified_cert(host, port, timeout, create_verify_context()), True, None
    except ssl.SSLCertVerificationError as exc:
        verify_error = _verify_message(exc)
        chain_error = is_chain_error(exc)

    decoded = _decode_der_cert(_get_unverified_der(host, port, timeout))
    if chain_error:
        cert, count, retry_error = complete_chain_via_aia(host, port, timeout, decoded)
        if cert is not None:
            return cert, True, None, f"{AIA_NOTE} ({count} intermediate(s) fetched)"
        if retry_error:
            verify_error = retry_error
    return decoded, False, verify_error


def check_cert(host: str, port: int = DEFAULT_PORT, warn_days: int = DEFAULT_WARN_DAYS,
               timeout: float = DEFAULT_TIMEOUT, now: datetime | None = None) -> CertInfo:
    """Check the TLS certificate of host:port. Never raises."""
    info = CertInfo()
    try:
        cert, verified, verify_error, *extra = fetch_peer_cert(host, port, timeout)
        info.note = extra[0] if extra else None
        parsed = parse_peer_cert(cert)
    except Exception as exc:  # noqa: BLE001 - per-domain robustness
        info.status = ERROR
        info.error = _format_error(exc)
        return info

    info.not_after = _iso(parsed["not_after"])
    info.days_remaining = days_remaining(parsed["not_after"], now)
    info.issuer = parsed["issuer"]
    info.subject_cn = parsed["subject_cn"]
    info.sans = parsed["sans"]
    info.verified = verified
    info.status = compute_status(info.days_remaining, warn_days)
    if not verified:
        info.error = f"certificate verification failed: {verify_error}"
        if info.status == OK:
            # Untrusted / mismatched certificates are a problem even if not expiring.
            info.status = ERROR
    return info


# --------------------------------------------------------------------------
# RDAP domain registration check
# --------------------------------------------------------------------------

def extract_rdap_expiration(data: Any) -> datetime | None:
    """Return the 'expiration' event date from an RDAP domain object, or None."""
    if not isinstance(data, dict):
        return None
    events = data.get("events")
    if not isinstance(events, list):
        return None
    for event in events:
        if not isinstance(event, dict):
            continue
        action = str(event.get("eventAction", "")).strip().lower()
        if action == "expiration":
            date = event.get("eventDate")
            try:
                return parse_rdap_date(date)
            except ValueError:
                continue
    return None


def fetch_rdap(domain: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[dict[str, Any], str]:
    """GET the RDAP domain object (urllib follows redirects). Returns (data, final_url)."""
    url = RDAP_BASE_URL + domain
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": USER_AGENT,
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read()
        final_url = resp.geturl()
    return json.loads(raw.decode("utf-8")), final_url


def _fetch_rdap_with_parent_fallback(domain: str, timeout: float) -> tuple[dict[str, Any], str]:
    """Fetch RDAP; on 404 retry with parent domains (www.example.com -> example.com).

    Stops at two labels. This is a heuristic: it does not know about public
    suffixes such as co.uk, but those simply end in another 404.
    """
    candidate = domain
    while True:
        try:
            return fetch_rdap(candidate, timeout)
        except urllib.error.HTTPError as exc:
            labels = candidate.split(".")
            if exc.code != 404 or len(labels) <= 2:
                raise
            candidate = ".".join(labels[1:])


def check_rdap(domain: str, warn_days: int = DEFAULT_WARN_DAYS,
               timeout: float = DEFAULT_TIMEOUT, now: datetime | None = None) -> DomainInfo:
    """Check domain registration expiry via RDAP. Never raises.

    Any RDAP failure (unsupported TLD, network error, missing event) is reported
    as UNKNOWN with an explanatory message rather than an error.
    """
    info = DomainInfo()
    try:
        data, info.rdap_url = _fetch_rdap_with_parent_fallback(domain, timeout)
    except urllib.error.HTTPError as exc:
        info.error = ("RDAP: domain not found / TLD not supported (HTTP 404)"
                      if exc.code == 404 else f"RDAP unavailable: HTTP {exc.code}")
        return info
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # ValueError covers JSON decode errors
        info.error = f"RDAP unavailable: {_format_error(exc)}"
        return info
    except Exception as exc:  # noqa: BLE001
        info.error = f"RDAP unavailable: {_format_error(exc)}"
        return info

    expiry = extract_rdap_expiration(data)
    if expiry is None:
        info.error = "RDAP: no expiration event"
        return info
    info.expiration = _iso(expiry)
    info.days_remaining = days_remaining(expiry, now)
    info.status = compute_status(info.days_remaining, warn_days)
    return info


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def _format_error(exc: BaseException) -> str:
    if isinstance(exc, urllib.error.URLError) and not isinstance(exc, urllib.error.HTTPError):
        return f"{type(exc).__name__}: {exc.reason}"
    msg = str(exc) or type(exc).__name__
    return f"{type(exc).__name__}: {msg}" if type(exc).__name__ not in msg else msg


def normalize_target(raw: str) -> tuple[str, int]:
    """Turn user input ('https://Example.com/path', 'host:8443') into (host, port)."""
    text = raw.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0].split("?", 1)[0]
    port = DEFAULT_PORT
    if text.count(":") == 1:
        host_part, port_part = text.split(":")
        if port_part.isdigit():
            text, port = host_part, int(port_part)
    host = text.strip().rstrip(".").lower()
    if not host:
        raise ValueError(f"invalid domain: {raw!r}")
    return host, port


def check_domain(target: str, warn_days: int = DEFAULT_WARN_DAYS,
                 timeout: float = DEFAULT_TIMEOUT, check_registration: bool = True,
                 now: datetime | None = None) -> CheckResult:
    """Run all checks for one domain. Never raises."""
    try:
        host, port = normalize_target(target)
    except ValueError as exc:
        result = CheckResult(domain=target.strip())
        result.cert = CertInfo(status=ERROR, error=str(exc))
        result.status = ERROR
        return result

    result = CheckResult(domain=host, port=port)
    result.cert = check_cert(host, port, warn_days, timeout, now)
    if check_registration:
        result.registration = check_rdap(host, warn_days, timeout, now)
    else:
        result.registration = DomainInfo(error="skipped")
    result.status = combine_status(result.cert.status, result.registration.status)
    return result


def check_all(targets: list[str], warn_days: int = DEFAULT_WARN_DAYS,
              timeout: float = DEFAULT_TIMEOUT, workers: int = 8,
              check_registration: bool = True) -> list[CheckResult]:
    """Check many domains concurrently, preserving input order."""
    if not targets:
        return []
    workers = max(1, min(workers, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(
            lambda t: check_domain(t, warn_days, timeout, check_registration), targets))


def exit_code_for(results: list[CheckResult]) -> int:
    """0 = all OK, 2 = any WARNING/EXPIRED, 1 = any ERROR (with no warnings)."""
    statuses = set()
    for r in results:
        statuses.update((r.status, r.cert.status, r.registration.status))
    if statuses & {WARNING, EXPIRED}:
        return EXIT_WARNING
    if ERROR in statuses:
        return EXIT_ERROR
    return EXIT_OK


# --------------------------------------------------------------------------
# Input / output
# --------------------------------------------------------------------------

def parse_domain_lines(lines: Iterable[str]) -> list[str]:
    """Parse a domain list: one per line, '#' comments and blank lines ignored."""
    domains: list[str] = []
    for line in lines:
        content = line.split("#", 1)[0].strip()
        if content:
            domains.append(content)
    return domains


def read_domain_file(path: str) -> list[str]:
    with open(path, encoding="utf-8") as fh:
        return parse_domain_lines(fh)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def _date_only(iso: str | None) -> str:
    return iso[:10] if iso else "-"


def _num(n: int | None) -> str:
    return "-" if n is None else str(n)


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def format_table(results: list[CheckResult]) -> str:
    headers = ["DOMAIN", "STATUS", "CERT EXPIRES", "DAYS", "ISSUER",
               "DOMAIN EXPIRES", "DAYS", "NOTES"]
    rows = []
    for r in results:
        host = r.domain if r.port == DEFAULT_PORT else f"{r.domain}:{r.port}"
        notes = []
        if r.cert.error:
            notes.append(f"cert: {r.cert.error}")
        if r.cert.note:
            notes.append(f"cert: {r.cert.note}")
        if r.registration.error and r.registration.error != "skipped":
            notes.append(r.registration.error)
        rows.append([
            host,
            r.status,
            _date_only(r.cert.not_after),
            _num(r.cert.days_remaining),
            _truncate(r.cert.issuer or "-", 32),
            _date_only(r.registration.expiration),
            _num(r.registration.days_remaining),
            "; ".join(notes) or "",
        ])
    widths = [max(len(str(row[i])) for row in [headers] + rows) for i in range(len(headers))]
    right_align = {3, 6}

    def fmt(row: list[str]) -> str:
        cells = [str(c).rjust(widths[i]) if i in right_align else str(c).ljust(widths[i])
                 for i, c in enumerate(row)]
        return "  ".join(cells).rstrip()

    lines = [fmt(headers), "  ".join("-" * w for w in widths)]
    lines.extend(fmt(row) for row in rows)
    return "\n".join(lines)


def summarize(results: list[CheckResult]) -> dict[str, int]:
    counts = {OK: 0, WARNING: 0, EXPIRED: 0, ERROR: 0, UNKNOWN: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts


def summary_line(results: list[CheckResult]) -> str:
    c = summarize(results)
    return (f"Checked {len(results)} domain(s): {c[OK]} OK, {c[WARNING]} WARNING, "
            f"{c[EXPIRED]} EXPIRED, {c[ERROR]} ERROR, {c[UNKNOWN]} UNKNOWN")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cert_checker.py",
        description="Check SSL/TLS certificate expiry and domain registration expiry (RDAP).",
        epilog="Exit codes: 0 = all OK, 2 = any WARNING/EXPIRED, 1 = check error(s).",
    )
    p.add_argument("domains", nargs="*", help="domains to check (host or host:port)")
    p.add_argument("-f", "--file", action="append", default=[],
                   help="read domains from file (one per line, '#' comments allowed); repeatable")
    p.add_argument("--json", action="store_true", help="output JSON instead of a table")
    p.add_argument("--warn-days", type=int, default=DEFAULT_WARN_DAYS, metavar="N",
                   help=f"warn when expiry is within N days (default: {DEFAULT_WARN_DAYS})")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, metavar="SEC",
                   help=f"network timeout in seconds (default: {DEFAULT_TIMEOUT:g})")
    p.add_argument("--workers", type=int, default=8, metavar="N",
                   help="number of domains to check in parallel (default: 8)")
    p.add_argument("--no-rdap", action="store_true",
                   help="skip domain registration (RDAP) check")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.warn_days < 0:
        parser.error("--warn-days must be >= 0")

    targets = list(args.domains)
    for path in args.file:
        try:
            targets.extend(read_domain_file(path))
        except OSError as exc:
            print(f"error: cannot read {path}: {exc.strerror or exc}", file=sys.stderr)
            return EXIT_ERROR
    targets = _dedupe(t.strip() for t in targets if t.strip())
    if not targets:
        parser.error("no domains given (pass domains as arguments or use --file)")

    results = check_all(targets, args.warn_days, args.timeout, args.workers,
                        check_registration=not args.no_rdap)
    code = exit_code_for(results)

    if args.json:
        payload = {
            "checked_at": _iso(datetime.now(timezone.utc)),
            "warn_days": args.warn_days,
            "results": [r.to_dict() for r in results],
            "summary": summarize(results),
            "exit_code": code,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        print(summary_line(results), file=sys.stderr)
    else:
        print(format_table(results))
        print()
        print(summary_line(results))
    return code


if __name__ == "__main__":
    sys.exit(main())
