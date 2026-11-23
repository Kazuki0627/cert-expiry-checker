"""Offline unit tests for cert_checker. All network calls are mocked."""

import io
import json
import os
import ssl
import sys
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import cert_checker as cc  # noqa: E402

NOW = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def make_peer_cert(not_after="Mar  1 12:00:00 2026 GMT"):
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R3"),),
        ),
        "notBefore": "Dec  1 12:00:00 2025 GMT",
        "notAfter": not_after,
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com"),
                           ("IP Address", "93.184.216.34")),
    }


def rdap_payload(exp_date="2026-08-13T04:00:00Z"):
    events = [
        {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:38Z"},
    ]
    if exp_date is not None:
        events.append({"eventAction": "expiration", "eventDate": exp_date})
    return {"objectClassName": "domain", "ldhName": "EXAMPLE.COM", "events": events}


class FakeResponse:
    def __init__(self, body: bytes, url="https://rdap.verisign.com/com/v1/domain/example.com"):
        self._body = body
        self._url = url

    def read(self):
        return self._body

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

class TestParseCertDate(unittest.TestCase):
    def test_standard_format(self):
        dt = cc.parse_cert_date("Jun  1 12:00:00 2025 GMT")
        self.assertEqual(dt, datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc))

    def test_two_digit_day(self):
        dt = cc.parse_cert_date("Dec 31 23:59:59 2030 GMT")
        self.assertEqual(dt, datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc))

    def test_result_is_aware_utc(self):
        self.assertEqual(cc.parse_cert_date("Jan  5 00:00:00 2026 GMT").tzinfo, timezone.utc)

    def test_invalid_raises_value_error(self):
        for bad in ["", "   ", "not a date", "2025-06-01", None]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cc.parse_cert_date(bad)


class TestParseRdapDate(unittest.TestCase):
    def test_zulu(self):
        self.assertEqual(cc.parse_rdap_date("2026-08-13T04:00:00Z"),
                         datetime(2026, 8, 13, 4, 0, tzinfo=timezone.utc))

    def test_fractional_seconds(self):
        dt = cc.parse_rdap_date("2026-08-13T04:00:00.123Z")
        self.assertEqual(dt.replace(microsecond=0),
                         datetime(2026, 8, 13, 4, 0, tzinfo=timezone.utc))

    def test_offset_converted_to_utc(self):
        self.assertEqual(cc.parse_rdap_date("2026-08-13T09:00:00+09:00"),
                         datetime(2026, 8, 13, 0, 0, tzinfo=timezone.utc))

    def test_naive_assumed_utc(self):
        self.assertEqual(cc.parse_rdap_date("2026-08-13T04:00:00"),
                         datetime(2026, 8, 13, 4, 0, tzinfo=timezone.utc))

    def test_date_only(self):
        self.assertEqual(cc.parse_rdap_date("2026-08-13"),
                         datetime(2026, 8, 13, tzinfo=timezone.utc))

    def test_invalid(self):
        for bad in ["", "garbage", "13/08/2026", None, 12345]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cc.parse_rdap_date(bad)


# ---------------------------------------------------------------------------
# Days remaining / status logic
# ---------------------------------------------------------------------------

class TestDaysRemainingAndStatus(unittest.TestCase):
    def test_days_remaining_exact(self):
        self.assertEqual(cc.days_remaining(NOW + timedelta(days=10), NOW), 10)

    def test_days_remaining_partial_day_floors(self):
        self.assertEqual(cc.days_remaining(NOW + timedelta(days=10, hours=23), NOW), 10)

    def test_days_remaining_less_than_one_day(self):
        self.assertEqual(cc.days_remaining(NOW + timedelta(hours=5), NOW), 0)

    def test_days_remaining_past_is_negative(self):
        self.assertEqual(cc.days_remaining(NOW - timedelta(hours=1), NOW), -1)
        self.assertEqual(cc.days_remaining(NOW - timedelta(days=5), NOW), -5)

    def test_days_remaining_defaults_to_now(self):
        future = datetime.now(timezone.utc) + timedelta(days=100, hours=1)
        self.assertEqual(cc.days_remaining(future), 100)

    def test_compute_status(self):
        cases = [
            (None, 30, cc.UNKNOWN),
            (-1, 30, cc.EXPIRED),
            (-365, 30, cc.EXPIRED),
            (0, 30, cc.WARNING),
            (30, 30, cc.WARNING),
            (31, 30, cc.OK),
            (365, 30, cc.OK),
            (0, 0, cc.WARNING),
            (1, 0, cc.OK),
        ]
        for days, warn, expected in cases:
            with self.subTest(days=days, warn=warn):
                self.assertEqual(cc.compute_status(days, warn), expected)

    def test_combine_status_picks_most_severe(self):
        self.assertEqual(cc.combine_status(cc.OK, cc.UNKNOWN), cc.UNKNOWN)
        self.assertEqual(cc.combine_status(cc.OK, cc.WARNING), cc.WARNING)
        self.assertEqual(cc.combine_status(cc.WARNING, cc.EXPIRED), cc.EXPIRED)
        self.assertEqual(cc.combine_status(cc.ERROR, cc.OK), cc.ERROR)
        self.assertEqual(cc.combine_status(cc.OK, cc.OK), cc.OK)


# ---------------------------------------------------------------------------
# RDAP parsing and check
# ---------------------------------------------------------------------------

class TestExtractRdapExpiration(unittest.TestCase):
    def test_finds_expiration(self):
        self.assertEqual(cc.extract_rdap_expiration(rdap_payload()),
                         datetime(2026, 8, 13, 4, 0, tzinfo=timezone.utc))

    def test_case_insensitive_action(self):
        data = {"events": [{"eventAction": "Expiration", "eventDate": "2027-01-01T00:00:00Z"}]}
        self.assertEqual(cc.extract_rdap_expiration(data),
                         datetime(2027, 1, 1, tzinfo=timezone.utc))

    def test_no_expiration_event(self):
        self.assertIsNone(cc.extract_rdap_expiration(rdap_payload(exp_date=None)))

    def test_missing_or_malformed_events(self):
        for data in [{}, {"events": None}, {"events": "x"}, {"events": [None, 1, "x"]},
                     None, [], "string"]:
            with self.subTest(data=data):
                self.assertIsNone(cc.extract_rdap_expiration(data))

    def test_bad_date_skipped_then_valid_used(self):
        data = {"events": [
            {"eventAction": "expiration", "eventDate": "not-a-date"},
            {"eventAction": "expiration", "eventDate": "2028-02-02T00:00:00Z"},
        ]}
        self.assertEqual(cc.extract_rdap_expiration(data),
                         datetime(2028, 2, 2, tzinfo=timezone.utc))

    def test_missing_event_date(self):
        self.assertIsNone(cc.extract_rdap_expiration({"events": [{"eventAction": "expiration"}]}))


class TestCheckRdap(unittest.TestCase):
    def _urlopen_returning(self, payload):
        body = json.dumps(payload).encode()
        return mock.patch.object(cc.urllib.request, "urlopen",
                                 return_value=FakeResponse(body))

    def test_ok(self):
        with self._urlopen_returning(rdap_payload("2026-08-13T04:00:00Z")) as m:
            info = cc.check_rdap("example.com", warn_days=30, now=NOW)
        req = m.call_args.args[0]
        self.assertEqual(req.full_url, "https://rdap.org/domain/example.com")
        self.assertEqual(info.status, cc.OK)
        self.assertEqual(info.expiration, "2026-08-13T04:00:00Z")
        self.assertEqual(info.days_remaining, 224)
        self.assertIsNone(info.error)
        self.assertIn("verisign", info.rdap_url)

    def test_warning(self):
        with self._urlopen_returning(rdap_payload("2026-01-15T00:00:00Z")):
            info = cc.check_rdap("example.com", warn_days=30, now=NOW)
        self.assertEqual(info.status, cc.WARNING)
        self.assertEqual(info.days_remaining, 14)

    def test_expired(self):
        with self._urlopen_returning(rdap_payload("2025-12-01T00:00:00Z")):
            info = cc.check_rdap("example.com", warn_days=30, now=NOW)
        self.assertEqual(info.status, cc.EXPIRED)

    def test_no_expiration_event_is_unknown(self):
        with self._urlopen_returning(rdap_payload(exp_date=None)):
            info = cc.check_rdap("example.de", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)
        self.assertIsNone(info.expiration)
        self.assertIn("no expiration", info.error)

    def test_http_404_is_unknown(self):
        err = urllib.error.HTTPError("https://rdap.org/domain/x.zz", 404, "Not Found", {}, None)
        with mock.patch.object(cc.urllib.request, "urlopen", side_effect=err):
            info = cc.check_rdap("x.zz", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)
        self.assertIn("404", info.error)

    def test_subdomain_falls_back_to_parent(self):
        body = json.dumps(rdap_payload("2026-08-13T04:00:00Z")).encode()

        def fake_urlopen(req, timeout):
            if req.full_url.endswith("/www.example.com"):
                raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)
            return FakeResponse(body)

        with mock.patch.object(cc.urllib.request, "urlopen", side_effect=fake_urlopen) as m:
            info = cc.check_rdap("www.example.com", now=NOW)
        self.assertEqual(m.call_count, 2)
        self.assertEqual(m.call_args.args[0].full_url, "https://rdap.org/domain/example.com")
        self.assertEqual(info.status, cc.OK)

    def test_fallback_stops_at_two_labels(self):
        err = urllib.error.HTTPError("u", 404, "Not Found", {}, None)
        with mock.patch.object(cc.urllib.request, "urlopen", side_effect=err) as m:
            info = cc.check_rdap("a.b.example.zz", now=NOW)
        self.assertEqual(m.call_count, 3)  # a.b.example.zz, b.example.zz, example.zz
        self.assertEqual(info.status, cc.UNKNOWN)

    def test_http_500_is_unknown(self):
        err = urllib.error.HTTPError("u", 503, "Unavailable", {}, None)
        with mock.patch.object(cc.urllib.request, "urlopen", side_effect=err):
            info = cc.check_rdap("example.com", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)
        self.assertIn("503", info.error)

    def test_network_error_is_unknown(self):
        with mock.patch.object(cc.urllib.request, "urlopen",
                               side_effect=urllib.error.URLError("no route")):
            info = cc.check_rdap("example.com", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)
        self.assertIn("RDAP unavailable", info.error)

    def test_timeout_is_unknown(self):
        with mock.patch.object(cc.urllib.request, "urlopen", side_effect=TimeoutError()):
            info = cc.check_rdap("example.com", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)

    def test_invalid_json_is_unknown(self):
        with mock.patch.object(cc.urllib.request, "urlopen",
                               return_value=FakeResponse(b"<html>nope</html>")):
            info = cc.check_rdap("example.com", now=NOW)
        self.assertEqual(info.status, cc.UNKNOWN)
        self.assertIn("RDAP unavailable", info.error)


# ---------------------------------------------------------------------------
# Certificate parsing and check
# ---------------------------------------------------------------------------

class TestCertCheck(unittest.TestCase):
    def test_parse_peer_cert(self):
        parsed = cc.parse_peer_cert(make_peer_cert())
        self.assertEqual(parsed["subject_cn"], "example.com")
        self.assertEqual(parsed["issuer"], "Let's Encrypt / R3")
        self.assertEqual(parsed["sans"], ["example.com", "www.example.com"])
        self.assertEqual(parsed["not_after"], datetime(2026, 3, 1, 12, tzinfo=timezone.utc))

    def test_parse_peer_cert_missing_not_after(self):
        cert = make_peer_cert()
        del cert["notAfter"]
        with self.assertRaises(ValueError):
            cc.parse_peer_cert(cert)

    def test_check_cert_ok(self):
        with mock.patch.object(cc, "fetch_peer_cert",
                               return_value=(make_peer_cert(), True, None)) as m:
            info = cc.check_cert("example.com", warn_days=30, now=NOW)
        m.assert_called_once_with("example.com", 443, cc.DEFAULT_TIMEOUT)
        self.assertEqual(info.status, cc.OK)
        self.assertEqual(info.days_remaining, 59)
        self.assertEqual(info.not_after, "2026-03-01T12:00:00Z")
        self.assertTrue(info.verified)
        self.assertIsNone(info.error)

    def test_check_cert_warning(self):
        with mock.patch.object(cc, "fetch_peer_cert",
                               return_value=(make_peer_cert(), True, None)):
            info = cc.check_cert("example.com", warn_days=60, now=NOW)
        self.assertEqual(info.status, cc.WARNING)

    def test_check_cert_expired_unverified(self):
        cert = make_peer_cert("Dec  1 00:00:00 2025 GMT")
        with mock.patch.object(cc, "fetch_peer_cert",
                               return_value=(cert, False, "certificate has expired")):
            info = cc.check_cert("expired.example", now=NOW)
        self.assertEqual(info.status, cc.EXPIRED)
        self.assertFalse(info.verified)
        self.assertIn("certificate has expired", info.error)

    def test_check_cert_untrusted_but_valid_dates_is_error(self):
        with mock.patch.object(cc, "fetch_peer_cert",
                               return_value=(make_peer_cert(), False, "self-signed certificate")):
            info = cc.check_cert("self-signed.example", now=NOW)
        self.assertEqual(info.status, cc.ERROR)
        self.assertEqual(info.days_remaining, 59)

    def test_check_cert_connection_error(self):
        for exc in [socket_gaierror(), ConnectionRefusedError("refused"), TimeoutError(),
                    ssl.SSLError("handshake failure")]:
            with self.subTest(exc=type(exc).__name__):
                with mock.patch.object(cc, "fetch_peer_cert", side_effect=exc):
                    info = cc.check_cert("bad.invalid", now=NOW)
                self.assertEqual(info.status, cc.ERROR)
                self.assertTrue(info.error)


def socket_gaierror():
    import socket
    return socket.gaierror(-2, "Name or service not known")


# ---------------------------------------------------------------------------
# AIA chain completion
# ---------------------------------------------------------------------------

# Test-only certificates (EC P-256). The intermediate is signed by the root and
# carries AIA caIssuers http://ca.test/root.der and ldap://ca.test/root.
INT_PEM = """-----BEGIN CERTIFICATE-----
MIICMTCCAdegAwIBAgIUXIFl1A/0J8onTzVfJ3PfK5ATZ/kwCgYIKoZIzj0EAwIw
IzENMAsGA1UECgwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MCAXDTI2MTEyMzE1
MzEwMVoYDzIxMjYxMDMwMTUzMTAxWjArMQ0wCwYDVQQKDARUZXN0MRowGAYDVQQD
DBFUZXN0IEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEs1
Z+3Vomo2lxQByBks6jd6CV67kwkZajb8vxqeEivEUSy4cR9VdeyuSEqKzIdjVBUb
h1KwRMKGJ/W6maeUbACjgd4wgdswEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8B
Af8EBAMCAQYwdQYIKwYBBQUHAQEEaTBnMCMGCCsGAQUFBzAChhdodHRwOi8vY2Eu
dGVzdC9yb290LmRlcjAfBggrBgEFBQcwAoYTbGRhcDovL2NhLnRlc3Qvcm9vdDAf
BggrBgEFBQcwAYYTaHR0cDovL29jc3AuY2EudGVzdDAdBgNVHQ4EFgQUEtraq/vB
XZmDU2ltHfprp/ngsqwwHwYDVR0jBBgwFoAUwPmQ5VinFh9OmLpx3McXCLhPDycw
CgYIKoZIzj0EAwIDSAAwRQIhAJ3J5qj4KmAPi9e4ylpfj0QME7uPWhHaus+MJ0Kg
wL9mAiAjq79sDltgxqoPY1ZGAfKzvdWDJFNBF3rDsFS06wAfDA==
-----END CERTIFICATE-----
"""
ROOT_PEM = """-----BEGIN CERTIFICATE-----
MIIBnTCCAUOgAwIBAgIUa+0ipKDnfktSwHUmUVXp5QQlPHIwCgYIKoZIzj0EAwIw
IzENMAsGA1UECgwEVGVzdDESMBAGA1UEAwwJVGVzdCBSb290MCAXDTI2MTEyMzE1
MzEwMVoYDzIxMjYxMDMwMTUzMTAxWjAjMQ0wCwYDVQQKDARUZXN0MRIwEAYDVQQD
DAlUZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS65//i2txj9HHS
NpX8ftqRkinxmF6M7ywqzSr7XnJAkU95a2UtYRnKsRCRvczUSf5Ujn9nbSG+0gQc
3pYY7PEso1MwUTAdBgNVHQ4EFgQUwPmQ5VinFh9OmLpx3McXCLhPDycwHwYDVR0j
BBgwFoAUwPmQ5VinFh9OmLpx3McXCLhPDycwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAgNIADBFAiA1vMMuwOdeoYols+pBnfNNOSlkOQ6nm8E9AoVi0PX5LQIh
ANq1M5LJJs2TkqXb5wGfS3Jy64Z5cyINqT7L/IgG1CQc
-----END CERTIFICATE-----
"""
INT_DER = ssl.PEM_cert_to_DER_cert(INT_PEM)
ROOT_DER = ssl.PEM_cert_to_DER_cert(ROOT_PEM)
LEAF_DER = b"\x30fake-leaf-der"
LEAF_AIA = "http://ca.test/intermediate.crt"

_real_decode = cc._decode_der_cert


def leaf_with_aia(not_after="Mar  1 12:00:00 2026 GMT"):
    cert = make_peer_cert(not_after)
    cert["caIssuers"] = (LEAF_AIA,)
    return cert


def decode_leaf_or_real(der):
    return leaf_with_aia() if der == LEAF_DER else _real_decode(der)


def verify_error(code, message):
    exc = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] "
                                          f"certificate verify failed: {message}")
    exc.verify_code = code
    exc.verify_message = message
    return exc


def chain_error():
    return verify_error(20, "unable to get local issuer certificate")


class AiaResponse:
    def __init__(self, body: bytes):
        self._body = body

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class TestExtractCaIssuers(unittest.TestCase):
    def test_extracts_http_and_https_only(self):
        cert = {"caIssuers": ("http://a.test/ca.crt", "ldap://b.test/ca", "https://c.test/ca.der",
                              "file:///etc/passwd", "http://a.test/ca.crt", "  HTTP://d.test/x ")}
        self.assertEqual(cc.extract_ca_issuers(cert),
                         ["http://a.test/ca.crt", "https://c.test/ca.der", "HTTP://d.test/x"])

    def test_missing_or_malformed(self):
        for cert in [{}, {"caIssuers": None}, {"caIssuers": (1, None)}, None, "x"]:
            with self.subTest(cert=cert):
                self.assertEqual(cc.extract_ca_issuers(cert), [])

    def test_from_real_decoded_cert(self):
        decoded = _real_decode(INT_DER)
        self.assertEqual(cc.extract_ca_issuers(decoded), ["http://ca.test/root.der"])


class TestAiaDownload(unittest.TestCase):
    def test_der_converted_to_pem(self):
        pem = cc.cert_bytes_to_pem(INT_DER)
        self.assertTrue(pem.startswith("-----BEGIN CERTIFICATE-----"))
        self.assertEqual(ssl.PEM_cert_to_DER_cert(pem), INT_DER)

    def test_pem_accepted(self):
        pem = cc.cert_bytes_to_pem(b"junk before\n" + INT_PEM.encode() + ROOT_PEM.encode())
        self.assertEqual(ssl.PEM_cert_to_DER_cert(pem), INT_DER)  # first block only

    def test_garbage_rejected(self):
        for bad in [b"", b"<html>not a cert</html>", b"-----BEGIN CERTIFICATE-----\nabc"]:
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    cc.cert_bytes_to_pem(bad)

    def test_download_der(self):
        with mock.patch.object(cc, "_open_aia_url", return_value=AiaResponse(INT_DER)) as m:
            pem = cc.download_ca_issuer("http://ca.test/int.crt", timeout=3)
        m.assert_called_once_with("http://ca.test/int.crt", 3)
        self.assertEqual(ssl.PEM_cert_to_DER_cert(pem), INT_DER)

    def test_download_size_capped(self):
        big = INT_DER + b"\x00" * cc.AIA_MAX_BYTES
        with mock.patch.object(cc, "_open_aia_url", return_value=AiaResponse(big)):
            with self.assertRaises(ValueError):
                cc.download_ca_issuer("http://ca.test/int.crt")

    def test_non_http_scheme_not_fetched(self):
        with mock.patch.object(cc, "_open_aia_url") as m:
            with self.assertRaises(ValueError):
                cc.download_ca_issuer("file:///etc/passwd")
        m.assert_not_called()

    def test_aia_context_disables_partial_chain(self):
        ctx = cc._aia_context([INT_PEM])
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        partial = getattr(ssl, "VERIFY_X509_PARTIAL_CHAIN", 0)
        self.assertFalse(ctx.verify_flags & partial)


class TestIsChainError(unittest.TestCase):
    def test_chain_errors(self):
        for code, msg in [(20, "unable to get local issuer certificate"),
                          (21, "unable to verify the first certificate"),
                          (2, "unable to get issuer certificate"),
                          (19, "self-signed certificate in certificate chain"),
                          (None, "unable to get local issuer certificate")]:
            with self.subTest(code=code):
                self.assertTrue(cc.is_chain_error(verify_error(code, msg)))

    def test_non_chain_errors(self):
        for code, msg in [(62, "Hostname mismatch, certificate is not valid for 'x.test'."),
                          (10, "certificate has expired"),
                          (18, "self-signed certificate"),
                          (None, "Hostname mismatch, certificate is not valid for 'x'.")]:
            with self.subTest(code=code):
                self.assertFalse(cc.is_chain_error(verify_error(code, msg)))


class TestAiaFetchPeerCert(unittest.TestCase):
    """fetch_peer_cert / check_cert with all network I/O mocked."""

    def _patches(self, verify_side_effect, open_side_effect=None, open_return=None):
        return [
            mock.patch.object(cc, "_get_verified_cert", side_effect=verify_side_effect),
            mock.patch.object(cc, "_get_unverified_der", return_value=LEAF_DER),
            mock.patch.object(cc, "_decode_der_cert", side_effect=decode_leaf_or_real),
            mock.patch.object(cc, "_open_aia_url", side_effect=open_side_effect,
                              return_value=open_return),
        ]

    def _run(self, patches, fn):
        mocks = [p.start() for p in patches]
        try:
            return fn(), mocks
        finally:
            for p in patches:
                p.stop()

    def test_retry_success(self):
        verified_cert = leaf_with_aia("Dec 31 00:00:00 2026 GMT")
        patches = self._patches([chain_error(), verified_cert],
                                open_side_effect=lambda url, t: AiaResponse(INT_DER))
        result, (verify, _, _, opener) = self._run(
            patches, lambda: cc.fetch_peer_cert("example.com", 443, 7))
        cert, verified, err, note = result
        self.assertIs(cert, verified_cert)
        self.assertTrue(verified)
        self.assertIsNone(err)
        self.assertIn(cc.AIA_NOTE, note)
        opener.assert_called_once_with(LEAF_AIA, 7)
        self.assertEqual(verify.call_count, 2)
        retry_ctx = verify.call_args.args[3]
        self.assertTrue(retry_ctx.check_hostname)  # hostname still verified on retry
        self.assertEqual(verify.call_args.args[:3], ("example.com", 443, 7))

    def test_check_cert_reports_verified_with_note(self):
        patches = self._patches([chain_error(), make_peer_cert()],
                                open_side_effect=lambda url, t: AiaResponse(INT_PEM.encode()))
        info, _ = self._run(patches, lambda: cc.check_cert("example.com", now=NOW))
        self.assertEqual(info.status, cc.OK)
        self.assertTrue(info.verified)
        self.assertIsNone(info.error)
        self.assertIn(cc.AIA_NOTE, info.note)

    def test_aia_success_still_reports_expiry_status(self):
        patches = self._patches([chain_error(), make_peer_cert()],
                                open_side_effect=lambda url, t: AiaResponse(INT_DER))
        info, _ = self._run(patches, lambda: cc.check_cert("example.com", warn_days=60, now=NOW))
        self.assertEqual(info.status, cc.WARNING)
        self.assertTrue(info.verified)

    def test_fetch_failure_falls_back_to_original_error(self):
        for exc in [urllib.error.URLError("no route"), TimeoutError(), OSError("boom")]:
            with self.subTest(exc=type(exc).__name__):
                patches = self._patches([chain_error()], open_side_effect=exc)
                info, (verify, _, _, opener) = self._run(
                    patches, lambda: cc.check_cert("example.com", now=NOW))
                self.assertEqual(info.status, cc.ERROR)
                self.assertFalse(info.verified)
                self.assertIn("unable to get local issuer certificate", info.error)
                self.assertIsNone(info.note)
                self.assertEqual(info.days_remaining, 59)  # expiry still shown
                self.assertEqual(verify.call_count, 1)

    def test_unparseable_download_falls_back(self):
        patches = self._patches([chain_error()],
                                open_side_effect=lambda url, t: AiaResponse(b"<html>404</html>"))
        result, (verify, *_) = self._run(patches, lambda: cc.fetch_peer_cert("example.com"))
        self.assertEqual(result[1:], (False, "unable to get local issuer certificate"))
        self.assertEqual(verify.call_count, 1)

    def test_retry_still_failing_falls_back(self):
        # INT's caIssuers points to the self-signed root, which must not be loaded.
        def fake_open(url, timeout):
            return AiaResponse(INT_DER if url == LEAF_AIA else ROOT_DER)

        patches = self._patches([chain_error(), chain_error()], open_side_effect=fake_open)
        result, (verify, _, _, opener) = self._run(
            patches, lambda: cc.fetch_peer_cert("example.com"))
        self.assertEqual(result[1:], (False, "unable to get local issuer certificate"))
        self.assertEqual(verify.call_count, 2)
        self.assertEqual([c.args[0] for c in opener.call_args_list],
                         [LEAF_AIA, "http://ca.test/root.der"])

    def test_follows_at_most_three_intermediates(self):
        counter = iter(range(100))

        def fake_decode(der):
            if der == LEAF_DER:
                return leaf_with_aia()
            n = next(counter)
            return {"subject": ((("commonName", f"I{n}"),),),
                    "issuer": ((("commonName", f"I{n + 1}"),),),
                    "caIssuers": (f"http://ca.test/{n + 1}.crt",)}

        def always_chain_error(*args):
            raise chain_error()

        with mock.patch.object(cc, "_get_verified_cert",
                               side_effect=always_chain_error) as verify, \
             mock.patch.object(cc, "_get_unverified_der", return_value=LEAF_DER), \
             mock.patch.object(cc, "_decode_der_cert", side_effect=fake_decode), \
             mock.patch.object(cc, "_open_aia_url",
                               side_effect=lambda u, t: AiaResponse(INT_DER)) as opener:
            result = cc.fetch_peer_cert("example.com")
        self.assertFalse(result[1])
        self.assertEqual(opener.call_count, 3)
        self.assertEqual(verify.call_count, 1 + 3)

    def test_retry_reveals_more_specific_error(self):
        patches = self._patches([chain_error(), verify_error(10, "certificate has expired")],
                                open_side_effect=lambda url, t: AiaResponse(INT_DER))
        result, _ = self._run(patches, lambda: cc.fetch_peer_cert("example.com"))
        self.assertEqual(result[1:], (False, "certificate has expired"))

    def test_hostname_mismatch_not_retried(self):
        err = verify_error(62, "Hostname mismatch, certificate is not valid for 'example.com'.")
        patches = self._patches([err])
        info, (verify, _, _, opener) = self._run(
            patches, lambda: cc.check_cert("example.com", now=NOW))
        opener.assert_not_called()
        self.assertEqual(verify.call_count, 1)
        self.assertEqual(info.status, cc.ERROR)
        self.assertIn("Hostname mismatch", info.error)
        self.assertIsNone(info.note)

    def test_self_signed_and_expired_not_retried(self):
        for code, msg, status in [(18, "self-signed certificate", cc.ERROR),
                                  (10, "certificate has expired", cc.ERROR)]:
            with self.subTest(msg=msg):
                patches = self._patches([verify_error(code, msg)])
                info, (verify, _, _, opener) = self._run(
                    patches, lambda: cc.check_cert("example.com", now=NOW))
                opener.assert_not_called()
                self.assertEqual(verify.call_count, 1)
                self.assertEqual(info.status, status)
                self.assertFalse(info.verified)

    def test_note_in_table_and_json(self):
        r = cc.CheckResult(domain="example.com", status=cc.OK)
        r.cert = cc.CertInfo(status=cc.OK, verified=True, note="chain completed via AIA")
        self.assertIn("cert: chain completed via AIA", cc.format_table([r]))
        self.assertEqual(r.to_dict()["cert"]["note"], "chain completed via AIA")
        self.assertIn("error", r.to_dict()["cert"])


# ---------------------------------------------------------------------------
# Orchestration, input parsing, exit codes, CLI
# ---------------------------------------------------------------------------

class TestInputParsing(unittest.TestCase):
    def test_parse_domain_lines(self):
        lines = ["# header comment\n", "\n", "example.com\n", "  google.com  # inline\n",
                 "   \n", "#commented.out\n", "test.org"]
        self.assertEqual(cc.parse_domain_lines(lines),
                         ["example.com", "google.com", "test.org"])

    def test_example_file(self):
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                            "domains.example.txt")
        self.assertEqual(cc.read_domain_file(path), ["example.com", "google.com"])

    def test_normalize_target(self):
        cases = {
            "example.com": ("example.com", 443),
            "  Example.COM. ": ("example.com", 443),
            "https://example.com/path?q=1": ("example.com", 443),
            "example.com:8443": ("example.com", 8443),
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(cc.normalize_target(raw), expected)
        with self.assertRaises(ValueError):
            cc.normalize_target("https://")


class TestCheckDomainAndExitCodes(unittest.TestCase):
    def test_check_domain_combines(self):
        cert = cc.CertInfo(status=cc.OK, days_remaining=100)
        reg = cc.DomainInfo(status=cc.WARNING, days_remaining=5)
        with mock.patch.object(cc, "check_cert", return_value=cert), \
             mock.patch.object(cc, "check_rdap", return_value=reg):
            result = cc.check_domain("example.com")
        self.assertEqual(result.status, cc.WARNING)

    def test_check_domain_invalid_target(self):
        result = cc.check_domain("https://")
        self.assertEqual(result.status, cc.ERROR)

    def test_one_bad_domain_does_not_stop_others(self):
        def fake_fetch(host, port, timeout):
            if host == "bad.invalid":
                raise OSError("boom")
            return make_peer_cert("Dec 31 00:00:00 2099 GMT"), True, None

        with mock.patch.object(cc, "fetch_peer_cert", side_effect=fake_fetch), \
             mock.patch.object(cc, "fetch_rdap",
                               return_value=(rdap_payload("2099-01-01T00:00:00Z"), "u")):
            results = cc.check_all(["example.com", "bad.invalid", "google.com"])
        self.assertEqual([r.domain for r in results],
                         ["example.com", "bad.invalid", "google.com"])
        self.assertEqual([r.status for r in results], [cc.OK, cc.ERROR, cc.OK])
        self.assertEqual(cc.exit_code_for(results), cc.EXIT_ERROR)

    def _result(self, cert_status, reg_status=cc.OK):
        r = cc.CheckResult(domain="x.com")
        r.cert.status = cert_status
        r.registration.status = reg_status
        r.status = cc.combine_status(cert_status, reg_status)
        return r

    def test_exit_codes(self):
        self.assertEqual(cc.exit_code_for([]), 0)
        self.assertEqual(cc.exit_code_for([self._result(cc.OK)]), 0)
        self.assertEqual(cc.exit_code_for([self._result(cc.OK, cc.UNKNOWN)]), 0)
        self.assertEqual(cc.exit_code_for([self._result(cc.ERROR)]), 1)
        self.assertEqual(cc.exit_code_for([self._result(cc.WARNING)]), 2)
        self.assertEqual(cc.exit_code_for([self._result(cc.OK, cc.EXPIRED)]), 2)
        # warning takes precedence over errors
        self.assertEqual(cc.exit_code_for([self._result(cc.ERROR),
                                           self._result(cc.WARNING)]), 2)
        self.assertEqual(cc.exit_code_for([self._result(cc.ERROR, cc.WARNING)]), 2)


class TestCli(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cc.main(argv)
        return code, out.getvalue(), err.getvalue()

    def _patched(self, cert_date="Dec 31 00:00:00 2099 GMT", rdap_date="2099-01-01T00:00:00Z"):
        return (
            mock.patch.object(cc, "fetch_peer_cert",
                              return_value=(make_peer_cert(cert_date), True, None)),
            mock.patch.object(cc, "fetch_rdap",
                              return_value=(rdap_payload(rdap_date), "u")),
        )

    def test_table_output_ok(self):
        p1, p2 = self._patched()
        with p1, p2:
            code, out, _ = self._run(["example.com", "google.com"])
        self.assertEqual(code, 0)
        self.assertIn("DOMAIN", out)
        self.assertIn("example.com", out)
        self.assertIn("Checked 2 domain(s): 2 OK", out)

    def test_json_output_and_warning_exit(self):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).strftime("%b %d %H:%M:%S %Y GMT")
        p1, p2 = self._patched(cert_date=soon)
        with p1, p2:
            code, out, err = self._run(["--json", "--warn-days", "30", "example.com"])
        self.assertEqual(code, 2)
        data = json.loads(out)
        self.assertEqual(data["results"][0]["status"], cc.WARNING)
        self.assertEqual(data["results"][0]["cert"]["sans"], ["example.com", "www.example.com"])
        self.assertEqual(data["exit_code"], 2)
        self.assertIn("1 WARNING", err)

    def test_file_input(self):
        p1, p2 = self._patched()
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                            "domains.example.txt")
        with p1, p2:
            code, out, _ = self._run(["--file", path])
        self.assertEqual(code, 0)
        self.assertIn("google.com", out)

    def test_missing_file(self):
        code, _, err = self._run(["--file", "/nonexistent/domains.txt"])
        self.assertEqual(code, 1)
        self.assertIn("cannot read", err)

    def test_no_domains_is_usage_error(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run([])
        self.assertEqual(ctx.exception.code, 2)


class TestCreateVerifyContext(unittest.TestCase):
    def test_returns_ssl_context(self):
        ctx = cc.create_verify_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_fallback_without_truststore(self):
        with mock.patch.object(cc, "_truststore", None):
            ctx = cc.create_verify_context()
        self.assertIsInstance(ctx, ssl.SSLContext)
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)

    def test_uses_truststore_when_available(self):
        if cc._truststore is None:
            self.skipTest("truststore is not installed")
        ctx = cc.create_verify_context()
        self.assertIsInstance(ctx, cc._truststore.SSLContext)


if __name__ == "__main__":
    unittest.main()
