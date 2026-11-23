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


if __name__ == "__main__":
    unittest.main()
