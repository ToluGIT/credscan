"""SSRF-hardening tests for WebScanner.

The URL scanner is reachable from the GUI, so it must not be turnable into a
probe of the host's internal network. These tests verify the destination guard
and that redirects to internal hosts are refused mid-chain (the one-shot
pre-flight check in the GUI cannot catch a redirect or DNS rebind; the scanner
defends itself when block_private_addresses is set).
"""

from unittest import mock

import pytest

from credscan.web.scanner import WebScanner, destination_blocked


class TestDestinationBlocked:
    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://127.0.0.1:6379/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "ftp://example.com/",
            "file:///etc/passwd",
        ],
    )
    def test_internal_targets_blocked(self, url):
        assert destination_blocked(url) is not None

    def test_public_host_allowed(self):
        # example.com resolves to public space; the guard returns None (allowed).
        assert destination_blocked("http://example.com/") is None


class TestRedirectSsrf:
    def test_redirect_to_internal_is_refused(self):
        scanner = WebScanner({"block_private_addresses": True})

        # First hop: a public URL that 302-redirects to a loopback address.
        redirect_resp = mock.Mock()
        redirect_resp.is_redirect = True
        redirect_resp.status_code = 302
        redirect_resp.headers = {"Location": "http://127.0.0.1:6379/"}

        with mock.patch(
            "credscan.web.scanner.requests.get", return_value=redirect_resp
        ) as g:
            # destination_blocked passes the first public URL but must refuse the
            # internal redirect target, so no findings come back.
            findings = scanner.scan_url("http://example.com/bounce")

        assert findings == []
        # The internal target must never have been fetched.
        fetched = [c.args[0] for c in g.call_args_list]
        assert all("127.0.0.1" not in u for u in fetched)

    def test_redirects_disabled_on_the_request(self):
        scanner = WebScanner({"block_private_addresses": True})
        resp = mock.Mock()
        resp.is_redirect = False
        resp.status_code = 200
        resp.text = "nothing here"
        with mock.patch("credscan.web.scanner.requests.get", return_value=resp) as g:
            scanner.scan_url("http://example.com/app.js")
        # Hardened fetch must not let requests auto-follow redirects.
        assert g.call_args.kwargs.get("allow_redirects") is False
