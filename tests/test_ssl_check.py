from datetime import UTC, datetime

import pytest

from src.ssl_check import BlockedHost, check_certificate, parse_cert, public_addresses

NOW = datetime(2026, 10, 20, tzinfo=UTC)


@pytest.mark.parametrize("host", [
    "127.0.0.1", "localhost", "192.168.1.15", "10.0.0.1",
    "172.16.0.5", "169.254.169.254", "::1",
])
def test_non_public_hosts_are_blocked(host):
    with pytest.raises(BlockedHost):
        public_addresses(host)


def test_public_ip_is_allowed():
    assert public_addresses("8.8.8.8") == ["8.8.8.8"]


def test_check_certificate_refuses_internal_address():
    result = check_certificate("http://192.168.1.15/bank/login.php")
    assert result["status"] == "blocked"
    assert check_certificate("https://localhost:8000")["status"] == "blocked"


def test_check_certificate_rejects_empty_url():
    assert check_certificate("")["status"] == "error"


def _cert(not_before, not_after):
    return {
        "notBefore": not_before,
        "notAfter": not_after,
        "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
    }


def test_parse_cert_old_certificate_has_no_warning():
    info = parse_cert(_cert("Aug  1 00:00:00 2026 GMT", "Dec  1 00:00:00 2026 GMT"), NOW)
    assert info["issuer"] == "Let's Encrypt"
    assert info["warnings"] == []
    assert info["age_days"] == 80
    assert info["days_left"] == 42


def test_parse_cert_young_certificate_is_flagged():
    info = parse_cert(_cert("Oct 18 00:00:00 2026 GMT", "Jan 16 00:00:00 2027 GMT"), NOW)
    assert any("seulement" in w for w in info["warnings"])


def test_parse_cert_expiring_soon_is_flagged():
    info = parse_cert(_cert("Jul  1 00:00:00 2026 GMT", "Oct 23 00:00:00 2026 GMT"), NOW)
    assert any("expire" in w for w in info["warnings"])
