from src.features import extract_features, normalize_url


def test_normalize_adds_scheme_lowercase_and_strips_fragment():
    assert normalize_url("  Example.COM/Path#frag ") == "http://example.com/path"


def test_normalize_keeps_existing_scheme():
    assert normalize_url("https://a.com").startswith("https://")


def test_www_is_not_a_subdomain():
    assert extract_features("https://www.google.com")["num_subdomains"] == 0


def test_real_subdomain_is_counted():
    assert extract_features("https://mail.google.com")["num_subdomains"] == 1


def test_ip_address_detected():
    assert extract_features("http://192.168.1.15/login.php")["has_ip"] == 1
    assert extract_features("https://google.com")["has_ip"] == 0


def test_at_symbol_counted():
    assert extract_features("http://a.com@evil.com")["num_at"] == 1


def test_suspicious_words_and_risky_tld():
    f = extract_features("http://paypal-secure-login.verify-account.xyz/signin")
    assert f["num_suspicious_words"] >= 3
    assert f["risky_tld"] == 1


def test_clean_url_has_no_suspicious_signals():
    f = extract_features("https://google.com")
    assert f["num_suspicious_words"] == 0
    assert f["risky_tld"] == 0
    assert f["num_hyphens"] == 0
