import pytest

from src.brands import check_brand


@pytest.mark.parametrize("url", [
    "https://www.paypal.com/signin",
    "https://mail.google.com/mail/u/0/",
    "https://aws.amazon.com",
    "https://s3.amazonaws.com/fichier",
    "https://www.pineapple.com",
    "https://stream.com",
    "https://www.lemonde.fr",
    "http://192.168.1.15/bank/login.php",
])
def test_no_alert_on_legit_urls(url):
    assert check_brand(url) is None


@pytest.mark.parametrize("url, brand, kind", [
    ("http://paypal-secure-login.verify-account.xyz/signin", "paypal", "brand_in_subdomain"),
    ("https://amazon.fr.account-update.top/ap/signin", "amazon", "brand_in_subdomain"),
    ("https://paypal.xyz", "paypal", "brand_in_domain"),
    ("http://paypa1.com/login", "paypal", "typosquatting"),
    ("https://g00gle.com", "google", "typosquatting"),
])
def test_alert_on_impersonation(url, brand, kind):
    alert = check_brand(url)
    assert alert is not None
    assert alert["brand"] == brand
    assert alert["kind"] == kind
