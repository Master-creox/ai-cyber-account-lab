from src.phishing_detector import assess_url


def test_normal_https_site_has_low_risk():
    result = assess_url("https://github.com/Master-creox")
    assert not result.is_suspicious


def test_ip_address_login_link_is_suspicious():
    result = assess_url("http://192.168.1.10/login@secure-verify-account.example.com/confirm")
    assert result.is_suspicious
    assert result.reasons
