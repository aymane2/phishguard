from src.risk import risk_level


def test_high_above_threshold():
    assert risk_level(0.80, 0.45) == "high"
    assert risk_level(0.45, 0.45) == "high"


def test_medium_just_below_threshold():
    assert risk_level(0.35, 0.45) == "medium"


def test_low_far_below_threshold():
    assert risk_level(0.10, 0.45) == "low"
    assert risk_level(0.29, 0.45) == "low"


def test_brand_alert_raises_low_to_medium():
    assert risk_level(0.10, 0.45, {"brand": "paypal"}) == "medium"
    assert risk_level(0.10, 0.45, None) == "low"
