from src import db


def test_save_and_history(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "t.db"))
    db.init_db()
    db.save_scan("http://a.com/x", 0.9, "phishing", "1.0.0", {"url_length": 1})
    db.save_scan("https://google.com", 0.1, "legitimate", "1.0.0", {})
    assert len(db.history()) == 2
    suspicious = db.history(suspicious_only=True)
    assert len(suspicious) == 1
    assert suspicious[0]["domain"] == "a.com"


def test_suspicious_includes_to_check(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_DB", str(tmp_path / "t.db"))
    db.init_db()
    db.save_scan("https://a.com", 0.35, "legitimate", "1.0.0", {}, "medium")
    db.save_scan("https://b.com", 0.05, "legitimate", "1.0.0", {}, "low")
    assert [s["domain"] for s in db.history(suspicious_only=True)] == ["a.com"]
