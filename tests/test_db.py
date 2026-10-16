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
