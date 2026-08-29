from app.schemas.keys import (
    agent_entity_key,
    alert_fingerprint,
    evt_key,
    normalize_ip,
    session_key,
)


def test_session_key_v4():
    assert session_key("10.0.0.1", "10.0.0.2", "443", "tcp") == "sess:10.0.0.1:10.0.0.2:443:tcp"


def test_session_key_v6_hashed():
    v6 = "2001:db8::1"
    key = session_key(v6, "10.0.0.2", "443", "tcp")
    assert key.startswith("sess:v6_")
    assert ":" not in key.replace("sess:", "") or len(key) > 20
    # 同一 IPv6 两次生成键一致
    assert key == session_key(v6, "10.0.0.2", "443", "tcp")


def test_normalize_ip():
    assert normalize_ip("1.2.3.4") == "1.2.3.4"
    assert normalize_ip("2001:db8::1").startswith("v6_")


def test_keys():
    assert evt_key("abc") == "evt:abc"
    assert agent_entity_key("10.0.0.1") == "agent:entity:10.0.0.1"
    fp1 = alert_fingerprint("sess:a", "benign", ["BEH-001"])
    fp2 = alert_fingerprint("sess:a", "benign", ["BEH-001"])
    fp3 = alert_fingerprint("sess:a", "benign", ["BEH-002"])
    assert fp1 == fp2
    assert fp1 != fp3
