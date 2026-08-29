from app.config import load_config


def test_load_config_resolves_env(monkeypatch):
    monkeypatch.setenv("EDGE_LLM_BASE_URL", "http://edge:8000")
    monkeypatch.setenv("EDGE_LLM_API_KEY", "k1")
    monkeypatch.setenv("EDGE_LLM_MODEL", "xlam-2-1b-fc-r")
    monkeypatch.setenv("CLOUD_LLM_BASE_URL", "http://cloud:9000")
    monkeypatch.setenv("CLOUD_LLM_API_KEY", "k2")
    monkeypatch.setenv("CLOUD_LLM_MODEL", "deepseek-v3")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6390/0")

    cfg = load_config()
    assert cfg.stream == "analysis:events"
    assert cfg.consumer_group == "analysis-group"
    assert cfg.redis_url == "redis://localhost:6390/0"
    assert cfg.providers["edge"].base_url == "http://edge:8000"
    assert cfg.providers["edge"].model == "xlam-2-1b-fc-r"
    assert cfg.providers["cloud"].model == "deepseek-v3"
