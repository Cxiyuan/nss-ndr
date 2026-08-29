import fakeredis.aioredis
import pytest

from app.config import AgentConfig, ProviderConfig
from app.storage.redis_store import RedisStore


@pytest.fixture
def config() -> AgentConfig:
    cfg = AgentConfig()
    cfg.providers = {
        "edge": ProviderConfig(name="edge", base_url="http://edge.local", api_key=None, model="xlam-2-1b"),
        "cloud": ProviderConfig(name="cloud", base_url="http://cloud.local", api_key="sk-x", model="cloud-hq"),
    }
    return cfg


@pytest.fixture
def redis_store() -> RedisStore:
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return RedisStore(client, result_ttl=3600, evt_ttl=86400, entity_ttl=86400, lock_ttl=30)


@pytest.fixture
def events_ssh_bruteforce():
    from app.schemas.event import EventEnvelope

    events = []
    for i in range(25):
        events.append(
            EventEnvelope(
                event_id=f"e{i}",
                ts="2026-08-29T10:00:00Z",
                src_ip="10.0.0.30",
                src_port=str(40000 + i),
                dst_ip="10.0.0.10",
                dst_port="22",
                proto="tcp",
                dataset="zeek.connection",
                enriched={"conn_state": "REJ" if i % 2 else "SF"},
            )
        )
    return events
