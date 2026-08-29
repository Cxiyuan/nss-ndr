import pytest


@pytest.mark.asyncio
async def test_stream_group_read_ack(redis_store):
    await redis_store.ensure_group()
    await redis_store.client.xadd("analysis:events", {"event_id": "e1", "ts": "2026-08-29T10:00:00Z", "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2"})
    entries = await redis_store.read_batch(10, block_ms=100)
    assert len(entries) == 1
    assert entries[0][1]["event_id"] == "e1"
    await redis_store.ack([entries[0][0]])
    assert await redis_store.read_batch(10, block_ms=100) == []


@pytest.mark.asyncio
async def test_write_verdict_lua_atomic(redis_store):
    old = await redis_store.write_verdict("sess:a:b:443:tcp", '{"verdict":"benign","watermark":{"event_count":1}}', ttl=60)
    assert old == ""
    old2 = await redis_store.write_verdict("sess:a:b:443:tcp", '{"verdict":"suspicious","watermark":{"event_count":2}}', ttl=60)
    assert "benign" in old2
    result = await redis_store.get_result("sess:a:b:443:tcp")
    assert result["verdict"] == "suspicious"
    ttl = await redis_store.client.ttl("agent:result:sess:a:b:443:tcp")
    assert 0 < ttl <= 60


@pytest.mark.asyncio
async def test_event_dedup(redis_store):
    assert await redis_store.mark_event_seen("ev1") is True
    assert await redis_store.mark_event_seen("ev1") is False


@pytest.mark.asyncio
async def test_lock(redis_store):
    token = await redis_store.acquire_lock("sess:1:2:80:tcp")
    assert token is not None
    assert await redis_store.acquire_lock("sess:1:2:80:tcp") is None
    await redis_store.release_lock("sess:1:2:80:tcp", token)
    assert await redis_store.acquire_lock("sess:1:2:80:tcp") is not None


@pytest.mark.asyncio
async def test_entity_profile_rolling(redis_store):
    for i in range(60):
        await redis_store.append_entity("10.0.0.1", {"ts": i}, max_entries=50)
    profile = await redis_store.get_entity("10.0.0.1")
    assert len(profile) == 50
