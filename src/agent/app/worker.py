"""常驻 Worker（设计文档 §3、§9）：消费组批量拉取 → 会话分组 → 图执行 → XACK。"""

from __future__ import annotations

import asyncio
from collections import defaultdict

import redis.asyncio as aioredis
import structlog
from elasticsearch import AsyncElasticsearch

from app.alerting import AlertStore
from app.assets import AssetKB
from app.baseline import BaselineConfig, BaselineEngine
from app.config import AgentConfig, load_config
from app.mcp import MCPClient
from app.mcp.tools import build_tools
from app.observability import Metrics, TraceContext
from app.pipeline.graph import build_graph
from app.pipeline.nodes import Nodes
from app.prompts import PromptBuilder
from app.providers import ModelGateway, OpenAICompatProvider
from app.rules import RuleEngine
from app.schemas.event import EventEnvelope, event_from_stream
from app.schemas.keys import session_key
from app.skills import SkillLoader
from app.storage.es_store import ESStore
from app.storage.redis_store import RedisStore

log = structlog.get_logger("agent.worker")


class AgentWorker:
    def __init__(self, config: AgentConfig):
        self.config = config
        self.metrics = Metrics()
        self.skills = SkillLoader(config.skills_dir)
        self.assets = AssetKB(config.asset_seed_file)
        self.prompts = PromptBuilder(config.prompts_dir)
        self.redis_client = aioredis.from_url(
            config.redis_url,
            password=config.redis_password or None,
            decode_responses=True,
        )
        self.redis = RedisStore(
            self.redis_client,
            stream=config.stream,
            consumer_group=config.consumer_group,
            consumer_name=config.consumer_name,
            result_ttl=config.result_ttl,
            evt_ttl=config.evt_ttl,
            entity_ttl=config.entity_ttl,
            lock_ttl=config.lock_ttl,
        )
        es_client = None
        if config.es_hosts:
            es_client = AsyncElasticsearch(
                config.es_hosts,
                basic_auth=(config.es_username, config.es_password) if config.es_password else None,
            )
        self.es = ESStore(es_client, {"verdict": config.verdict_index, "asset": config.asset_index, "alert": config.alert_index})
        self.engine = RuleEngine(rules_dir=config.rules_dir)
        providers = {
            name: OpenAICompatProvider(pcfg) for name, pcfg in config.providers.items()
        }
        self.gateway = ModelGateway(config, providers)
        registry = build_tools(self.es, self.redis)
        self.mcp = MCPClient(registry)
        self.alerts = AlertStore(self.es, config.webhook_url, config.dry_run)
        self.nodes = Nodes(
            config,
            self.redis,
            self.es,
            self.engine,
            self.gateway,
            self.mcp,
            self.alerts,
            self.prompts,
            baseline=BaselineEngine(BaselineConfig.from_dict(config.baseline)) if (config.baseline or {}).get("enabled", True) else None,
        )
        # v1 不启用图 Checkpoint：崩溃恢复由 XAUTOCLAIM 事件级重投保证；
        # 图级 Checkpoint（Redis 持久化）作为后续演进项（TODO M2.5）。
        self.graph = build_graph(self.nodes)
        self._stop = asyncio.Event()

    async def start(self) -> None:
        """校验依赖并确保消费组存在（索引/ILM 由 setup 阶段负责）。"""
        if not await self.redis.ping():
            log.warning("redis unreachable, worker will retry")
        try:
            await self.redis.ensure_group()
        except Exception as e:  # noqa: BLE001
            log.warning("consumer group ensure failed", error=str(e))

    async def stop(self) -> None:
        self._stop.set()

    def _parse(self, entry_id: str, fields: dict) -> EventEnvelope | None:
        try:
            return event_from_stream(fields)
        except Exception as e:  # noqa: BLE001
            log.warning("bad event", entry_id=entry_id, error=str(e))
            return None

    async def _process_session(self, sess: str, events: list[EventEnvelope], entry_ids: list[str]) -> None:
        token = None
        for _ in range(self.config.lock_retries):
            token = await self.redis.acquire_lock(sess)
            if token:
                break
            await asyncio.sleep(0.2)
        if not token:
            self.metrics.inc("session.lock_busy")
            return
        try:
            trace_id = TraceContext.set()
            unit_proto = events[0].proto if events else ""
            pre_hits = self.engine.evaluate(events)
            behavior_hint = [h.behavior_id for h in pre_hits.get(sess, [])]
            skill_text = self.skills.load_for(behavior_hint, unit_proto)
            asset_context = self.assets.context_for([events[0].src_ip, events[0].dst_ip] if events else [])
            state = {
                "session_key": sess,
                "events": events,
                "trace_id": trace_id,
                "provider": self.config.default_provider,
                "messages": [],
                "tool_calls_made": 0,
                "asset_context": asset_context,
                "skill": skill_text,
            }
            with self.metrics.time("session.graph"):
                result = await self.graph.ainvoke(state)
            reused = bool(result.get("reused"))
            final = result.get("final")
            if reused:
                self.metrics.inc("cache.hit")
                log.info("verdict_reused", sess=sess, trace_id=trace_id)
            if final is not None:
                log.info(
                    "verdict",
                    sess=sess,
                    trace_id=trace_id,
                    verdict=final.verdict,
                    risk=final.risk_level,
                    reused=reused,
                    behavior=final.behavior_hits,
                )
                self.metrics.inc("verdict.total")
                self.metrics.inc(f"verdict.risk.{final.risk_level}")
                self.metrics.inc("cache.miss")
            # 处理成功后才打已处理标记 + XACK（设计文档：XACK 在写回成功后才执行）。
            # dry_run=只读模式：消费并推进水位，但结论/告警写回仍被 nodes/alerts 跳过。
            if entry_ids:
                for ev in events:
                    await self.redis.mark_event_seen(ev.event_id)
                await self.redis.ack(entry_ids)
            return True
        except Exception as e:  # noqa: BLE001
            log.exception("session processing failed", sess=sess, error=str(e))
            return False
        finally:
            await self.redis.release_lock(sess, token)
            TraceContext.reset()

    async def run_once(self) -> int:
        """拉取一批并处理，返回处理条数（测试/一次性模式用）。"""
        try:
            stale = await self.redis.claim_stale(60000, self.config.max_pending_claim)
            entries = stale + await self.redis.read_batch(self.config.batch_size, block_ms=2000)
        except Exception as e:  # noqa: BLE001
            log.warning("redis unavailable", error=str(e))
            return 0
        if not entries:
            return 0
        groups: dict[str, tuple[list[EventEnvelope], list[str]]] = defaultdict(lambda: ([], []))
        for entry_id, fields in entries:
            ev = self._parse(entry_id, fields)
            if ev is None:
                continue
            sess = session_key(ev.src_ip, ev.dst_ip, ev.dst_port, ev.proto)
            groups[sess][0].append(ev)
            groups[sess][1].append(entry_id)
        self.metrics.inc("events.received", len(entries))
        self.metrics.inc("sessions.batch", len(groups))
        if self.config.dry_run:
            log.info("dry_run batch", sessions=len(groups), events=len(entries))
        for sess, (events, ids) in groups.items():
            await self._process_session(sess, events, ids)
        return len(entries)

    async def run_forever(self) -> None:
        await self.start()
        log.info("worker started", stream=self.config.stream, group=self.config.consumer_group)
        while not self._stop.is_set():
            try:
                processed = await self.run_once()
                if not processed:
                    await asyncio.wait_for(self._stop.wait(), timeout=self.config.idle_poll_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:  # noqa: BLE001
                log.exception("worker loop error", error=str(e))
                await asyncio.sleep(self.config.idle_poll_seconds)
        await self.redis_client.aclose()

    async def close(self) -> None:
        await self.redis_client.aclose()
        for p in self.gateway.providers.values():
            if isinstance(p, OpenAICompatProvider):
                await p.close()


def run_worker(config: AgentConfig | None = None) -> None:
    cfg = config or load_config()
    worker = AgentWorker(cfg)
    try:
        asyncio.run(worker.run_forever())
    except KeyboardInterrupt:
        pass
