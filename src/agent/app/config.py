"""配置加载：agent.yaml + providers.yaml + 环境变量/.env。

设计文档 §15.1：智能体不感知 LLM 运行环境，全部通过配置声明。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv


def _env_file_path() -> Path:
    """复用数据总线 /etc/nss-ndr/.env 键名；本地开发读项目根 .env。"""
    for p in (Path(os.getenv("NSS_ENV_FILE", "/etc/nss-ndr/.env")), Path(".env")):
        if p.exists():
            return p
    return Path(".env")


@dataclass
class ProviderConfig:
    name: str
    base_url: str
    api_key: str | None
    model: str
    max_context: int = 32768
    capabilities: dict[str, bool] = field(
        default_factory=lambda: {
            "tool_calling": True,
            "json_schema": True,
            "streaming": False,
        }
    )
    weight: float = 1.0
    # 配额 / 熔断
    quota: dict[str, Any] = field(default_factory=lambda: {"hourly_tokens": 0, "daily_tokens": 0})
    circuit_breaker: dict[str, Any] = field(
        # 修复：原 max_consecutive_failures=5 允许连续 5 次失败才熔断，
        # 期间 llama.cpp 占满 CPU；降到 2 次立即熔断，给其它 session 留 CPU
        default_factory=lambda: {"max_consecutive_failures": 2, "cooldown_seconds": 30}
    )


@dataclass
class AgentConfig:
    """agent.yaml 与 providers.yaml 合并后的运行时配置。"""

    # 数据总线对接
    redis_url: str = "redis://localhost:6379/0"
    redis_password: str | None = None
    es_hosts: list[str] = field(default_factory=lambda: ["http://localhost:9200"])
    es_username: str = "elastic"
    es_password: str | None = None
    stream: str = "analysis:events"
    consumer_group: str = "analysis-group"
    consumer_name: str = "agent-worker"

    # Worker 批处理（修复：原 batch_size=1000 + model_timeout=60 在 redis 流大时
    # 累积 1000 事件/session 致 prompt 暴涨触发 llama.cpp cancel，单会话拖死整队列；
    # batch=50 + 单 session 50 事件 + max_tool_calls=2 + timeout=15s 避免单个会话拖垮）
    batch_size: int = 50
    max_events_per_session: int = 50
    batch_seconds: float = 5.0
    idle_poll_seconds: float = 1.0
    max_pending_claim: int = 200

    # 缓存 / TTL
    result_ttl: int = 3600
    entity_ttl: int = 86400
    chain_ttl: int = 172800
    evt_ttl: int = 86400
    lock_ttl: int = 30
    lock_retries: int = 3

    # 模型（修复：原 timeout=60 + max_context=32768 + max_tool_calls=5 让单推理
    # 占用宿主 CPU 并导致 prompt 超过 ctx-size 后被 llama.cpp 主动 cancel；
    # 减小 timeout + context + tool_calls，配合 llm-server entrypoint 的比例线程
    # 控制单次推理负载，circuit_breaker 更激进熔断）
    default_provider: str = "edge"
    cloud_provider: str = "cloud"
    max_tool_calls: int = 2
    max_output_tokens: int = 384
    model_timeout: float = 15.0

    # 输出 / 索引
    verdict_index: str = "nss-ndr-agent-verdict"
    asset_index: str = "nss-ndr-agent-assets"
    alert_index: str = "nss-ndr-agent-events"

    # 失效补偿 / DLQ（修复：原 ES 失败抛异常 → 不 XACK → 事件一直卡在 PEL）
    outbox_index: str = "nss-ndr-agent-outbox"  # ES 写入失败暂存 outbox（带 TTL 与重试）
    dlq_stream: str = "analysis:events:dlq"     # 解析失败消息的 DLQ 流
    dlq_max_len: int = 10000
    outbox_ttl: int = 3600                      # outbox 重试间隔秒

    # 资产知识库
    asset_seed_file: str = "data/assets.example.csv"

    # 通知（v1 仅日志/Webhook）
    webhook_url: str | None = None

    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    rules_dir: str = "config/rules"
    prompts_dir: str = "prompts"
    skills_dir: str = "skills"

    # 基线/异常检测引擎（设计文档 §14）
    baseline: dict = field(default_factory=dict)

    # 调试
    dry_run: bool = False  # 只读消费，不写生产结论（M4.3）


def _resolve_env(value: str) -> str:
    """支持 ${VAR} 引用，来源优先级：进程环境变量 > .env 文件。"""
    if value.startswith("${") and value.endswith("}"):
        key = value[2:-1]
        return os.environ.get(key, "")
    return value


def load_config(base_dir: str | Path | None = None) -> AgentConfig:
    """加载 agent.yaml + providers.yaml + 环境变量，返回 AgentConfig。"""
    base = Path(base_dir or Path(__file__).resolve().parent.parent)
    load_dotenv(_env_file_path(), override=False)

    agent_path = base / "config" / "agent.yaml"
    providers_path = base / "config" / "providers.yaml"
    raw = yaml.safe_load(agent_path.read_text(encoding="utf-8")) or {}
    raw_providers = yaml.safe_load(providers_path.read_text(encoding="utf-8")) or {}

    cfg = AgentConfig(**{k: v for k, v in raw.items() if k != "providers"})

    providers: dict[str, ProviderConfig] = {}
    for name, p in (raw_providers.get("providers") or {}).items():
        providers[name] = ProviderConfig(
            name=name,
            base_url=_resolve_env(str(p["base_url"])),
            api_key=_resolve_env(str(p.get("api_key", ""))) or None,
            model=_resolve_env(str(p["model"])),
            max_context=int(p.get("max_context", 32768)),
            capabilities=p.get("capabilities") or {"tool_calling": True, "json_schema": True, "streaming": False},
            weight=float(p.get("weight", 1.0)),
            quota=p.get("quota", {}),
            circuit_breaker=p.get("circuit_breaker", {}),
        )
    cfg.providers = providers

    # 环境变量覆盖关键连接项（部署时由 Salt/.env 注入）
    cfg.redis_url = os.environ.get("REDIS_URL", cfg.redis_url)
    cfg.redis_password = os.environ.get("REDIS_PASSWORD", cfg.redis_password)
    if os.environ.get("ELASTICSEARCH_HOSTS"):
        cfg.es_hosts = os.environ["ELASTICSEARCH_HOSTS"].split(",")
    cfg.es_username = os.environ.get("ELASTICSEARCH_USERNAME", cfg.es_username)
    cfg.es_password = os.environ.get("ELASTICSEARCH_PASSWORD", cfg.es_password)
    # dry_run: 默认 0（生产模式，写 verdict / entity / ES / Redis Lua）。
    # agent.yaml 里写 False 是同等语义；显式 opt-in 设 AGENT_DRY_RUN=1。
    cfg.dry_run = os.environ.get("AGENT_DRY_RUN", "0") in ("1", "true", "yes")

    # LLM provider 健康自检：dry_run=False 但所有 provider 的 base_url/model 都为空时，
    # 启动期 fail-fast 报错，避免出现"静默兜底到 uncertain low"导致看起来在跑、实际没用 LLM。
    # 预留未启用的 provider（如 cloud，weight=0，base_url/model/api_key 全空）跳过自检，
    # 允许 edge-only 部署；一旦配置了其中任一项就必须配齐，防手误。
    if not cfg.dry_run:
        for name, p in cfg.providers.items():
            if not p.base_url and not p.model and not p.api_key:
                continue
            missing = []
            if not p.base_url: missing.append("base_url")
            if not p.model:   missing.append("model")
            if missing:
                raise RuntimeError(
                    f"provider '{name}' 配置缺失: {', '.join(missing)}；"
                    f"请检查 /etc/nss-ndr/agent/providers.yaml 或容器 ENV "
                    f"(EDGE_LLM_BASE_URL / EDGE_LLM_MODEL)。如确实只想只读消费，"
                    f"请设置 AGENT_DRY_RUN=1 显式启用 dry_run 模式。"
                )
    return cfg
