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
        default_factory=lambda: {"max_consecutive_failures": 5, "cooldown_seconds": 60}
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

    # Worker 批处理
    batch_size: int = 1000
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

    # 模型
    default_provider: str = "edge"
    cloud_provider: str = "cloud"
    max_tool_calls: int = 5
    max_output_tokens: int = 512
    model_timeout: float = 60.0

    # 输出 / 索引
    verdict_index: str = "nss-ndr-agent-verdict"
    asset_index: str = "nss-ndr-agent-assets"
    alert_index: str = "nss-ndr-agent-events"

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
    cfg.dry_run = os.environ.get("AGENT_DRY_RUN", "0") in ("1", "true", "yes")
    return cfg
