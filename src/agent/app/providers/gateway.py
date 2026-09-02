"""模型网关（设计文档 §8、§15.3）：needs_cloud 判定、配额、熔断、降级。"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from app.config import AgentConfig
from app.providers.base import LLMResponse, Provider


def needs_cloud(
    initial_risk: str = "low",
    local_risk: str = "",
    behavior_hits: int = 0,
    rule_resolved: bool = False,
    requires_chain_analysis: bool = False,
    estimated_tool_calls: int = 0,
    local_verdict: str = "",
    local_parsed: bool = True,
    anomaly_alert: bool = False,
) -> bool:
    """升级判定（设计文档 §8.5）：调度层硬编码，不依赖模型自行判断。"""
    if initial_risk == "high" or local_risk == "high":
        return True
    if requires_chain_analysis:
        return True
    if behavior_hits >= 2 and not rule_resolved:
        return True
    if local_verdict in ("uncertain", "error") or not local_parsed:
        return True
    if estimated_tool_calls >= 3:
        return True
    if anomaly_alert:
        return True  # 基线高分异常升级云端复核（设计文档 §14.5）
    return False


@dataclass
class CircuitState:
    consecutive_failures: int = 0
    opened_at: float = 0.0
    cooldown_seconds: int = 60

    @property
    def open(self) -> bool:
        return self.opened_at > 0 and (time.time() - self.opened_at) < self.cooldown_seconds


class ModelGateway:
    """Provider 注册表 + 路由 + 配额/熔断。v1 配额与熔断为进程内状态。"""

    def __init__(self, config: AgentConfig, providers: dict[str, Provider]):
        self.config = config
        self.providers = providers
        self.circuits: dict[str, CircuitState] = {
            name: CircuitState(cooldown_seconds=p.config.circuit_breaker.get("cooldown_seconds", 60))
            for name, p in providers.items()
        }
        # token 配额：hourly/daily 滚动计数（进程内；多 worker 需迁 Redis）
        self.tokens: dict[str, dict[str, float]] = {}  # provider -> {h,d,hk,dk}

    def get(self, name: str) -> Provider:
        return self.providers[name]

    def _check_circuit(self, name: str) -> bool:
        st = self.circuits[name]
        mx = int(self.providers[name].config.circuit_breaker.get("max_consecutive_failures", 5))
        if st.consecutive_failures >= mx:
            if st.opened_at == 0.0:
                # 刚达到阈值：打开熔断，进入冷却
                st.opened_at = time.time()
                return False
            if time.time() - st.opened_at >= st.cooldown_seconds:
                # 冷却结束：半开放行一次探针并复位计数（失败会重新累计再熔断）
                st.opened_at = time.time()
                st.consecutive_failures = 0
                return True
            return False
        return True

    def _record_failure(self, name: str) -> None:
        st = self.circuits[name]
        st.consecutive_failures += 1
        if st.consecutive_failures >= self.providers[name].config.circuit_breaker.get("max_consecutive_failures", 5):
            st.opened_at = time.time()

    def _record_success(self, name: str) -> None:
        st = self.circuits[name]
        st.consecutive_failures = 0
        st.opened_at = 0.0

    def _quota_ok(self, name: str, est_tokens: int) -> bool:
        p = self.providers[name].config
        hourly = int(p.quota.get("hourly_tokens", 0))
        daily = int(p.quota.get("daily_tokens", 0))
        if hourly <= 0 and daily <= 0:
            return True
        now = time.time()
        hour_key = int(now // 3600)
        day_key = int(now // 86400)
        bucket = self.tokens.setdefault(name, {"h": 0.0, "hk": 0, "d": 0.0, "dk": 0})
        if bucket["hk"] != hour_key:
            bucket["h"], bucket["hk"] = 0.0, hour_key
        if bucket["dk"] != day_key:
            bucket["d"], bucket["dk"] = 0.0, day_key
        return (hourly <= 0 or bucket["h"] + est_tokens <= hourly) and (
            daily <= 0 or bucket["d"] + est_tokens <= daily
        )

    def _charge_tokens(self, name: str, tokens: int) -> None:
        bucket = self.tokens.setdefault(name, {"h": 0.0, "hk": int(time.time() // 3600), "d": 0.0, "dk": int(time.time() // 86400)})
        bucket["h"] += tokens
        bucket["d"] += tokens

    async def generate(
        self,
        provider_name: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        response_schema: dict | None = None,
        max_tokens: int = 512,
    ) -> LLMResponse:
        provider = self.providers[provider_name]
        est = self.providers[provider_name].estimate_tokens(messages) + max_tokens
        if not self._check_circuit(provider_name):
            return LLMResponse(error=f"circuit open: {provider_name}")
        if not self._quota_ok(provider_name, est):
            return LLMResponse(error=f"quota exceeded: {provider_name}")
        self._charge_tokens(provider_name, est)
        resp = await provider.generate(
            messages, tools=tools, response_schema=response_schema, max_tokens=max_tokens,
            timeout=self.config.model_timeout,
        )
        if resp.ok:
            self._record_success(provider_name)
        else:
            self._record_failure(provider_name)
        return resp
