"""Elasticsearch 存储：索引初始化、verdict 落盘、回溯查询、资产档案。"""

from __future__ import annotations

import json

from elasticsearch import AsyncElasticsearch

from app.schemas.verdict import Verdict


VERDICT_MAPPING = {
    "mappings": {
        "properties": {
            "sess": {"type": "keyword"},
            "risk_level": {"type": "keyword"},
            "verdict": {"type": "keyword"},
            "evidence": {"type": "text"},
            "iocs": {"type": "object", "enabled": False},
            "behavior_hits": {"type": "keyword"},
            "model": {"type": "keyword"},
            "trace_id": {"type": "keyword"},
            "@timestamp": {"type": "date"},
        }
    },
    "settings": {"number_of_shards": 1, "number_of_replicas": 1},
}

ASSET_MAPPING = {
    "mappings": {
        "properties": {
            "ip": {"type": "keyword"},
            "segment": {"type": "keyword"},
            "business": {"type": "keyword"},
            "owner": {"type": "keyword"},
            "ports": {"type": "keyword"},
            "known_vulns": {"type": "keyword"},
            "importance": {"type": "keyword"},
            "sensitivity": {"type": "keyword"},
            "confidence": {"type": "float"},
            "updated_at": {"type": "date"},
        }
    }
}

ALERT_MAPPING = {
    "mappings": {
        "properties": {
            "fingerprint": {"type": "keyword"},
            "sess": {"type": "keyword"},
            "status": {"type": "keyword"},
            "risk_level": {"type": "keyword"},
            "verdict": {"type": "keyword"},
            "trace_id": {"type": "keyword"},
            "@timestamp": {"type": "date"},
        }
    }
}


class ESStore:
    """数据总线 ES 的智能体侧封装。client 可注入（测试用 fake）。"""

    def __init__(self, client: AsyncElasticsearch | None = None, indices: dict[str, str] | None = None):
        self.client = client  # 由调用方负责连接；None 时由 make_client 创建
        idx = indices or {}
        self.verdict_index = idx.get("verdict", "nss-ndr-agent-verdict")
        self.asset_index = idx.get("asset", "nss-ndr-agent-assets")
        self.alert_index = idx.get("alert", "nss-ndr-agent-events")

    @classmethod
    async def make_client(
        cls, hosts: list[str], username: str, password: str, indices: dict[str, str] | None = None
    ) -> "ESStore":
        client = AsyncElasticsearch(hosts, basic_auth=(username, password) if password else None)
        return cls(client, indices)

    async def close(self) -> None:
        if self.client is not None:
            await self.client.close()

    async def init_indices(self) -> None:
        """幂等创建索引（含 ILM 策略挂载）。"""
        if self.client is None:
            return
        try:
            await self.client.ilm.put_lifecycle(
                "nss-ndr-agent-policy",
                policy={"policy": {"phases": {"hot": {"min_age": "0ms", "actions": {"rollover": {"max_age": "7d", "max_size": "20gb"}}}, "delete": {"min_age": "30d", "actions": {"delete": {}}}}}},
            )
        except Exception:
            pass  # ILM 不可用时降级为普通索引
        for name, mapping in (
            (self.verdict_index, VERDICT_MAPPING),
            (self.asset_index, ASSET_MAPPING),
            (self.alert_index, ALERT_MAPPING),
        ):
            try:
                await self.client.indices.create(index=name, **mapping)
            except Exception:
                pass  # 已存在

    async def write_verdict(self, verdict: Verdict, index: str | None = None) -> dict:
        body = verdict.model_dump(mode="json")
        body["@timestamp"] = verdict.created_at or None
        if self.client is None:
            return {"index": index or self.verdict_index, "result": "noop"}
        return await self.client.index(index=index or self.verdict_index, document=body, refresh=True)

    async def write_doc(self, index: str, doc: dict) -> dict:
        if self.client is None:
            return {"index": index, "result": "noop"}
        return await self.client.index(index=index, document=doc, refresh=True)

    async def search_verdicts(self, ip: str, time_range_hours: int = 24, size: int = 20) -> list[dict]:
        """历史结论回溯：按 IP 检索（时间回溯策略第②级）。"""
        if self.client is None:
            return []
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"sess": ip}},
                        {"wildcard": {"sess": f"*{ip}*"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": size,
        }
        resp = await self.client.search(index=self.verdict_index, body=query)
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]

    async def fetch_details(self, src_ip: str, dst_ip: str, since_ts: str, size: int = 50) -> list[dict]:
        """按会话回查 ES 中的 Zeek 详情（时间回溯策略第③级 / 规则富化）。
        v1 简化：按 source.ip + destination.ip + 时间范围聚合查询。"""
        if self.client is None:
            return []
        query = {
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"source.ip": src_ip}},
                        {"term": {"destination.ip": dst_ip}},
                        {"range": {"@timestamp": {"gte": since_ts}}},
                    ]
                }
            },
            "sort": [{"@timestamp": "desc"}],
            "size": size,
        }
        try:
            resp = await self.client.search(index=".ds-logs-zeek.*", body=query)
        except Exception:
            return []
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]

    async def search_assets(self, ips: list[str], size: int = 10) -> list[dict]:
        """资产档案检索：按 IP 精确匹配（RAG v1 用 keyword，向量化后置）。"""
        if self.client is None or not ips:
            return []
        query = {"query": {"terms": {"ip": ips}}, "size": size}
        try:
            resp = await self.client.search(index=self.asset_index, body=query)
        except Exception:
            return []
        return [h["_source"] for h in resp.get("hits", {}).get("hits", [])]

    async def bulk_index_assets(self, assets: list[dict]) -> None:
        """批量导入资产档案（CSV/CMDB 种子）。"""
        if self.client is None or not assets:
            return
        for a in assets:
            await self.client.index(index=self.asset_index, id=a.get("ip"), document=a, refresh=True)
