"""evidence 落地点校验(Phase C/D2 结构性守卫)。

背景(见 docs/research/phase-c-observation-2026-09-05.md §D2):Qwen3-0.6B 对
prompt 约束的遵循有上限——消除"照抄示例数值"后改"照抄示例指令文字+编造细节"。
纯 prompt 无法根治,故在代码侧做**确定性校验**:模型输出中 evidence 若引用
task_json 里不存在的 features 键、或整段照抄指令性文字 → 判定不可信,由调用方降级。

校验规则:
1. 元文字照抄:evidence 含"引用本会话 / BEH-xxx / 不得照抄 / 按本会话真实情况"
   等指令性短语 → 不可信(模型把指令当 evidence 输出)。
2. features 键存在性(evidence 引用必须能在 task_json 里落地):
   a. `features.zeek.<ds>` 形式引用的 dataset 必须存在于 summary.features;
   b. evidence 出现已知特征键词(avg_entropy / conn_states_dist / sni_set 等)而
      对应 dataset 不在 summary.features → 不可信。
   例外:evidence 明确标注 es_search 工具来源(工具可返回其它会话/时间窗数据,
   不要求出现在本会话 summary.features)。
3. 通过 → 可信,原样返回。
"""
from __future__ import annotations

import re
from typing import Any

# 特征键词 → 所属 dataset(键词出现即声称该数据流有特征)
_FEATURE_KEY_TO_DATASET: dict[str, str] = {
    # zeek.dns
    "top_queries": "zeek.dns",
    "unique_domains": "zeek.dns",
    "qtype_dist": "zeek.dns",
    "avg_entropy": "zeek.dns",
    # zeek.http
    "methods_dist": "zeek.http",
    "status_codes_dist": "zeek.http",
    "top_uris": "zeek.http",
    "hosts": "zeek.http",
    # zeek.connection
    "services_dist": "zeek.connection",
    "conn_states_dist": "zeek.connection",
    "bytes_sum": "zeek.connection",
    "duration_sum": "zeek.connection",
    # zeek.ssl
    "sni_set": "zeek.ssl",
    "ja3_cnt": "zeek.ssl",
    "cipher_set": "zeek.ssl",
    "validation_status": "zeek.ssl",
    # zeek.files
    "filenames": "zeek.files",
    "mime_dist": "zeek.files",
    # zeek.notice
    "msgs": "zeek.notice",
    # zeek.weird(2026-09-05 输入复核 P1-B)
    "names": "zeek.weird",
    "notice_count": "zeek.weird",
    # zeek.ssh(2026-09-05 输入重心)
    "attempts_sum": "zeek.ssh",
    "auth_success_cnt": "zeek.ssh",
    "clients": "zeek.ssh",
}

# 指令性/示例性文字(模型把 prompt 指令或示例骨架抄进 evidence 的典型痕迹)
_META_PHRASES: tuple[str, ...] = (
    "引用本会话",
    "不得照抄",
    "按本会话真实情况",
    "BEH-xxx",
    "features/工具结果的真实字段",
    "以 BEH-xxx 窗口统计为第一依据",
    "可执行处置(不得照抄",
)

_DS_REF = re.compile(r"features\.(zeek\.[a-z_]+)")


def _has_tool_label(evidence: str) -> bool:
    return "es_search" in evidence or "工具返回" in evidence or "工具结果" in evidence


def validate(unit: Any, evidence: str) -> tuple[bool, str]:
    """校验 evidence 是否能在 AnalysisUnit 上落地。

    Returns: (ok, issue)。ok=False 时 issue 给出不可信原因(供降级 evidence 使用)。
    """
    if not evidence or not evidence.strip():
        return False, "evidence 为空"
    # 规则 1:指令文字照抄
    for phrase in _META_PHRASES:
        if phrase in evidence:
            return False, f"evidence 含指令性文字『{phrase}』(疑似照抄 prompt/示例)"
    # 规则 2a:features.zeek.<ds> dataset 存在性
    claimed_ds = set(_DS_REF.findall(evidence))
    feature_ds = set((unit.summary.get("features") or {}).keys())
    missing_ds = claimed_ds - feature_ds
    if missing_ds and not _has_tool_label(evidence):
        ds = sorted(missing_ds)[0]
        return False, f"evidence 引用 features.{ds},但本会话 summary.features 无该数据流"
    # 规则 2b:特征键词 → dataset 存在性(无 features.zeek. 前缀的裸键词引用)
    if not _has_tool_label(evidence):
        for key, ds in _FEATURE_KEY_TO_DATASET.items():
            if key in evidence and ds not in feature_ds:
                return False, f"evidence 引用特征键 {key}(属 {ds}),但本会话无 {ds} 特征"
    return True, ""


def downgrade_evidence(issue: str, original: str) -> str:
    """构造降级后的 evidence(引用不可信原因,不放大原始内容)。"""
    orig = (original or "").strip()
    tail = f"(原始: {orig[:120]})" if orig else ""
    return f"evidence 未通过落地点校验:{issue}{tail}"
