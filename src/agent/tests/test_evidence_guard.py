"""evidence 落地点校验守卫测试(Phase C/D2)。"""

import pytest

from app.evidence_guard import downgrade_evidence, validate


def _unit_with_features(datasets: list[str]) -> "AnalysisUnit":
    from app.rules import RuleEngine
    from app.schemas.event import EventEnvelope

    events = []
    for i, ds in enumerate(datasets):
        zeek = {}
        if ds == "zeek.dns":
            zeek = {"query": f"q{i}.example.com", "qtype_name": "A"}
        elif ds == "zeek.connection":
            zeek = {"conn_state": "S0", "service": "smb"}
        elif ds == "zeek.weird":
            zeek = {"name": "TCP_ack_underflow", "notice": False}
        elif ds == "zeek.ssh":
            zeek = {"auth_attempts": "2", "auth_success": False, "client": "SSH-2.0-OpenSSH"}
        events.append(
            EventEnvelope(
                event_id=f"g{i}",
                ts="2026-09-05T01:00:00Z",
                src_ip="10.1.1.1",
                dst_ip="10.1.1.2",
                dst_port="445",
                proto="tcp",
                dataset=ds,
                zeek=zeek,
            )
        )
    engine = RuleEngine(rules_dir="config/rules")
    unit = engine.build_unit("sess:10.1.1.1:10.1.1.2:445:tcp", events, [])
    return unit


def test_ok_features_reference_real_dataset():
    unit = _unit_with_features(["zeek.dns"])
    ok, issue = validate(unit, "依据 features.zeek.dns:qtype_dist(A 占比 1.0)、unique_domains 1")
    assert ok, issue


def test_fail_features_dataset_not_in_summary():
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "依据 features.zeek.dns:unique_domains=39")
    assert not ok
    assert "zeek.dns" in issue


def test_fail_bare_feature_key_without_dataset():
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "会话 DNS 平均熵 avg_entropy=0.72,共 39 次查询")
    assert not ok
    assert "avg_entropy" in issue


def test_fail_instruction_text_echo():
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "引用本会话 BEH-002 的 avg_entropy 与 39 个 DNS 查询")
    assert not ok
    assert "指令性文字" in issue


def test_ok_es_search_labeled_result_allowed():
    """明确标注 es_search 来源的工具结果允许引用非本会话数据。"""
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "es_search 返回:近 5min 该源 dns avg_entropy=0.72、unique_domains=39")
    assert ok, issue


def test_empty_evidence_invalid():
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "")
    assert not ok


def test_downgrade_evidence_message():
    ev = downgrade_evidence("evidence 引用 features.zeek.dns,但本会话无该数据流", "features.zeek.dns: x")
    assert ev.startswith("evidence 未通过落地点校验:")
    assert "features.zeek.dns" in ev


def test_weird_feature_keys_validated():
    """zeek.weird 特征键(names/notice_count)绑定 dataset 校验。"""
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "依据 names 含 possible_SPF_DoS")
    assert not ok
    assert "names" in issue
    # 有 weird 特征的会话允许引用
    unit_w = _unit_with_features(["zeek.connection", "zeek.weird"])
    ok, issue = validate(unit_w, "依据 zeek.weird:names 含 TCP_ack_underflow")
    assert ok, issue


def test_ssh_feature_keys_validated():
    unit = _unit_with_features(["zeek.connection"])
    ok, issue = validate(unit, "依据 attempts_sum=20 判定爆破")
    assert not ok
    assert "attempts_sum" in issue
    unit_s = _unit_with_features(["zeek.connection", "zeek.ssh"])
    ok, issue = validate(unit_s, "依据 zeek.ssh:attempts_sum=20、auth_success_cnt=0")
    assert ok, issue
