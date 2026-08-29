"""缓存键规范（设计文档 §4.3、§13.4）。"""

from __future__ import annotations

import hashlib


def normalize_ip(ip: str) -> str:
    """IPv6 冒号与键分隔符冲突：规范化或哈希。"""
    ip = ip.strip()
    if ":" in ip:
        return "v6_" + hashlib.sha256(ip.encode()).hexdigest()[:16]
    return ip


def session_key(src_ip: str, dst_ip: str, dst_port: str, proto: str) -> str:
    """流/服务级会话键：sess:{src}:{dst}:{dst_port}:{proto}，保留方向语义。"""
    return "sess:{}:{}:{}:{}".format(
        normalize_ip(src_ip), normalize_ip(dst_ip), dst_port or "*", proto or "*"
    )


def evt_key(event_id: str) -> str:
    return f"evt:{event_id}"


def lock_key(sess: str) -> str:
    return f"lock:{sess}"


def alert_fingerprint(sess: str, verdict: str, behavior_hits: list[str]) -> str:
    """告警指纹：同会话同结论同行为合并，重复触发不重复建单。"""
    raw = f"{sess}|{verdict}|{','.join(sorted(behavior_hits))}"
    return hashlib.sha1(raw.encode()).hexdigest()


def agent_result_key(sess: str) -> str:
    return f"agent:result:{sess}"


def agent_entity_key(ip: str) -> str:
    return f"agent:entity:{normalize_ip(ip)}"


def agent_chain_key(chain_id: str) -> str:
    return f"agent:chain:{chain_id}"
