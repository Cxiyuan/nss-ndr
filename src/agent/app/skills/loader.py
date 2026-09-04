"""Skills 三层渐进式加载（设计文档 §7.2）：Discovery 常驻 / Activation 按需 / Execution 动态。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Skill:
    name: str
    description: str
    version: str = "1.0"
    triggers: dict = field(default_factory=dict)
    context_budget: int = 1500
    mcp_tools: list[str] = field(default_factory=list)
    body: str = ""

    @property
    def discovery_line(self) -> str:
        """Layer1：name + description + triggers 索引（常驻系统提示词）。"""
        triggers = self.triggers or {}
        return f"- {self.name}：{self.description} [triggers={triggers.get('behavior', [])}]"

    def activation_text(self) -> str:
        """Layer2：完整 SKILL.md 指令（仅被路由选中的 1~2 个加载）。"""
        return self.body[: self.context_budget * 4]  # 字符预算约 4 倍 token 预算


def _parse_front_matter(text: str) -> tuple[dict, str]:
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n(.*)$", text, re.S)
    if not m:
        return {}, text
    import yaml

    try:
        meta = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError:
        meta = {}
    return meta, m.group(2)


class SkillLoader:
    def __init__(self, skills_dir: str | Path = "skills"):
        self.skills: list[Skill] = []
        for path in sorted(Path(skills_dir).glob("*.md")):
            meta, body = _parse_front_matter(path.read_text(encoding="utf-8"))
            if not meta.get("name"):
                continue
            self.skills.append(
                Skill(
                    name=meta["name"],
                    description=meta.get("description", ""),
                    version=str(meta.get("version", "1.0")),
                    triggers=meta.get("triggers", {}),
                    context_budget=int(meta.get("context_budget", 1500)),
                    mcp_tools=meta.get("mcp_tools", []),
                    body=body,
                )
            )

    def discovery_index(self) -> str:
        return "可用 Skills：\n" + "\n".join(s.discovery_line for s in self.skills)

    def route(self, behavior_ids: list[str], proto: str = "") -> list[Skill]:
        """按 triggers 选 Top-1~Top-3。

        修复#3:以前行为空时仍会因 proto 命中被拉入 prompt(每条 UDP 普通 DNS 都被塞入
        dns-tunneling skill,污染判定并加大 token)。
        现在默认 require_behavior=True:必须 behavior 命中才入候选;只有
        frontmatter 显式 `require_behavior: false` 才允许仅 proto 命中;
        triggers 完全为空(无 behavior / 无 proto)且 require_behavior: false → 兜底 catch-all。
        """
        scored: list[tuple[int, Skill]] = []
        for s in self.skills:
            triggers = s.triggers or {}
            beh: list[str] = list(triggers.get("behavior", []) or [])
            protos: list[str] = list(triggers.get("proto", []) or [])
            require_behavior_raw = triggers.get("require_behavior")
            # 缺省:必须 behavior 命中;显式 false 才允许 protocol-only 或 catch-all
            require_behavior = True if require_behavior_raw is None else bool(require_behavior_raw)

            beh_hit = bool(beh) and any(b in beh for b in behavior_ids)
            proto_hit = bool(protos) and proto in protos

            if require_behavior:
                if not beh_hit:
                    continue
                score = 2
                if proto_hit:
                    score += 1
            else:
                # require_behavior: false 的两类:protocol-only 或 全空 catch-all
                is_catchall = (not beh) and (not protos)
                if is_catchall:
                    score = 1
                else:
                    if not (beh_hit or proto_hit):
                        continue
                    score = 1
                    if beh_hit:
                        score += 1
            if score:
                scored.append((score, s))
        scored.sort(key=lambda x: -x[0])
        return [s for _, s in scored[:3]]

    def load_for(self, behavior_ids: list[str], proto: str = "") -> str:
        """返回路由命中 Skills 的完整指令拼接（≤2 个，控制上下文预算）。"""
        selected = self.route(behavior_ids, proto)[:2]
        return "\n\n".join(f"## Skill: {s.name}\n{s.activation_text()}" for s in selected)
