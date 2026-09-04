"""提示词构建（设计文档 §4：系统层/资产上下文层/任务层/输出约束层）。"""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.analysis import AnalysisUnit


class PromptBuilder:
    def __init__(self, prompts_dir: str | Path = "prompts"):
        self.dir = Path(prompts_dir)

    def _template(self, name: str) -> str:
        path = self.dir / f"{name}.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
        return ""

    def build(
        self,
        unit: AnalysisUnit,
        asset_context: str = "",
        tool_directory: str = "",
        skill: str = "",
    ) -> list[dict]:
        system = self._template("system") or "你是深瞳安全分析智能体。"
        system = system.format(asset_context=asset_context, tool_directory=tool_directory, skill=skill)
        task = self._template("task") or "分析任务：{task_json}"
        task = task.format(task_json=json.dumps(unit.model_dump(mode="json"), ensure_ascii=False, default=str))
        output = self._template("output") or "只输出 JSON，字段：risk_level/verdict/evidence/iocs/suggest_action。"
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": task},
            {"role": "user", "content": output},
        ]
        return messages
