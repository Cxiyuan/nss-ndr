# ============================================================================
# AI 分析智能体（nss-ndr/agent:0.1.1，worker 模式）
# 容器定义已统一到 agent/containers/agent.sls（user=agent、python -m app worker、
# alias agent、配置由 agent.configs 下发），此处保留入口以兼容 databus.top / deploy.sls
# ============================================================================

include:
  - agent.containers.agent
