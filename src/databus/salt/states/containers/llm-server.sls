# ============================================================================
# LLM Server（nss-ndr/llm-server，llama.cpp + Qwen3-0.6B-Q8_0，OpenAI 兼容 API）
# ----------------------------------------------------------------------------
# 容器为安全分析智能体提供本地边缘 LLM 推理：
#   - 监听 0.0.0.0:8080，对外暴露 /v1/chat/completions 等 OpenAI 兼容端点
#   - alias `llm-server`（agent.containers.agent 容器通过该别名访问）
#   - 启动期 1B 模型首次加载可能 30~60s，healthcheck start_period=120s 兜底
# ----------------------------------------------------------------------------
# 上下游依赖：
#   - 仅依赖 databus.network（IP 固定 192.168.250.90）+ databus.images
#   - 不依赖 ES / Redis / Fleet / zeek —— 任何时刻启动都不会阻塞数据总线
#   - 但必须先于 agent.containers.agent 启动，否则 agent 在 circuit_breaker
#     冷却期（默认 60s）内持续 503；好在 agent 重启后会自动重连
# ============================================================================

include:
  - databus.network
  - databus.images

{% from "databus/map.jinja" import databus with context %}
{% from "databus/map.jinja" import llm_server with context %}

nss-ndr-llm-server:
  docker_container.running:
    - image: {{ llm_server.image }}
    - restart_policy: unless-stopped
    - network_mode: nss-net
    - detach: True
    - skip_translate: volumes
    # 镜像默认非特权用户 llm（uid 10001），与 agent 镜像一致
    # 模型 Qwen3-0.6B-Q8_0.gguf 已内置进镜像（/models），无需外挂模型卷
    - networks:
        - nss-net:
            - ipv4_address: {{ llm_server.ip }}
            - aliases:
                - llm-server
    - environment:
        - TZ={{ databus.tz }}
        - LLM_HOST=0.0.0.0
        - LLM_PORT={{ llm_server.port | string }}
        - LLM_MODEL={{ llm_server.model_path }}
        - LLM_ALIAS={{ llm_server.model_alias }}
        - LLM_CONTEXT_SIZE={{ llm_server.context_size | string }}
        - LLM_PARALLEL={{ llm_server.parallel | string }}
        - LLM_BATCH_SIZE={{ llm_server.batch_size | string }}
        - LLM_UBATCH_SIZE={{ llm_server.ubatch_size | string }}
        - LLM_CACHE_TYPE_K={{ llm_server.cache_type_k }}
        - LLM_CACHE_TYPE_V={{ llm_server.cache_type_v }}
        - LLM_THREADS={{ llm_server.threads | string }}
        - LLM_EXTRA_ARGS={{ llm_server.extra_args }}
        # LLM_API_KEY 仅在 pillar 显式非空时注入（默认无鉴权，符合内网部署假设）
        {%- if llm_server.api_key %}
        - LLM_API_KEY={{ llm_server.api_key }}
        {%- endif %}
    - log_driver: json-file
    - healthcheck:
        - test: ["CMD-SHELL", "wget -q -O /dev/null \"http://127.0.0.1:${LLM_PORT:-8080}/health\" || exit 1"]
        - interval: 30000000000
        - timeout: 5000000000
        - retries: 3
        - start_period: 120000000000
    - require:
      - docker_image: {{ llm_server.image }}
      - docker_network: ensure-nss-net-present
