# 用 SaltStack 管理智能体（容器 + 配置文件）· 正式实现

> 适用范围：智能体 1 容器（`nss-ndr-agent`）+ 配置文件 + 镜像离线 tar。
> 目标服务器：`172.16.199.235`（masterless salt-minion，与数据总线同机，**不得影响**数据总线与其他业务）。
> 前置条件：数据总线已由 `src/databus/salt/` 部署并正常生产（ES / Redis / `nss-net` / `/etc/nss-ndr/.env`）。

## 部署拓扑

```text
nss-ndr-agent（192.168.250.80，加入 nss-net）
  ├─ 消费 Redis Stream analysis:events（消费组 analysis-group）
  ├─ 写 Redis agent:result:* / sess:* / evt:* / lock:* / alert:* / agent:entity:*
  ├─ 写 ES nss-ndr-agent-verdict / nss-ndr-agent-assets / nss-ndr-agent-events
  └─ 调用外部 OpenAI 兼容模型接口（edge / cloud，配置在 .env）
```

## 目录结构（落盘 /srv/salt/agent/，与 databus 平铺规范一致）

```text
/srv/salt/agent/
├── top.sls / deploy.sls / images.sls / configs.sls / bootstrap.sls
├── setup.sls / verify.sls / teardown.sls / map.jinja
├── containers/agent.sls
├── files/          agent.yaml / providers.yaml / rules/beh-rules.yaml
└── scripts/        agent-setup.sh / saltctl.sh
```

## 部署步骤

```bash
# 1. 镜像：CI 已推送 GHCR，目标机直接 pull
#    如目标机不能直连 GHCR，可先 docker pull 到中转机再 docker save/load
docker pull ghcr.io/cxiyuan/nss-ndr-public/agent:0.1.1

# 2. salt 状态由 bootstrap systemd oneshot 铺设到 /srv/salt/agent/ 与 /srv/pillar/
#    （masterless 本地调用，无需 scp）

# 3. 触发部署
salt-call --local state.apply agent.deploy
```

> 自 2026-08-31 起，容器镜像仅通过 GHCR 发布，不再使用本地 `images/offline/*.tar` 或 `.run` 安装包；
> 目标机部署 = `docker pull` + `salt-call state.apply`，Salt 状态文件由 systemd oneshot 负责落盘。

## 日常操作

```bash
/srv/salt/agent/scripts/saltctl.sh deploy     # 从零部署 / 完整初始化
/srv/salt/agent/scripts/saltctl.sh apply      # 日常幂等自愈
/srv/salt/agent/scripts/saltctl.sh status     # 容器状态
/srv/salt/agent/scripts/saltctl.sh verify     # 验证消费组 / 容器日志
/srv/salt/agent/scripts/saltctl.sh teardown   # 清理智能体（保留数据总线）
```

## 上线前配置（.env）

在 `/etc/nss-ndr/.env` 填写（`agent-setup.sh` 会补默认空值）：

| 变量 | 说明 |
|---|---|
| `EDGE_LLM_BASE_URL` / `EDGE_LLM_API_KEY` / `EDGE_LLM_MODEL` | 本地边缘模型 OpenAI 兼容接口（默认 `http://llm-server:8080/v1`，模型 `Qwen3-0.6B-Q8_0`，由 `nss-ndr/llm-server` 镜像提供） |
| `CLOUD_LLM_BASE_URL` / `CLOUD_LLM_API_KEY` / `CLOUD_LLM_MODEL` | 云端高阶模型接口 |
| `AGENT_DRY_RUN` | `1`=只读消费（不写结论/不 XACK）；`0`=生产写回（默认上线前先 `1`） |

模型接口未配置时，规则直接判定（BEH-005 等）与基线异常检测仍工作；依赖模型的场景输出 `uncertain`。

## 风险与注意事项

- 只管理 `nss-ndr-agent` 容器与 `/etc/nss-ndr/agent` 配置，不触碰数据总线 7 容器与其他业务。
- 复用数据总线 `nss-net`，固定 IP `.80`（已确认未被占用）。
- 镜像走 GHCR：换版本只需修改 pillar `agent.image`，salt 会触发 `docker pull` 后重建容器；
  离线场景可用 `docker save/load` 把 GHCR 镜像导入目标机。
- 动态密钥走 `/etc/nss-ndr/.env`（`map.jinja` 的 `env_get` 宏），pillar 不放密钥。
