# 用 SaltStack 管理智能体（容器 + 配置文件）· 正式实现

> 适用范围：智能体 1 容器（`nss-ndr-agent`）+ 配置文件 + 镜像离线 tar。
> 目标服务器：`172.16.199.235`（masterless salt-minion，与数据总线同机，**不得影响**数据总线与其他业务）。
> 前置条件：数据总线已由 `src/databus/salt/` 部署并正常生产（ES / Redis / `nss-ndr-databus-net` / `/etc/nss-ndr/.env`）。

## 部署拓扑

```text
nss-ndr-agent（192.168.250.80，加入 nss-ndr-databus-net）
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
# 1. 上传镜像 tar
mkdir -p /root/nss-agent && scp images/offline/nss-ndr_agent_0.1.1.tar root@172.16.199.235:/root/nss-agent/
# 2. 上传 salt states / pillar
scp -r salt/states/* salt/files salt/scripts root@172.16.199.235:/srv/salt/agent/
scp salt/pillar.example root@172.16.199.235:/srv/pillar/agent.sls
# 3. 更新 top.sls / pillar top.sls，然后：
salt-call --local state.apply agent.deploy
```

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
| `EDGE_LLM_BASE_URL` / `EDGE_LLM_API_KEY` / `EDGE_LLM_MODEL` | 本地边缘模型 OpenAI 兼容接口 |
| `CLOUD_LLM_BASE_URL` / `CLOUD_LLM_API_KEY` / `CLOUD_LLM_MODEL` | 云端高阶模型接口 |
| `AGENT_DRY_RUN` | `1`=只读消费（不写结论/不 XACK）；`0`=生产写回（默认上线前先 `1`） |

模型接口未配置时，规则直接判定（BEH-005 等）与基线异常检测仍工作；依赖模型的场景输出 `uncertain`。

## 风险与注意事项

- 只管理 `nss-ndr-agent` 容器与 `/etc/nss-ndr/agent` 配置，不触碰数据总线 7 容器与其他业务。
- 复用数据总线 `nss-ndr-databus-net`，固定 IP `.80`（已确认未被占用）。
- 镜像只 load 不拉取：tar 在 `/root/nss-agent/`，换版本改 `pillar.example` 的 images 清单。
- 动态密钥走 `/etc/nss-ndr/.env`（`map.jinja` 的 `env_get` 宏），pillar 不放密钥。
