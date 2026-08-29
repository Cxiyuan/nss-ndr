# 数据总线脚本 · 已迁移至 Salt 管理

> 本目录原来的 `auto-init.sh` 和 `bootstrap-tokens.sh` 已被 Salt 完全接管并移除，
> 所有初始化脚本统一由 `../salt/scripts/` 管理，Salt 负责调度、幂等与编排。

## 脚本职责映射（原脚本 → Salt 实现）

| 原脚本/步骤 | Salt 接管方式 |
|---|---|
| `auto-init.sh`（全流程） | `../salt/states/deploy.sls` 编排：images → network → volumes → ES/Redis → 生成 token → Kibana → Fleet 初始化 → 其余容器 → 验证 |
| `auto-init.sh` 第 3 步（生成 KIBANA_SERVICE_TOKEN，仅需 ES） | `../salt/scripts/gen-kibana-token.sh` + `states/bootstrap.sls`（Kibana 启动前执行） |
| `auto-init.sh` 第 6~9 步（Fleet output/policy/enrollment keys/Zeek Integration，需 Kibana） | `../salt/scripts/fleet-setup.sh` + `states/fleet-setup.sls`（Kibana 启动后执行） |
| `auto-init.sh` 第 10~12 步（启动剩余容器/等待/验证） | `deploy.sls` + `states/verify.sls` |
| `bootstrap-tokens.sh`（等 Kibana + 建 policy/key） | 职责拆分：生成 token → `gen-kibana-token.sh`；policy/key → `fleet-setup.sh`（消除重复） |

## 当前脚本清单（以 `../salt/scripts/` 为准）

- `gen-kibana-token.sh`：Kibana 启动前，生成 `KIBANA_SERVICE_TOKEN` 写 `.env`（仅需 ES）
- `fleet-setup.sh`：Kibana 启动后，创建 Fleet output / policies / enrollment keys / Zeek Integration
- `fleet-server-start.sh` / `elastic-agent-start.sh` / `zeek-start.sh`：容器 entrypoint（enroll + 启动）
- `saltctl.sh`：一键操作 `deploy / apply / status / verify / teardown / pillar`

## 日常用法

```bash
# 在目标机（masterless）或控制机（salt-ssh）上
cd ../salt
./scripts/saltctl.sh deploy     # 从零部署 / 完整初始化
./scripts/saltctl.sh apply      # 日常幂等自愈
./scripts/saltctl.sh teardown   # 清理本项目（保留其他业务）
```

> 详细设计见 `../salt/README.md`。
