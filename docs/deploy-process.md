# 开发/发布流程(铁律)

> **所有修改一律先在本地项目目录完成 → 本地 commit/push → GitHub Actions CI 构建镜像 →
> 验证服务器只做「拉取新镜像 + 同步 state + 编排部署验证」。**
> 禁止在验证服务器上直接修改代码/state 或构建镜像。
>
> 本项目只负责 **数据总线（zeek → logstash/elastic-agent → elasticsearch）+ 本地边缘 LLM 推理服务（llm-server）**，
> 输出数据源供下游智能体/分析方消费；智能体本身不在本项目范围内。

## 一、代码 / 配置改动(本地)

1. 在本地工作区修改:`src/databus/`(zeek 配置/logstash pipeline/salt state/scripts/files/pillar.example)、`images/`(Dockerfile/entrypoint)等。
2. `git add -A && git commit -m "..."`(提交信息写清楚动机)。
3. `git push origin main` —— 触发 `.github/workflows/build-images.yml`(paths: src/databus/**, images/**, workflow 文件)。

## 二、CI 构建

- `gh run list --workflow=build-images.yml --limit 3` / `gh run watch <run_id> --exit-status` 等成功。
- CI 产物推送到 `ghcr.io/cxiyuan/nss-ndr-public/<img>:sha-<commit>`(镜像站 ghcr.nju.edu.cn 同步)。
- 版本 tag(latest / 9.5.2 / 8.2.2 / 8.10.1)与 sha 指向同一 digest(用前已核验)。

## 三、验证服务器部署(只拉取,不改)

1. **同步 state/pillar 模板**：用 `scripts/sync-salt.sh`（推荐，避免手工 scp 漏文件）：
   ```bash
   SSH_PASS='<密码>' scripts/sync-salt.sh root@<服务器IP> [--prune] [--with-images]
   ```
   映射（salt fileserver 的路径约定）：
   - `src/databus/salt/states/` → `/opt/nss/ndr/salt/file_roots/databus/`
     （顶层 .sls/jinja flatten；`containers/`、`teardown/` 保持子目录）
   - `src/databus/salt/files/` → `/opt/nss/ndr/salt/file_roots/databus/files/`
   - `pillar.example` → `/opt/nss/ndr/salt/pillar_roots/databus.sls.example`（仅模板）
   - `pillar_roots/top.sls` 缺失时自动创建；**不会覆盖** `pillar_roots/databus.sls`
   - 同步后自动清 salt master 的 fileserver 缓存（`--no-cache-clear` 可关）
   - `--prune` 删除服务器上仓库已不存在的 `.sls`/`.jinja`
   - **pillar 是部署期配置**（含 Vault token 等秘密，**不进仓库**），按 `databus.sls.example` 本地维护。
2. **拉取新镜像**：
   - 优先：服务器 `docker pull ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/<img>:<tag>`；
   - **服务器网不通时**（本项目现场就长期如此）：在**网络正常的机器**上下载离线包再传：
     ```bash
     scripts/fetch-all-images.sh docker          # 全部镜像 → docker/*.tar.gz（本机无需 docker）
     scripts/sync-salt.sh root@<IP> --with-images # 分片传输 + 服务器 docker load
     ```
     说明：`fetch-image.py` 直接调 GHCR Registry API（token→manifest→blobs）并打
     **docker save 格式** tar.gz（服务器 docker 26.1.3 **不吃 OCI 布局**）；传输按 8MB 分片
     （整文件在弱网下易卡死，分片可重试）。
3. **部署**：`docker exec nss-ndr-salt-master-api salt-run state.orchestrate databus.deploy`
   （幂等；若 minion 容器自身 spec 变更（如 salt 镜像更新），用临时 executor minion 收敛，避免自毁）。
4. **验证**:容器状态/编排 Summary/`.ds-logs-zeek.*` 数据流/ECS 字段归一化/llm CPU 限制等(见 `verify.sls` 检查清单)。

## 四、例外（不进程式但属于部署态）

- `/opt/nss/ndr/salt/pillar_roots/databus.sls`（Vault token、env_file 等秘密）—— 部署机密，不进仓库，结构以 `pillar.example` 为准。
- 镜像离线包 `docker/*.tar.gz`（由 `scripts/fetch-image.py` 生成）—— 本机→服务器传输用，不入库（已 .gitignore）。
- `/etc/nss-ndr/.env`、`/etc/nss-ndr/*.yml` —— 运行期派生文件(Vault vault-seed / salt configs 生成)。
- Vault 容器本体(nss-vault 手工部署 + unseal)—— 属运维侧基础设施,未纳入 salt state(可后续 state 化)。

## 五、凭据安全

- 密码唯一来源 = Vault(kv-v2 nss-ndr/*);宿主不再保存 `.env-credentials`。
- Vault 管理凭据见服务器 `/root/.vault-admin`(600),建议离线保管后删除。
- 仓库严禁出现任何真实密码 / token / hvs.*(提交前 `git grep` 检查)。
