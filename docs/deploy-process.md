# 开发/发布流程(铁律)

> **所有修改一律先在本地项目目录完成 → 本地 commit/push → GitHub Actions CI 构建镜像 →
> 验证服务器只做「拉取新镜像 + 同步 state + 编排部署验证」。**
> 禁止在验证服务器上直接修改代码/state 或构建镜像。

## 一、代码 / 配置改动(本地)

1. 在本地工作区修改:`src/agent/`(agent 代码/配置模板)、`src/databus/salt/`(state/scripts/files/pillar.example)、`images/`(Dockerfile/entrypoint)等。
2. `git add -A && git commit -m "..."`(提交信息写清楚动机)。
3. `git push origin main` —— 触发 `.github/workflows/build-images.yml`(paths: src/**, images/**, workflow 文件;10 个镜像 job)。

## 二、CI 构建

- `gh run list --workflow=build-images.yml --limit 3` / `gh run watch <run_id> --exit-status` 等成功。
- CI 产物推送到 `ghcr.io/cxiyuan/nss-ndr-public/<img>:sha-<commit>`(镜像站 ghcr.nju.edu.cn 同步)。
- 版本 tag(latest / 9.5.2 / 8.2.2 / 8.10.1)与 sha 指向同一 digest(用前已核验)。

## 三、验证服务器部署(只拉取,不改)

1. **同步 state/pillar 模板**:从本地(或服务器上 repo checkout)按同一 commit 复制到 `/srv/salt/`、`/srv/pillar`:
   - 本地 `scp -r src/databus/salt/{states,scripts,files}/*` → `/srv/salt/databus/`(注意 flatten 布局:states/*.sls → /srv/salt/databus/,states/containers/*.sls → containers/,teardown/ 同级)
   - `src/agent/salt/**` → `/srv/salt/agent/`
   - **pillar 是部署期配置**(含 Vault token 等秘密,**不进仓库**),按需本地手工维护 `/srv/pillar/databus.sls`(结构以仓库 `pillar.example` 为模板)。
2. **拉取新镜像**:
   - 优先镜像站:服务器 `docker pull ghcr.nju.edu.cn/cxiyuan/nss-ndr-public/<img>:sha-<commit>`;
   - 镜像站坏块回退:本地 `skopeo copy docker://ghcr.io/...:<sha> docker-archive:...:<镜像站路径tag>` → scp → `docker load`(tag 内嵌镜像站路径,保持单 tag)。
   - 需要则 `docker tag` 更新 latest 指向新 sha,删除旧 ID(保持镜像列表只含镜像站路径)。
3. **部署**:`docker exec nss-ndr-salt-master-api salt-run state.orchestrate databus.deploy`(幂等;若 minion 容器自身 spec 变更,用临时 executor minion 收敛,避免自毁)。
4. **验证**:容器状态/编排 Summary/redis lag 与 DLQ/ES verdict 质量/llm CPU 限制等(见 verify 检查清单)。

## 四、例外(不进程式但属于部署态)

- `/srv/pillar/databus.sls`(Vault token、env_file 等秘密)—— 部署机密,不进仓库,结构以 pillar.example 为准。
- `/etc/nss-ndr/.env`、`/etc/nss-ndr/*.yml` —— 运行期派生文件(Vault vault-seed / salt configs 生成)。
- Vault 容器本体(nss-vault 手工部署 + unseal)—— 属运维侧基础设施,未纳入 salt state(可后续 state 化)。

## 五、凭据安全

- 密码唯一来源 = Vault(kv-v2 nss-ndr/*);宿主不再保存 `.env-credentials`。
- Vault 管理凭据见服务器 `/root/.vault-admin`(600),建议离线保管后删除。
- 仓库严禁出现任何真实密码 / token / hvs.*(提交前 `git grep` 检查)。
