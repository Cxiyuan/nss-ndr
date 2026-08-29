# 用 SaltStack 管理数据总线（容器 + 配置文件）· 正式实现

> 适用范围：数据总线 7 容器（zeek / elasticsearch / kibana / fleet-server / elastic-agent / logstash / redis）及全部配置文件。
> 目标服务器：`172.16.199.235`（与其他业务 zabbix / grafana / postgres 共存，**不得影响**）。
> **状态：数据总线容器管理与配置管理已正式改为 Salt 管理**（本目录即实现）。原 `data-bus.yaml` 已删除，本目录是唯一实现。

---

## 1. 调研结论摘要

### 1.1 Salt 原生就支持管理 Docker，无需额外装 formula

Salt 自带一整套 docker 状态模块，覆盖数据总线需要的全部能力：

| 需要做的事 | Salt 状态模块 |
|---|---|
| 创建/删除容器 | `docker_container.running` / `docker_container.absent` |
| 创建/删除网络（含固定 IP） | `docker_network.present` / `docker_network.absent` |
| 创建/删除数据卷 | `docker_volume.present` / `docker_volume.absent` |
| 加载镜像 tar / 构建 / 拉取 | `docker_image.present`（`load` / `build` / 默认拉取） |
| 分发配置文件 | `file.managed`（从 fileserver `salt://` 下发） |
| 执行初始化命令（生成 token 等） | `cmd.run` / `module.run` |
| 等待服务就绪 | `http.wait_for_successful_query`（轮询直到成功） |
| 编排启动顺序 | 顶层 SLS 的 `require` 链 或 `orchestrate runner` |
| 周期自愈 | minion `schedule`（定期 `state.apply`）或外部 cron |

社区有 [saltstack-formulas/docker-formula](https://github.com/saltstack-formulas/docker-formula)，它封装了 docker 安装 + compose 管理，但：

- 版本老旧、封装偏重（pillar 结构复杂，compose-ng 只覆盖 compose 子集）；
- 数据总线场景是"单机 + 7 容器 + 少量外挂配置"，用**原生 docker_container 状态**更直接、可控、可审计。

**结论：不引入 docker-formula，直接用原生 docker 状态模块。**

### 1.2 版本与兼容性

- Salt 推荐 **3007.x（Argon，STS）**或更新的 **3008.x（Potassium，LTS）**。
- `docker_container` 等 docker 状态在 Salt 核心中已标记废弃，**将在 3009 移除**，迁移到官方扩展 [salt-extensions/saltext-dockermod](https://github.com/salt-extensions/saltext-dockermod)。3007/3008 仍内置，可正常使用；如要面向未来，可在 minion 上 `pip install saltext-dockermod`，状态名（`docker_container.running` 等）保持不变。
- 目标主机必须安装 Python `docker` 库（docker-py ≥ 1.6.0，建议 ≥ 7.x），Salt 通过 docker-py 与 Docker daemon 通信：
  - masterless minion：`pip3 install docker`
  - salt-ssh：同样在目标主机 `pip3 install docker`（salt-ssh 只在执行时把 thin 推上去，依赖库仍在目标机）

### 1.3 关键能力已验证（Salt 3006/3007 文档 + 源码）

| compose 字段 | Salt 写法 | 备注 |
|---|---|---|
| `network_mode: host` | `- network_mode: host` | ⚠️ host 模式下**不能设置 hostname**，也**不能用固定 IP**（zeek 正好不需要） |
| `networks: xxx: ipv4_address: 192.168.250.40` | `- networks: [nss-net: {ipv4_address: 192.168.250.40}]` | 需先创建网络，用 `require` 保证顺序 |
| `volumes:`（命名卷） | 先 `docker_volume.present` 建卷，容器里用 `- binds: [卷名:/容器路径]` | docker-py 的 binds 支持命名卷（`卷名:路径` 形式，Docker 会自动解析） |
| `binds`（bind 挂载） | `- binds: [/主机路径:/容器路径:ro]` | 支持 `ro` |
| `ports:` | `- port_bindings: [9200:9200]` | |
| `environment:` | `- environment: [KEY=value, ...]` 或 dict | |
| `command:` | `- command: [...]` | 长命令建议写成脚本文件分发（见 §4.4） |
| `cap_add:` | `- cap_add: [NET_ADMIN, NET_RAW, SYS_ADMIN]` | |
| `devices:` | `- devices: [/dev/net/tun]` | |
| `ulimits:` | `- ulimits: [memlock=-1:-1, nofile=65536:65536]` | 注意 Salt 用 `name=soft:hard` 或 `name:soft:hard` 格式 |
| `restart: unless-stopped` | `- restart_policy: unless-stopped` | 也支持 `on-failure:N` / `always` |
| `logging:` | `- log_driver: json-file` + `- log_opt: [max-size=20m, max-file=5]` | |
| `healthcheck:` | `- healthcheck: {test: [...], interval: ..., timeout: ..., retries: ...}` | ⚠️ 文档未收录但可用；**interval/timeout/start_period 单位是纳秒**（docker-py 直传 API），详见 §5.2 |
| `user: root` | `- user: root` | |
| `container_name` | SLS 状态 ID（`name`） | |

### 1.4 方案选型：salt-ssh vs salt-minion（masterless）vs master+minion

数据总线部署在**一台**服务器上，且该服务器还有其他业务。三种接入方式对比：

| 维度 | salt-ssh（无代理） | salt-minion masterless | salt-master + salt-minion |
|---|---|---|---|
| 目标机常驻进程 | 无（每次执行临时推 thin） | 有 `salt-minion` 守护进程 | 有 `salt-minion` |
| 需要外部控制机 | 需要（装有 salt-ssh 的机器/本机） | 不需要，目标机自己跑 | 需要 salt-master |
| 声明式状态 | ✅ | ✅ | ✅ |
| 周期自愈（无人值守） | 需在控制机配 cron 调 `salt-ssh` | ✅ minion `schedule` 内置 | ✅ master schedule |
| 实时事件/reactor/beacon | ❌（无常驻进程） | 部分（masterless 下 reactor 受限） | ✅ 完整 |
| 对现有业务影响 | 最小（不装任何常驻软件） | 多一个 salt-minion 服务 | 多一个 salt-minion 服务 |
| 适合场景 | 轻量、按需执行 | **单机自愈首选** | 多机规模化 |

**推荐：**

- **首选：salt-minion masterless**（`file_client: local`，状态文件放在目标机 `/srv/salt`，pillar 放 `/srv/pillar`）。目标机自己定时 `state.apply` 实现漂移自愈，不依赖外部控制机；不部署 salt-master，不引入额外单点。
- **备选：salt-ssh**（roster 方式），零常驻进程，从操作机/本机执行 `salt-ssh databus state.apply`；适合"只做初始化、不强求周期自愈"或不想在目标机装任何软件的场景。周期执行用控制机 cron。
- 将来要管多台 NDR 主机时，再把同一套 states 迁到 salt-master + minions 架构（SLS 不用改，只改 master 配置）。

---

## 2. 目录结构设计

放在仓库 `src/databus/salt/` 下（数据总线目录下与 scripts/ 平级）：

```text
src/databus/salt/
├── README.md                        # 本设计文档
├── pillar.example                   # pillar 示例（IP、密码、网卡、镜像清单）
├── roster.example                   # salt-ssh roster 示例（备选方案用）
├── minion.example                   # masterless minion 配置示例
├── files/                           # 需要下发的配置文件（从 src/databus 对应目录拷贝）
│   ├── kibana.yml
│   ├── elastic-agent-fleet-server.yml
│   ├── jvm.options
│   ├── logstash.yml / pipelines.yml / log4j2.properties
│   ├── redis.conf
│   └── zeek-local.zeek / detect.zeek
├── scripts/                         # 初始化脚本（Salt 调用）
│   ├── gen-kibana-token.sh          # Kibana 启动前：生成 KIBANA_SERVICE_TOKEN（仅需 ES）
│   └── fleet-setup.sh               # Fleet output/policy/enrollment keys/Zeek Integration
├── scripts/fleet-server-start.sh    # fleet-server 容器 entrypoint（enroll + 启动）
├── scripts/elastic-agent-start.sh   # elastic-agent 容器 entrypoint（enroll + 启动）
├── scripts/zeek-start.sh            # zeek 容器 entrypoint（抓包启动）
├── scripts/saltctl.sh               # 一键操作：deploy/apply/status/verify/teardown/pillar
└── states/
    ├── top.sls                      # 入口：databus 主状态
    ├── images.sls                   # 从 offline tar 加载 6 个镜像
    ├── network.sls                  # nss-net (192.168.250.0/24)
    ├── volumes.sls                  # 8 个命名卷
    ├── configs.sls                  # 外挂配置文件下发
    ├── bootstrap.sls                # Kibana 前：生成 KIBANA_SERVICE_TOKEN（调用 gen-kibana-token.sh）
    ├── fleet-setup.sls              # Fleet output/policy/enrollment keys/Zeek Integration
    ├── containers/
    │   ├── zeek.sls
    │   ├── elasticsearch.sls
    │   ├── redis.sls
    │   ├── kibana.sls
    │   ├── fleet-server.sls
    │   ├── elastic-agent.sls
    │   └── logstash.sls
    ├── verify.sls                   # 部署后验证（数据流 / ECS 字段）
    ├── teardown.sls                 # 一键清理本项目（容器/网络/卷），保留其他业务
    └── teardown/images.sls          # （可选）删除数据总线镜像
    └── deploy.sls                   # 编排：按依赖顺序一次性部署
```

> 镜像不随 states 走：offline tar 放在仓库 `images/offline/`，部署时通过 `file.managed`（或 scp/rsync）拷到目标机 `/opt/nss-ndr/images/`，再 `docker_image.present - load`。目标机**不重新拉取、不重新构建**。

### 2.1 fileserver 布局（masterless / salt-ssh）

Salt 的 `salt://` 路径按 file_roots 映射，本设计按如下约定组织：

```text
/srv/salt/
├── databus/            # 本目录 states/ + files/ + scripts/ 的内容
│   ├── states/  -> salt://databus/states/   （SLS 实际用 databus.* 前缀）
│   ├── files/   -> salt://databus/files/
│   └── scripts/ -> salt://databus/scripts/
└── offline/            # images/offline/*.tar 拷贝到此 -> salt://offline/
```

部署时按如下映射拷贝（仓库目录 → 目标机 fileserver）：

```text
src/databus/salt/states/*           -> /srv/salt/databus/        （含 map.jinja，SLS 用 databus.* 前缀）
src/databus/salt/states/containers/ -> /srv/salt/databus/containers/
src/databus/salt/files/*            -> /srv/salt/databus/files/
src/databus/salt/scripts/*          -> /srv/salt/databus/scripts/
images/offline/*.tar           -> /srv/salt/offline/
```

> 说明：仓库里把 states 放在 `salt/states/` 子目录只是便于组织；落盘到 fileserver 时**必须拍平**成 `/srv/salt/databus/`（`map.jinja` 与 `top.sls`、`images.sls` 同级），否则 `{% from "databus/map.jinja" %}` 和 `state.apply databus.deploy` 的路径解析会不一致。

> 注意：`images.sls` 里 `source: salt://offline/<tar>` 依赖 offline tar 已在 fileserver 中；首次部署也可用 scp 直传 `/opt/nss-ndr/images/` 后把 `images.sls` 的 `file.managed` 步骤去掉（`docker_image.present - load` 直接加载本地 tar）。

---

## 3. 目录结构与 pillar 设计

### 3.1 pillar.example（节选）

```yaml
# pillar.example —— 复制到 /srv/pillar/databus.sls（masterless 时即本机）
databus:
  env_file: /etc/nss-ndr/.env          # 运行时环境变量文件（含动态 token）
  base_dir: /opt/nss-ndr               # 目标机工作目录
  images_dir: /opt/nss-ndr/images      # 镜像 tar 存放目录
  network:
    name: nss-net
    subnet: 192.168.250.0/24
  tz: Asia/Shanghai
  zeek_interface: ens192
  creds:                               # 静态口令（动态 token 见 §4.3）
    elastic_password: ChangeMe_Elastic_2026!
    redis_password: ChangeMe_Redis_2026!
    kibana_encryption_key: NSS-NDR-Default-Kibana-Encryption-Key-2026!
  images:                              # image 名 → tar 文件
    - name: nss-ndr/zeek:8.2.2
      tar: nss-ndr_zeek_8.2.2.tar
    - name: docker.elastic.co/elasticsearch/elasticsearch:9.5.2
      tar: docker.elastic.co_elasticsearch_elasticsearch_9.5.2.tar
    - name: docker.elastic.co/kibana/kibana:9.5.2
      tar: docker.elastic.co_kibana_kibana_9.5.2.tar
    - name: nss-ndr/elastic-agent-zeek:9.5.2
      tar: nss-ndr_elastic-agent-zeek_9.5.2.tar
    - name: nss-ndr/logstash-databus:9.5.2
      tar: nss-ndr_logstash-databus_9.5.2.tar
    - name: nss-ndr/redis-databus:8.10.1
      tar: nss-ndr_redis-databus_8.10.1.tar
  fixed_ips:
    elasticsearch: 192.168.250.40
    kibana: 192.168.250.50
    fleet_server: 192.168.250.55
    elastic_agent: 192.168.250.20
    logstash: 192.168.250.30
    redis: 192.168.250.60
  # 宿主机端口映射（仅监听 127.0.0.1，外部不可达；容器间走 nss-net 内网）
  host_ports:
    es: 9200
    kibana: 5601
    fleet_server: 8220
    redis: 6379
  host_bind: 127.0.0.1
```

---

## 4. 核心 SLS 设计

### 4.1 镜像加载 images.sls（关键：直接 load tar，不拉取不构建）

```yaml
{% from "databus/map.jinja" import databus with context %}

{% for img in databus.images %}
load-image-{{ img.name | replace('/', '_') | replace(':', '_') }}:
  file.managed:
    - name: {{ databus.images_dir }}/{{ img.tar }}
    - source: salt://offline/{{ img.tar }}
    - makedirs: True
  docker_image.present:
    - name: {{ img.name }}
    - load: {{ databus.images_dir }}/{{ img.tar }}
    - require:
      - file: load-image-{{ img.name | replace('/', '_') | replace(':', '_') }}
{% endfor %}
```

> `docker_image.present` 会先检查镜像是否已存在；不存在才执行 `load`。tar 已存在时 `file.managed` 幂等跳过。
> 实际实现放在 `states/images.sls`，用 map.jinja 统一取值（示例见本目录 `states/`）。

### 4.2 网络与卷

```yaml
# network.sls
nss-net:
  docker_network.present:
    - driver: bridge
    - ipam:
        config:
          - subnet: 192.168.250.0/24

# volumes.sls
nss-ndr-zeek-logs:
  docker_volume.present
nss-ndr-es-data:
  docker_volume.present
... # 共 8 个卷
```

### 4.3 容器示例（elasticsearch 与 zeek）

```yaml
# containers/elasticsearch.sls
{% from "databus/map.jinja" import databus with context %}

nss-ndr-elasticsearch:
  docker_container.running:
    - image: docker.elastic.co/elasticsearch/elasticsearch:9.5.2
    - restart_policy: unless-stopped
    - user: root
    - environment:
        - discovery.type=single-node
        - xpack.security.enabled=true
        - xpack.security.http.ssl.enabled=false
        - xpack.license.self_generated.type=basic
        - xpack.ml.enabled=false
        - ELASTIC_PASSWORD={{ databus.creds.elastic_password }}
        - ES_JAVA_OPTS=-Xms2g -Xmx4g
    - ulimits:
        - memlock=-1:-1
        - nofile=65536:65536
    - binds:
        - nss-ndr-es-data:/usr/share/elasticsearch/data
        - nss-ndr-es-backup:/usr/share/elasticsearch/backup
    - port_bindings:
        - "{{ databus.host_bind }}:{{ databus.host_ports.es }}:9200"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.elasticsearch }}
    - log_driver: json-file
    - log_opt:
        - max-size=20m
        - max-file=5
    - healthcheck:
        - test: ["CMD-SHELL", "curl -fsS -u elastic:{{ databus.creds.elastic_password }} http://localhost:9200/_cluster/health | grep -qE 'green|yellow'"]
        - interval: 30000000000      # 30s（纳秒）
        - timeout: 15000000000       # 15s
        - retries: 20
        - start_period: 120000000000 # 120s
    - require:
      - docker_network: nss-net
      - docker_volume: nss-ndr-es-data
      - docker_image: docker.elastic.co/elasticsearch/elasticsearch:9.5.2
```

```yaml
# containers/zeek.sls —— host 网络 + 抓包权限
nss-ndr-zeek:
  docker_container.running:
    - image: nss-ndr/zeek:8.2.2
    - restart_policy: unless-stopped
    - network_mode: host            # 不走 nss-net，直接监听宿主机 ens192
    - cap_add:
        - NET_ADMIN
        - NET_RAW
        - SYS_ADMIN
    - devices:
        - /dev/net/tun
    - binds:
        - nss-ndr-zeek-logs:/opt/zeek/logs
    - environment:
        - TZ={{ databus.tz }}
        - ZEEK_INTERFACE={{ databus.zeek_interface }}
        - ZEEK_LOG_DIR=/opt/zeek/logs
    - command: /opt/nss-ndr/bin/zeek-run.sh   # 启动脚本（分发到目标机，见 §4.4）
    - require:
      - docker_volume: nss-ndr-zeek-logs
      - docker_image: nss-ndr/zeek:8.2.2
```

> ⚠️ `network_mode: host` 时不能设置 `hostname`，也不能配置 `networks` 固定 IP —— 与原始编排定义中 zeek 的定义一致。

### 4.4 长命令容器（fleet-server / elastic-agent / redis）改为脚本文件

compose 里 fleet-server / elastic-agent 的 `command` 是几十行 bash（enroll 逻辑）。**注意：`nss-ndr/elastic-agent-zeek` 镜像只内置了 Zeek Integration 包，没有内置 enroll 逻辑**，所以 Salt 版把这套逻辑固化为启动脚本，由 Salt 下发到目标机 `/opt/nss-ndr/scripts/` 并挂载进容器作为 `entrypoint`：

- `fleet-server-start.sh`：无 fleet.enc 则 `elastic-agent enroll --fleet-server-*`，再以 fleet-server 模式启动（与原始编排定义等效）
- `elastic-agent-start.sh`：无 fleet.enc 则 enroll 到 fleet-server:8220，再 `elastic-agent run`
- `zeek-start.sh`：`export PATH` + `exec zeek -i $ZEEK_INTERFACE local.zeek`
- redis 命令较短，保持内联 `command`

```yaml
nss-ndr-fleet-server:
  docker_container.running:
    - image: nss-ndr/elastic-agent-zeek:9.5.2
    - user: root
    - restart_policy: unless-stopped
    - binds:
        - nss-ndr-fleet-server-data:/usr/share/elastic-agent/data
        - /etc/nss-ndr/elastic-agent-fleet-server.yml:/usr/share/elastic-agent/elastic-agent.yml:ro
        - /opt/nss-ndr/scripts/fleet-server-start.sh:/opt/nss-ndr/scripts/fleet-server-start.sh:ro
    - environment:
        - TZ={{ databus.tz }}
        - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
        - ELASTICSEARCH_USERNAME=elastic
        - ELASTICSEARCH_PASSWORD={{ databus.creds.elastic_password }}
        - KIBANA_HOST=http://kibana:5601
        - FLEET_URL=https://fleet-server:8220
        - FLEET_ENROLLMENT_TOKEN={{ env_get('FLEET_ENROLLMENT_TOKEN') }}
    - entrypoint: /opt/nss-ndr/scripts/fleet-server-start.sh
        - FLEET_SERVER_ENABLE=true
        - FLEET_SERVER_POLICY_NAME=nss-ndr-fleet-server-policy
    - port_bindings:
        - "{{ databus.host_ports.fleet_server }}:8220"
    - networks:
        - nss-net:
            - ipv4_address: {{ databus.fixed_ips.fleet_server }}
    - require:
      - docker_network: nss-net
      - docker_container: nss-ndr-elasticsearch
      - docker_container: nss-ndr-kibana
```

### 4.5 配置文件分发 configs.sls

只保留**必须外挂**的（已确认清单）：

| 文件 | 挂载到 | 是否需要按环境改 |
|---|---|---|
| `kibana.yml` | `/usr/share/kibana/config/kibana.yml:ro` | 部分（fingerprint 等） |
| `elastic-agent-fleet-server.yml` | `/usr/share/elastic-agent/elastic-agent.yml:ro` | 部分 |
| `logstash/config/jvm.options` | `/usr/share/logstash/config/jvm.options:ro` | 是（JVM 内存） |
| `logstash/config/logstash.yml` 等 | `/usr/share/logstash/config/` | 否（已进镜像则跳过） |
| `redis.conf` | 已进镜像 | 否 |
| `zeek/local.zeek` | 已进镜像 | 否 |

```yaml
/etc/nss-ndr/kibana.yml:
  file.managed:
    - source: salt://databus/files/kibana.yml
    - user: root
    - group: root
    - mode: 644
```

---

## 5. 动态 token（KIBANA_SERVICE_TOKEN / FLEET_ENROLLMENT_TOKEN / ELASTIC_AGENT_ENROLLMENT_TOKEN）

### 5.1 事实

- 这三个 token 每次部署由 ES / Kibana **动态生成**，写死在 pillar 里没有意义（之前已确认"接受这种 token 写入方式"）。
- 原 `scripts/auto-init.sh` / `bootstrap-tokens.sh` 已实现"生成 → 写回 .env"逻辑，已按职责拆分并迁入 `salt/scripts/`：`gen-kibana-token.sh`（Kibana 前，仅需 ES）+ `fleet-setup.sh`（Kibana 后，policy/key/Integration），避免原 bootstrap-tokens.sh 依赖 Kibana 而编排在 Kibana 前调用会超时的问题。

### 5.2 Salt 下的处理方案（推荐）

编排（`deploy.sls`）按阶段执行，阶段之间用 `require` 保证顺序，token 写入 `/etc/nss-ndr/.env`，**后续容器状态在渲染时读取该文件**：

```yaml
# states/bootstrap.sls —— 生成 KIBANA_SERVICE_TOKEN 并写回 .env
generate-kibana-token:
  cmd.run:
    - name: |
        /opt/nss-ndr/scripts/gen-kibana-token.sh && \
        sed -i "s/^KIBANA_SERVICE_TOKEN=.*/KIBANA_SERVICE_TOKEN=$(grep ...)/" /etc/nss-ndr/.env
    - unless: test -f /etc/nss-ndr/.bootstrap.done   # 幂等：完成一次后不再重复生成
    - require:
      - docker_container: nss-ndr-elasticsearch
```

```yaml
# map.jinja / jinja 渲染时读取已生成的 token
{%- set env = salt['file.read']('/etc/nss-ndr/.env') if salt['file.file_exists']('/etc/nss-ndr/.env') else '' %}
{%- set fleet_token = salt['file.search']('/etc/nss-ndr/.env', 'FLEET_ENROLLMENT_TOKEN=(.*)') %}
```

**关键点**：`deploy.sls` 编排里，`containers/fleet-server.sls`、`containers/elastic-agent.sls`、`containers/kibana.sls` 是编排中**后执行的独立 `salt.state` 调用**，它们各自在被执行时才渲染，此时 `.env` 已由前序阶段写好了，所以能读到最新 token。这是 Salt 里处理"运行时动态值"的标准做法（文件传递法）。

编排顺序（`states/deploy.sls`，orchestrate 风格）：

```yaml
# states/deploy.sls（orchestrate 风格，masterless 下用 salt-ssh / salt-call 执行）
deploy-images:   salt.state -> images.sls
deploy-network:  salt.state -> network.sls      (require: deploy-images)
deploy-volumes:  salt.state -> volumes.sls
deploy-configs:  salt.state -> configs.sls
deploy-es-redis: salt.state -> containers.elasticsearch, containers.redis
wait-es:         http.wait_for_successful_query  (http://localhost:9200/_cluster/health, auth=elastic)
deploy-bootstrap-token: salt.state -> bootstrap.sls   (生成 KIBANA_SERVICE_TOKEN)
deploy-kibana:   salt.state -> containers.kibana
wait-kibana:     http.wait_for_successful_query  (http://localhost:5601/api/status)
deploy-fleet-setup: salt.state -> fleet-setup.sls     (创建 output/policy/enrollment keys/Zeek Integration, 复用 auto-init.sh 的 API 逻辑)
deploy-apps:     salt.state -> containers.fleet-server, containers.elastic-agent, containers.logstash, containers.zeek
verify:          salt.state -> verify.sls
```

执行方式说明：

- **masterless**：`salt-call --local state.apply databus.deploy` 即可。`salt.state` 在 masterless 下会**忽略 tgt、始终在本地执行**，且每次触发一次全新的状态运行 → 渲染时机正确，能读到前序阶段写入的 token。
- **salt-ssh**：从装有 salt-master（配 ssh roster）的控制机跑 `salt-run state.orchestrate databus.deploy`；或由驱动脚本分阶段调用 `salt-ssh databus state.apply databus.<阶段>`。
- **master+minion**：`salt-run state.orchestrate databus.deploy`，`tgt` 生效。

> 注意：不能把"生成 token 的 cmd.run"和"读取 token 的容器 SLS"放在**同一次** state 运行里 —— Salt 会先渲染全部 SLS 再执行，token 文件此时还不存在，读到的会是空值。这也是必须用编排（每个阶段独立运行）的原因。

---

## 6. 健康检查与自愈

### 6.1 容器退出重启

`docker_container.running` 的 `restart_policy: unless-stopped` 与 compose 一致，容器进程退出（含崩溃）由 Docker 自动拉起。这一层**不需要 Salt 参与**。

### 6.2 健康检查（healthcheck）

- Salt 的 `healthcheck` 参数**可传但官方文档未收录**（GitHub issue #53511），它是透传给 docker-py `create_container` 的：
  - `test`、`interval`、`timeout`、`retries`、`start_period`
  - ⚠️ **interval / timeout / start_period 单位是纳秒**（Docker API 直接收整数纳秒），如 `30s → 30000000000`。这是最常见的踩坑点。
- 若觉得纳秒不直观，也可以**不用 Salt 的 healthcheck**，在镜像 Dockerfile 里已定义（本项目的镜像均已内置 healthcheck 时则完全不需要）。

### 6.3 unhealthy 但未退出的容器

Docker 的 restart_policy **不会**因为 unhealthy 而重启。两种方案：

1. **周期 state.apply（推荐，masterless minion 内置 schedule）**：
   ```yaml
   # /etc/salt/minion.d/schedule.conf
   schedule:
     databus-highstate:
       function: state.apply
       args: [databus]
       hours: 1
   ```
   Salt 每次 apply 会对比容器期望配置，配置漂移会被修正；再配合一个小的健康检查 state（探测 unhealthy 则 `cmd.run: docker restart <容器>`）实现真正自愈。
2. **外部 cron + 脚本**：控制机 cron 每 5 分钟 `salt-ssh ... state.apply databus.healthcheck` 或直接跑健康检查脚本。

3.（进阶）**reactor**：master+minion 架构下用 docker engine 事件 + reactor 自动 restart；masterless 下不适用，本项目不采用。

---

## 7. 风险与注意事项

1. **zeek 使用 host 网络**：`network_mode: host` 与 hostname、固定 IP 冲突，SLS 里 zeek 不能写这两项（与 compose 一致）。
2. **命名卷引用**：Salt 的 `binds` 直接写 `卷名:/容器路径` 即可，Docker 自动按命名卷解析；但卷必须先用 `docker_volume.present` 创建，并用 `require` 保证顺序。
3. **镜像只 load 不拉取**：目标机需先有 6 个 tar（`images/offline/`）。`docker_image.present` 的 `load` 只在该镜像不存在时执行；换镜像版本时改 pillar 里的 `images` 列表即可。
4. **不碰其他业务**：Salt 只管理本项目命名空间（`nss-ndr-*` 容器/卷/网络 + `/opt/nss-ndr` + `/etc/nss-ndr`），不设置全局 docker prune；`docker_container.absent` 只针对本项目容器。卸载 Salt 不会影响 zabbix/grafana/postgres。
5. **masterless 无 reactor**：若以后要实时事件自愈，升级为 master+minion 即可，SLS 复用。
6. **salt-ssh 的 thin 模式**：每次执行推送 thin 到目标机，稍慢（几十秒级），适合初始化/按需执行；周期自愈请用 masterless schedule 或控制机 cron。
7. **docker-py 版本**：目标机 `pip3 install docker`（≥7.x），否则部分参数（如 healthcheck）可能不生效。
8. **token 幂等**：`bootstrap.sls` 用 `creates`/`unless` 保证只生成一次；重装（从零部署）时删掉 `/etc/nss-ndr/.env` 及 token 标记文件即可重新生成。

---

## 8. 与现有资产的衔接

**原 `data-bus.yaml` 已删除**：容器定义以 `salt/states/` 为唯一实现，不再保留 compose 参照文件。

| 现有资产 | Salt 中如何使用 |
|---|---|
| `src/databus/scripts/`（auto-init.sh / bootstrap-tokens.sh，已移除） | 功能被 Salt 完全接管：编排 `deploy.sls` + `bootstrap.sls`（gen-kibana-token.sh）+ `fleet-setup.sls`（fleet-setup.sh）+ `verify.sls`；目录仅保留迁移说明 README |
| `images/offline/*.tar`（6 个有效镜像） | `file.managed` 下发 + `docker_image.present - load` |
| `src/databus/*.yml` / `kibana.yml` 等 | `file.managed` 下发到 `/etc/nss-ndr/`，再 binds 进容器 |
| ~~`data-bus.yaml`~~ | **已删除**：容器定义以 `salt/states/` 为唯一实现 |

---

## 9. 落地路径（供后续执行，不在本次实施）

1. 选定接入方式：**masterless minion（推荐）** 或 **salt-ssh**。
2. 目标机准备：安装 salt-minion（masterless）或仅装 docker-py（salt-ssh）；`mkdir /opt/nss-ndr /etc/nss-ndr`。
3. 上传：offline tar → `/opt/nss-ndr/images/`；states/pillar/files → `/srv/salt`、`/srv/pillar`（masterless 本机，或 salt-ssh 从控制机下发）。
4. 首跑：`salt-call --local state.apply databus.deploy`（masterless）或 `salt-ssh databus state.apply databus.deploy`。
5. 验证：`verify.sls` 检查 agent online、`.ds-logs-zeek.*` 数据流、ECS 字段归一化。
6. 开启周期自愈：minion `schedule` 每小时 `state.apply databus`（或控制机 cron）。
7. 回滚：Salt 一键 `docker_container.absent` 只清本项目容器，保留其他业务。

### 日常操作速查（`scripts/saltctl.sh`）

```bash
./saltctl.sh deploy    # 从零部署 / 完整初始化（编排）
./saltctl.sh apply     # 日常幂等自愈
./saltctl.sh status    # 查看本项目容器状态
./saltctl.sh verify    # 验证数据流 / ECS 字段
./saltctl.sh teardown  # 清理本项目容器/网络/卷（保留其他业务）
./saltctl.sh pillar    # 查看 pillar
```
