# nss-ndr 部署安装包（.run）

## 结构

- `install.sh`：安装器主体（嵌入 run 载荷），目标平台 Linux Anolis OS / x86_64
- `build-run.sh`：构建脚本，把 `install.sh` + `部署发布/容器镜像/*.tar` 打包成自解压 `.run`

## 构建

```bash
scripts/installer/build-run.sh            # 输出 部署发布/nss-ndr-installer-<日期>.run
scripts/installer/build-run.sh /tmp/out v1.0.0   # 自定义输出目录与版本号
```

## 使用（目标服务器）

```bash
sudo ./nss-ndr-installer-20260830.run              # 安装到默认 /opt/nss-agent
sudo ./nss-ndr-installer-20260830.run /opt/my-path  # 自定义安装目录
sudo NSS_NIC=ens192 ./nss-ndr-installer-20260830.run  # 非交互指定监控网卡
```

安装器行为：

1. 检测 docker / docker compose / salt，缺失则自动安装（docker-ce、compose v2 插件、salt-minion）
2. 创建安装目录并拷贝镜像包（默认 `/opt/nss-agent`）
3. 列出物理网卡，交互选择"流量镜像/监控网卡"（写入 `config/deploy.conf` 的 `ZEEK_INTERFACE`）
4. 关闭并禁止 firewalld 开机自启
5. `docker load` 导入全部镜像
6. 安装 Salt 状态：databus 拍平到 `/srv/salt/databus/`、agent 到 `/srv/salt/agent/`，
   pillar 放到 `/srv/pillar/`（自动生成 `top.sls`），之后可直接 masterless 部署
