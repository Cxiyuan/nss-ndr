# 内置 Sigma 事件告警规则库（产品规则库）

本目录存放随产品版本维护的内置 Sigma 规则（事件告警），由 ndr-manager 启动时同步到 SQLite：

- 规则文件：`.yml` / `.yaml`（标准 Sigma YAML，支持本项目扩展的 `correlation` 关联规则段）
- 规则 ID：优先取 YAML 中的 `id` 字段；缺失时按内容哈希生成稳定 ID
- 同步策略：`INSERT ... ON CONFLICT(id) DO UPDATE` 更新标题/内容等字段，**保留用户启停状态**
- 权限边界：内置规则仅可启停（enable/disable），WebUI 与 API 均禁止编辑/删除
- 默认启停：`status: stable` 的规则首次导入默认启用；`test`/`experimental` 默认禁用

产品发布新规则时，直接在此目录新增/更新规则文件并随镜像版本发布即可。
