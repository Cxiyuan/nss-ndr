##! NSS-NDR Zeek 站点策略（M0 最小集）

@load misc/loaded-scripts
@load misc/capture-loss

# Community ID（内置）+ 扩展
@load policy/frameworks/notice/community-id
@load policy/protocols/conn/community-id-logging

# NSS-NDR 自研策略
@load securityonion/json-logs
@load securityonion/conn-add-sensorname
@load securityonion/community-id-extended
@load securityonion/bpfconf
@load securityonion/file-extraction

# 指纹与协议插件（so-zeek 基础镜像已安装，按需启用）
@load ja3
@load ja4
@load hassh
@load oui-logging

redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef CaptureLoss::watch_interval = 5 mins;
