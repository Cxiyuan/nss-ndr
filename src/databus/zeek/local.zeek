## === JSON 输出 redef（必须最早期执行，在 base init 之前）===
redef LogAscii::use_json = T;
redef LogAscii::enable_utf_8 = T;
## 强制所有日志文件名带 .log 后缀（默认 known_hosts / known_services / capture_loss
## / reporter / loaded_scripts / packet_filter 等是无后缀的），以便与 Elastic Agent
## Zeek Integration 5.0.1 manifest.yml 中 filenames.default（全部 *.log）对齐。
redef Log::default_logdir = "/usr/local/zeek/logs";

## === 协议 / 框架加载（覆盖 Zeek Integration 5.0.1 全部 43 个 dataset）===
## 协议解析
@load base/protocols/conn
@load base/protocols/dce-rpc
@load base/protocols/dhcp
@load base/protocols/dnp3
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/krb
@load base/protocols/modbus
@load base/protocols/mysql
@load base/protocols/ntlm
@load base/protocols/ntp
# @load base/protocols/ocsp (zeek 8.x removed)
# @load base/protocols/pe (zeek 8.x removed)
@load base/protocols/radius
@load base/protocols/rdp
@load base/protocols/rfb
@load base/protocols/sip
@load base/protocols/smb
@load base/protocols/smtp
@load base/protocols/snmp
@load base/protocols/socks
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/syslog
# @load base/protocols/tunnel (zeek 8.x removed)

## 框架/日志源（覆盖 zeek.capture_loss / known_* / weird / notice / x509 / software / stats / traceroute 等）
# @load base/frameworks/capture-loss (zeek 8.x removed)
# @load base/frameworks/dpd (zeek 8.x removed)
@load base/frameworks/files
@load base/frameworks/intel
# @load base/frameworks/known-certs (zeek 8.x removed)
# @load base/frameworks/known-hosts (zeek 8.x removed)
# @load base/frameworks/known-services (zeek 8.x removed)
@load base/frameworks/notice
# @load base/frameworks/signature (zeek 8.x removed)
@load base/frameworks/software
@load base/frameworks/sumstats
# @load base/frameworks/traceroute (zeek 8.x removed)
# @load base/frameworks/weird (zeek 8.x removed; weird 由 conn 解析器间接触发)
# @load base/protocols/x509

## === Notice::policy（生成 notice 事件；必须位于 base/frameworks/notice 之后）===
@load policy/misc/capture-loss                       ## 抓包丢失告警（依赖 Notice::Too_Much_Loss / Too_Little_Traffic）
@load policy/misc/loaded-scripts                     ## 输出 loaded_scripts.log（运维调试，确认 @load 是否生效）
@load policy/protocols/ssh/detect-bruteforcing       ## SSH 暴力破解（与智能体 zeek.ssh≥20 互补）
@load policy/protocols/ssl/validate-certs            ## TLS 证书验证失败
@load policy/protocols/ftp/detect                    ## FTP 明文密码告警
@load policy/protocols/http/detect-sql-injection     ## SQL 注入
@load policy/protocols/http/detect-webapps           ## Web 应用攻击（含 XSS 等）

## === 自定义检测脚本 ===
# @load ./scripts/detect.zeek
