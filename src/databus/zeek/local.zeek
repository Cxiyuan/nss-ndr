## === JSON 输出 redef（必须最早期执行，在 base init 之前）===
redef LogAscii::use_json = T;
redef LogAscii::enable_utf_8 = T;
## 强制所有日志文件名带 .log 后缀（默认 known_hosts / known_services / capture_loss
## / reporter / loaded_scripts / packet_filter 等是无后缀的），以便与 Elastic Agent
## Zeek Integration 5.0.1 manifest.yml 中 filenames.default（全部 *.log）对齐。
redef LogAscii::log_ext = ".log";
redef Log::default_logdir = "/opt/zeek/logs";

## === 协议 / 框架加载（覆盖 Zeek Integration 5.0.1 全部 43 个 dataset）===
## 协议解析
@load base/protocols/conn
@load base/protocols/dce_rpc
@load base/protocols/dhcp
@load base/protocols/dnp3
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/kerberos
@load base/protocols/modbus
@load base/protocols/mysql
@load base/protocols/ntlm
@load base/protocols/ntp
@load base/protocols/ocsp
@load base/protocols/pe
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
@load base/protocols/tunnel

## 框架/日志源（覆盖 zeek.capture_loss / known_* / weird / notice / x509 / software / stats / traceroute 等）
@load base/frameworks/capture-loss
@load base/frameworks/dpd
@load base/frameworks/files
@load base/frameworks/intel
@load base/frameworks/known-certs
@load base/frameworks/known-hosts
@load base/frameworks/known-services
@load base/frameworks/notice
@load base/frameworks/signatures
@load base/frameworks/software
@load base/frameworks/sumstats
@load base/frameworks/traceroute
@load base/frameworks/weird
@load base/protocols/x509

## === 自定义检测脚本 ===
@load ./scripts/detect.zeek
