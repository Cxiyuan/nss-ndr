## === JSON 输出 redef（必须最早期执行，在 base init 之前）===
redef LogAscii::use_json = T;
redef LogAscii::enable_utf_8 = T;
redef Log::default_logdir = "/opt/zeek/logs";

## === 默认协议加载 ===
@load base/protocols/conn
@load base/protocols/http
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/syslog
@load base/frameworks/sumstats

## === 自定义检测脚本 ===
@load ./scripts/detect.zeek
