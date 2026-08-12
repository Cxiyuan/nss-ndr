##! NSS-NDR Zeek 站点策略（对齐 SO 3.1.0 so-zeek local.zeek 加载清单）

@load misc/loaded-scripts
@load misc/capture-loss
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
@load protocols/dns/detect-external-names
@load protocols/ftp/detect
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/conn/vlan-logging
@load protocols/ssl/known-certs
@load protocols/ssl/validate-certs
@load protocols/ssl/log-hostcerts-only
@load protocols/ssh/geo-data
@load protocols/ssh/detect-bruteforcing
@load protocols/ssh/interesting-hostnames
@load protocols/http/detect-sql-injection
@load frameworks/files/hash-all-files
@load frameworks/files/detect-MHR
@load policy/frameworks/notice/extend-email/hostnames
@load policy/frameworks/notice/community-id
@load policy/protocols/conn/community-id-logging
@load ja3
@load ja4
@load hassh
@load intel
@load cve-2020-0601
@load securityonion/bpfconf
@load securityonion/file-extraction
@load securityonion/community-id-extended
@load oui-logging
@load icsnpp-modbus
@load icsnpp-dnp3
@load icsnpp-bacnet
@load icsnpp-ethercat
@load icsnpp-enip
@load icsnpp-opcua-binary
@load icsnpp-bsap
@load icsnpp-s7comm
@load zeek-plugin-tds
@load zeek-plugin-profinet
@load zeek-spicy-wireguard
@load zeek-spicy-stun
@load http2
@load zeek-spicy-ipsec
@load zeek-spicy-openvpn
@load-sigs frameworks/signatures/detect-windows-shells

# NSS-NDR 自研策略（SO 基础上：JSON 输出 + 探针标识）
@load securityonion/json-logs
@load securityonion/conn-add-sensorname

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef CaptureLoss::watch_interval = 5 mins;
