##! NSS-NDR：Zeek 输出 JSON 格式日志（整条管道的根基）

@load tuning/json-logs

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
