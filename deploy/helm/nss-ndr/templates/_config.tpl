{{/* NSS-NDR 配置渲染 helper */}}

{{- define "nss.zeeknets" -}}
{{- $p := .Values.probeConfig -}}
{{- $nets := list -}}
{{- range $p.probe.home_net -}}
{{-   $nets = append $nets (printf "%s Private_IP_Space" .) -}}
{{- end -}}
{{- join "\n" $nets -}}
{{- end -}}

{{- define "nss.maxfiles" -}}
{{- $s := .Values.probeConfig.suricata -}}
{{- $threads := default 4 $s.af_packet_threads | int -}}
{{- $fs := default 1000 $s.pcap.file_size_mb | int -}}
{{- $gb := default 500 $s.pcap.storage_limit_gb | int -}}
{{- max 1 (ceil (divf (mul $gb 1000.0) (mul $fs $threads))) -}}
{{- end -}}

{{- define "nss.render" -}}
{{- $p := .ctx.Values.probeConfig -}}
{{- $s := $p.suricata -}}
{{- $z := $p.zeek -}}
{{- $probe := $p.probe -}}
{{- $threads := default 4 $s.af_packet_threads | int -}}
{{- $fs := default 1000 $s.pcap.file_size_mb | int -}}
{{- $content := .ctx.Files.Get .file -}}
{{- $content = replace "${INTERFACE}" $probe.interface $content -}}
{{- $content = replace "${THREADS}" (toString $threads) $content -}}
{{- $content = replace "${HOME_NET}" (printf "[%s]" (join "," $probe.home_net)) $content -}}
{{- $content = replace "${EXTERNAL_NET}" (default "any" $probe.external_net) $content -}}
{{- $content = replace "${PCAP_ENABLED}" (ternary "yes" "no" (default true $s.pcap.enabled)) $content -}}
{{- $content = replace "${PCAP_FILE_SIZE_MB}" (toString $fs) $content -}}
{{- $content = replace "${PCAP_COMPRESSION}" (default "none" $s.pcap.compression) $content -}}
{{- $content = replace "${PCAP_MAX_FILES}" (toString (include "nss.maxfiles" .ctx)) $content -}}
{{- $content = replace "${WORKERS}" (toString (default 4 $z.workers)) $content -}}
{{- $content = replace "${BUFFER_SIZE}" (default "128*1024*1024" $z.buffer_size) $content -}}
{{- $content = replace "${LOG_ROTATION_INTERVAL}" (toString (default 3600 $z.log_rotation_interval_s)) $content -}}
{{- $content = replace "${ZEEK_NETWORKS}" (include "nss.zeeknets" .ctx) $content -}}
{{- $content -}}
{{- end -}}
