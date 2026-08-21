import { useEffect, useMemo, useState } from "react";
import { RefreshCw, AlertCircle } from "lucide-react";

import {
  api,
  type AlertBucket,
  type AlertsTodayStats,
  type HealthStats,
  type TrafficSample,
  type WorkloadStats,
} from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { formatBps, formatNumber, formatPct, formatRate, shortTs } from "@/lib/utils";

const REFRESH_MS = 30_000;

function TrafficChart({ samples }: { samples: TrafficSample[] }) {
  const W = 720, H = 180, padL = 48, padR = 12, padT = 12, padB = 24;
  if (samples.length === 0) {
    return <div className="chart-empty">近 60 分钟无 zeek.conn 数据（可能流量尚未产生或 ES 索引未建）</div>;
  }
  const maxEps = Math.max(1, ...samples.map((s) => s.eps));
  const maxBps = Math.max(1, ...samples.map((s) => s.bps));
  const n = samples.length;
  const x = (i: number) => padL + (i / Math.max(1, n - 1)) * (W - padL - padR);
  const yEps = (v: number) => padT + (1 - v / maxEps) * (H - padT - padB);
  const yBps = (v: number) => padT + (1 - v / maxBps) * (H - padT - padB);
  const epsPath = samples.map((s, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${yEps(s.eps).toFixed(1)}`).join(" ");
  const bpsPath = samples.map((s, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${yBps(s.bps).toFixed(1)}`).join(" ");
  const gridY = [0, 0.25, 0.5, 0.75, 1].map((r) => padT + r * (H - padT - padB));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="chart-svg">
      {gridY.map((y, i) => (
        <line key={i} x1={padL} y1={y} x2={W - padR} y2={y} stroke="rgba(255,255,255,0.08)" strokeWidth={1} />
      ))}
      <path d={epsPath} fill="none" stroke="#5fb3ff" strokeWidth={1.6} />
      <path d={bpsPath} fill="none" stroke="#7fd07f" strokeWidth={1.6} strokeDasharray="4 3" />
      <text x={padL} y={H - 6} fill="rgba(255,255,255,0.5)" fontSize={10}>{shortTs(samples[0].ts)}</text>
      <text x={W - padR} y={H - 6} fill="rgba(255,255,255,0.5)" fontSize={10} textAnchor="end">{shortTs(samples[samples.length - 1].ts)}</text>
      <text x={4} y={padT + 6} fill="#5fb3ff" fontSize={10}>{formatRate(maxEps)}</text>
      <text x={4} y={H - padB} fill="#5fb3ff" fontSize={10}>0</text>
      <text x={W - padR + 2} y={padT + 6} fill="#7fd07f" fontSize={10} textAnchor="start">{formatBps(maxBps)}</text>
    </svg>
  );
}

function AlertsHistogram({ buckets }: { buckets: AlertBucket[] }) {
  const W = 720, H = 160, padL = 36, padR = 12, padT = 12, padB = 28;
  if (buckets.length === 0) {
    return <div className="chart-empty">今日暂无 Suricata 告警线索</div>;
  }
  const max = Math.max(1, ...buckets.map((b) => b.count));
  const n = buckets.length;
  const barW = Math.max(2, (W - padL - padR) / n - 2);
  const yVal = (v: number) => padT + (1 - v / max) * (H - padT - padB);
  const gridY = [0, 0.25, 0.5, 0.75, 1].map((r) => padT + r * (H - padT - padB));
  return (
    <svg viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" className="chart-svg">
      {gridY.map((y, i) => (
        <line key={i} x1={padL} y1={y} x2={W - padR} y2={y} stroke="rgba(255,255,255,0.08)" strokeWidth={1} />
      ))}
      {buckets.map((b, i) => {
        const x = padL + i * ((W - padL - padR) / n);
        const h = (H - padT - padB) * (b.count / max);
        const y = padT + (H - padT - padB) - h;
        return (
          <g key={i}>
            <rect x={x} y={y} width={barW} height={h} fill="#ffb14a" opacity={0.85}>
              <title>{shortTs(b.hour)} — {b.count} 条线索</title>
            </rect>
          </g>
        );
      })}
      <text x={4} y={padT + 6} fill="rgba(255,255,255,0.7)" fontSize={10}>{max}</text>
      <text x={4} y={H - padB} fill="rgba(255,255,255,0.5)" fontSize={10}>0</text>
      <text x={padL} y={H - 8} fill="rgba(255,255,255,0.5)" fontSize={10}>{shortTs(buckets[0].hour)}</text>
      <text x={W - padR} y={H - 8} fill="rgba(255,255,255,0.5)" fontSize={10} textAnchor="end">{shortTs(buckets[buckets.length - 1].hour)}</text>
      <text x={(padL + W - padR) / 2} y={H - 2} fill="rgba(255,255,255,0.4)" fontSize={10} textAnchor="middle">今日 24 小时</text>
    </svg>
  );
}

export default function Dashboard() {
  const [traffic, setTraffic] = useState<{ samples: TrafficSample[] } | null>(null);
  const [workload, setWorkload] = useState<WorkloadStats | null>(null);
  const [health, setHealth] = useState<HealthStats | null>(null);
  const [alertsToday, setAlertsToday] = useState<AlertsTodayStats | null>(null);
  const [status, setStatus] = useState<any>(null);
  const [err, setErr] = useState("");
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);

  const load = async () => {
    setErr("");
    try {
      const [t, w, h, a, s] = await Promise.allSettled([
        api.monitoringTraffic(),
        api.monitoringWorkload(),
        api.monitoringHealth(),
        api.monitoringAlertsToday(),
        api.status(),
      ]);
      if (t.status === "fulfilled") setTraffic(t.value);
      if (w.status === "fulfilled") setWorkload(w.value);
      if (h.status === "fulfilled") setHealth(h.value);
      if (a.status === "fulfilled") setAlertsToday(a.value);
      if (s.status === "fulfilled") setStatus(s.value);
      const firstErr = [t, w, h, a, s].find((r) => r.status === "rejected") as PromiseRejectedResult | undefined;
      if (firstErr) setErr(String(firstErr.reason?.message ?? firstErr.reason));
      setLastRefresh(new Date());
    } catch (e: any) {
      setErr(e.message ?? String(e));
    }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, []);

  const currentEps = useMemo(() => traffic?.samples?.length ? traffic.samples[traffic.samples.length - 1].eps : 0, [traffic]);
  const currentBps = useMemo(() => traffic?.samples?.length ? traffic.samples[traffic.samples.length - 1].bps : 0, [traffic]);
  const xdrSuccessRate = useMemo(() => {
    if (!workload) return null;
    const { success, failed } = workload.xdr_push;
    const total = success + failed;
    if (total === 0) return null;
    return (success / total) * 100;
  }, [workload]);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold tracking-tight">运维监控</h2>
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          {lastRefresh && <span>上次刷新 {lastRefresh.toLocaleTimeString()}（每 30s 自动）</span>}
          <Button variant="outline" size="sm" onClick={load}>
            <RefreshCw className="mr-2 h-4 w-4" />
            手动刷新
          </Button>
        </div>
      </div>

      {err && (
        <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>{err}</span>
        </div>
      )}
      {workload?.es_error && (
        <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <span>ES 部分查询失败：{workload.es_error}</span>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">今日事件总量</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">{workload ? formatNumber(workload.total_events_today) : "—"}</div>
            <p className="mt-1 text-xs text-muted-foreground">
              {workload?.events_by_dataset.length ? `Top: ${workload.events_by_dataset[0].dataset}` : "—"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">今日告警线索量</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">{workload ? formatNumber(workload.alerts_today) : "—"}</div>
            <p className="mt-1 text-xs text-muted-foreground">Suricata 命中线索</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">XDR 推送成功率</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">
              {xdrSuccessRate === null ? "—" : formatPct(Math.round(xdrSuccessRate))}
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              {workload
                ? `成功 ${formatNumber(workload.xdr_push.success)} / 失败 ${formatNumber(workload.xdr_push.failed)} / DLQ ${workload.xdr_push.dlq}`
                : "Webhook 累计"}
            </p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">当前流量速率</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-semibold">{traffic ? formatRate(currentEps) : "—"}</div>
            <p className="mt-1 text-xs text-muted-foreground">{traffic ? formatBps(currentBps) : "最近 60 分钟峰值见左图"}</p>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">流量处理波形图（最近 60 分钟）</CardTitle>
          <div className="legend">
            <span className="legend-item">
              <span className="legend-swatch" style={{ background: "#5fb3ff" }} />
              连接事件速率（eps）
            </span>
            <span className="legend-item">
              <span className="legend-swatch" style={{ background: "#7fd07f", opacity: 0.7 }} />
              字节速率（bps）
            </span>
          </div>
        </CardHeader>
        <CardContent>
          <TrafficChart samples={traffic?.samples ?? []} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
          <CardTitle className="text-sm font-medium">今日告警线索分时柱状图</CardTitle>
          <div className="legend">
            <span className="legend-item">共 {alertsToday?.total ?? 0} 条线索</span>
          </div>
        </CardHeader>
        <CardContent>
          <AlertsHistogram buckets={alertsToday?.buckets ?? []} />
        </CardContent>
      </Card>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">组件健康</CardTitle></CardHeader>
          <CardContent>
            {health?.components?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>组件</TableHead>
                    <TableHead>状态</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {health.components.map((c) => (
                    <TableRow key={c.name}>
                      <TableCell className="font-mono text-xs">{c.name}</TableCell>
                      <TableCell>
                        <Badge variant={c.state === "running" ? "success" : c.state === "exited" ? "warning" : "destructive"}>
                          {c.state}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">未检测到 nss-* 容器或 docker 不可用</p>
            )}
            <p className="mt-3 text-sm text-muted-foreground">
              ES 集群：
              <Badge
                variant={
                  health?.es?.status === "green" ? "success" : health?.es?.status === "yellow" ? "warning" : "destructive"
                }
                className="ml-2"
              >
                {health?.es?.status ?? "unknown"}
              </Badge>
              {health?.es?.nodes != null && `（${health.es.nodes} 节点）`}
              {health?.es?.error && <span className="ml-2 text-destructive">— {health.es.error}</span>}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">磁盘与 Cleaner</CardTitle></CardHeader>
          <CardContent className="space-y-4">
            {health?.disk?.length ? (
              health.disk.map((d) => {
                const cls = d.usage_pct >= 90 ? "bg-red-500" : d.usage_pct >= 75 ? "bg-amber-500" : "bg-emerald-500";
                return (
                  <div key={d.mount}>
                    <div className="mb-1 flex justify-between text-sm">
                      <span className="font-mono">{d.mount}</span>
                      <span className="text-muted-foreground">
                        {formatPct(d.usage_pct)} 已用 · {d.free_gb.toFixed(1)} GB 可用
                      </span>
                    </div>
                    <Progress value={d.usage_pct} indicatorClassName={cls} />
                  </div>
                );
              })
            ) : (
              <p className="text-sm text-muted-foreground">未挂载 /nsm 或 /opt/ndr</p>
            )}

            <div className="border-t pt-3">
              <div className="mb-1 text-xs font-medium text-muted-foreground">Cleaner 最近一次</div>
              {health?.cleaner?.error ? (
                <p className="text-sm text-muted-foreground">{health.cleaner.error}</p>
              ) : (
                <>
                  <div className="text-sm text-muted-foreground">
                    {health?.cleaner?.last_run ? `运行于 ${new Date(health.cleaner.last_run).toLocaleString()}` : "尚未运行"}
                    {health?.cleaner?.pressure_triggered && (
                      <Badge variant="warning" className="ml-2">触发压力清理</Badge>
                    )}
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    删除 {health?.cleaner?.removed_files ?? 0} 个文件 ·{" "}
                    {((health?.cleaner?.removed_bytes ?? 0) / 1e9).toFixed(2)} GB 释放 ·{" "}
                    /nsm 用量 {formatPct(health?.cleaner?.fs_usage_pct ?? 0)}
                  </div>
                </>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">当日事件按 dataset 分布（Top 10）</CardTitle></CardHeader>
          <CardContent>
            {workload?.events_by_dataset?.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>dataset</TableHead>
                    <TableHead className="text-right">事件数</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {workload.events_by_dataset.slice(0, 10).map((d) => (
                    <TableRow key={d.dataset}>
                      <TableCell className="font-mono text-xs">{d.dataset}</TableCell>
                      <TableCell className="text-right">{formatNumber(d.count)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">今日暂无事件</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2"><CardTitle className="text-sm font-medium">探针基础</CardTitle></CardHeader>
          <CardContent>
            <dl className="space-y-1 text-sm">
              <div className="flex justify-between">
                <dt className="text-muted-foreground">探针 ID</dt>
                <dd className="font-mono">{status?.probe_id ?? "—"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">镜像口</dt>
                <dd className="font-mono">{status?.interface || "未配置"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">最近配置下发</dt>
                <dd className="font-mono">{status?.applied_hash ?? "—"}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-muted-foreground">Strelka 今日处理</dt>
                <dd className="font-mono">{workload ? formatNumber(workload.strelka_files_today) : "—"} 个文件</dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </div>

      <p className="text-xs text-muted-foreground">
        本页面只展示本探针自身的运维监控指标（流量波形 / 当日工作量 / 组件健康 / 配置审计）。
        具体告警事件内容、跨会话关联、SOC 视图等安全数据分析可视化由 XDR 平台承担。
      </p>
    </div>
  );
}