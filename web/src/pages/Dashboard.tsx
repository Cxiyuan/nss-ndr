import { useEffect, useMemo, useState } from "react";
import {
  api,
  type AlertBucket,
  type AlertsTodayStats,
  type HealthStats,
  type TrafficSample,
  type WorkloadStats,
} from "../api";

// 30s 刷新
const REFRESH_MS = 30_000;

function formatNumber(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(2) + " G";
  if (n >= 1e6) return (n / 1e6).toFixed(2) + " M";
  if (n >= 1e3) return (n / 1e3).toFixed(1) + " k";
  return String(n);
}

function formatRate(eps: number): string {
  return formatNumber(eps) + " /s";
}

function formatBps(bps: number): string {
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + " Gbps";
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kbps";
  return Math.round(bps) + " bps";
}

function formatPct(pct: number): string {
  return pct + "%";
}

function shortTs(iso: string): string {
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const h = String(d.getHours()).padStart(2, "0");
  const m = String(d.getMinutes()).padStart(2, "0");
  return `${h}:${m}`;
}

// ---- 折线图（纯 SVG）----
function TrafficChart({ samples }: { samples: TrafficSample[] }) {
  const W = 720;
  const H = 180;
  const padL = 48;
  const padR = 12;
  const padT = 12;
  const padB = 24;

  if (samples.length === 0) {
    return (
      <div className="chart-empty">
        近 60 分钟无 zeek.conn 数据（可能流量尚未产生或 ES 索引未建）
      </div>
    );
  }

  const maxEps = Math.max(1, ...samples.map((s) => s.eps));
  const maxBps = Math.max(1, ...samples.map((s) => s.bps));
  const n = samples.length;

  const x = (i: number) =>
    padL + (i / Math.max(1, n - 1)) * (W - padL - padR);
  const yEps = (v: number) =>
    padT + (1 - v / maxEps) * (H - padT - padB);
  const yBps = (v: number) =>
    padT + (1 - v / maxBps) * (H - padT - padB);

  const epsPath = samples
    .map((s, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${yEps(s.eps).toFixed(1)}`)
    .join(" ");
  const bpsPath = samples
    .map((s, i) => `${i === 0 ? "M" : "L"} ${x(i).toFixed(1)} ${yBps(s.bps).toFixed(1)}`)
    .join(" ");

  // Y 轴刻度（4 条网格线）
  const gridY = [0, 0.25, 0.5, 0.75, 1].map((r) => padT + r * (H - padT - padB));

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className="chart-svg"
      role="img"
      aria-label="流量速率时序图"
    >
      {/* 网格 */}
      {gridY.map((y, i) => (
        <line
          key={i}
          x1={padL}
          y1={y}
          x2={W - padR}
          y2={y}
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={1}
        />
      ))}
      {/* EPS 线 */}
      <path d={epsPath} fill="none" stroke="#5fb3ff" strokeWidth={1.6} />
      {/* BPS 线 */}
      <path d={bpsPath} fill="none" stroke="#7fd07f" strokeWidth={1.6} strokeDasharray="4 3" />
      {/* X 轴时间标签（首末） */}
      <text x={padL} y={H - 6} fill="rgba(255,255,255,0.5)" fontSize={10}>
        {shortTs(samples[0].ts)}
      </text>
      <text x={W - padR} y={H - 6} fill="rgba(255,255,255,0.5)" fontSize={10} textAnchor="end">
        {shortTs(samples[samples.length - 1].ts)}
      </text>
      {/* Y 轴左标签（eps） */}
      <text x={4} y={padT + 6} fill="#5fb3ff" fontSize={10}>
        {formatRate(maxEps)}
      </text>
      <text x={4} y={H - padB} fill="#5fb3ff" fontSize={10}>
        0
      </text>
      {/* Y 轴右标签（bps） */}
      <text x={W - padR + 2} y={padT + 6} fill="#7fd07f" fontSize={10} textAnchor="start">
        {formatBps(maxBps)}
      </text>
    </svg>
  );
}

// ---- 柱状图（纯 SVG，按小时）----
function AlertsHistogram({ buckets }: { buckets: AlertBucket[] }) {
  const W = 720;
  const H = 160;
  const padL = 36;
  const padR = 12;
  const padT = 12;
  const padB = 28;

  if (buckets.length === 0) {
    return <div className="chart-empty">今日暂无 Suricata 告警线索</div>;
  }

  const max = Math.max(1, ...buckets.map((b) => b.count));
  const n = buckets.length;
  const barW = Math.max(2, (W - padL - padR) / n - 2);

  const yVal = (v: number) => padT + (1 - v / max) * (H - padT - padB);

  // Y 轴刻度（max 4 等分）
  const gridY = [0, 0.25, 0.5, 0.75, 1].map(
    (r) => padT + r * (H - padT - padB)
  );

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      preserveAspectRatio="none"
      className="chart-svg"
      role="img"
      aria-label="今日告警线索分时柱状图"
    >
      {gridY.map((y, i) => (
        <line
          key={i}
          x1={padL}
          y1={y}
          x2={W - padR}
          y2={y}
          stroke="rgba(255,255,255,0.08)"
          strokeWidth={1}
        />
      ))}
      {buckets.map((b, i) => {
        const x = padL + i * ((W - padL - padR) / n);
        const h = (H - padT - padB) * (b.count / max);
        const y = padT + (H - padT - padB) - h;
        return (
          <g key={i}>
            <rect
              x={x}
              y={y}
              width={barW}
              height={h}
              fill="#ffb14a"
              opacity={0.85}
            >
              <title>
                {shortTs(b.hour)} — {b.count} 条线索
              </title>
            </rect>
          </g>
        );
      })}
      <text x={4} y={padT + 6} fill="rgba(255,255,255,0.7)" fontSize={10}>
        {max}
      </text>
      <text x={4} y={H - padB} fill="rgba(255,255,255,0.5)" fontSize={10}>
        0
      </text>
      {/* X 轴首末时间 */}
      <text x={padL} y={H - 8} fill="rgba(255,255,255,0.5)" fontSize={10}>
        {shortTs(buckets[0].hour)}
      </text>
      <text
        x={W - padR}
        y={H - 8}
        fill="rgba(255,255,255,0.5)"
        fontSize={10}
        textAnchor="end"
      >
        {shortTs(buckets[buckets.length - 1].hour)}
      </text>
      <text
        x={(padL + W - padR) / 2}
        y={H - 2}
        fill="rgba(255,255,255,0.4)"
        fontSize={10}
        textAnchor="middle"
      >
        今日 24 小时
      </text>
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
      const firstErr = [t, w, h, a, s].find((r) => r.status === "rejected") as
        | PromiseRejectedResult
        | undefined;
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

  const currentEps = useMemo(() => {
    if (!traffic?.samples?.length) return 0;
    return traffic.samples[traffic.samples.length - 1].eps;
  }, [traffic]);

  const currentBps = useMemo(() => {
    if (!traffic?.samples?.length) return 0;
    return traffic.samples[traffic.samples.length - 1].bps;
  }, [traffic]);

  const xdrSuccessRate = useMemo(() => {
    if (!workload) return null;
    const { success, failed } = workload.xdr_push;
    const total = success + failed;
    if (total === 0) return null;
    return (success / total) * 100;
  }, [workload]);

  return (
    <div className="dashboard">
      <div className="row between">
        <h2 style={{ margin: 0 }}>运维监控</h2>
        <div className="row" style={{ alignItems: "center", gap: 12 }}>
          {lastRefresh && (
            <span className="hint" style={{ margin: 0 }}>
              上次刷新 {lastRefresh.toLocaleTimeString()}（每 30s 自动）
            </span>
          )}
          <button className="btn" onClick={load}>
            手动刷新
          </button>
        </div>
      </div>

      {err && <div className="alert error">{err}</div>}
      {workload?.es_error && (
        <div className="alert error">ES 部分查询失败：{workload.es_error}</div>
      )}

      {/* 顶部 4 张数字卡 */}
      <div className="cards cards-4">
        <div className="card">
          <div className="card-label">今日事件总量</div>
          <div className="card-value">
            {workload ? formatNumber(workload.total_events_today) : "—"}
          </div>
          <div className="card-sub">
            {workload && workload.events_by_dataset.length > 0
              ? `Top：${workload.events_by_dataset[0].dataset}`
              : "—"}
          </div>
        </div>
        <div className="card">
          <div className="card-label">今日告警线索量</div>
          <div className="card-value">
            {workload ? formatNumber(workload.alerts_today) : "—"}
          </div>
          <div className="card-sub">
            {alertsToday
              ? `Suricata 日累计，详见分时图`
              : "Suricata 命中线索"}
          </div>
        </div>
        <div className="card">
          <div className="card-label">XDR 推送成功率</div>
          <div className="card-value">
            {xdrSuccessRate === null ? "—" : formatPct(Math.round(xdrSuccessRate))}
          </div>
          <div className="card-sub">
            {workload
              ? `成功 ${formatNumber(workload.xdr_push.success)} / 失败 ${formatNumber(
                  workload.xdr_push.failed
                )} / DLQ ${workload.xdr_push.dlq}`
              : "Webhook 累计"}
          </div>
        </div>
        <div className="card">
          <div className="card-label">当前流量速率</div>
          <div className="card-value">
            {traffic ? formatRate(currentEps) : "—"}
          </div>
          <div className="card-sub">
            {traffic ? formatBps(currentBps) : "最近 60 分钟峰值见左图"}
          </div>
        </div>
      </div>

      {/* 流量波形图 */}
      <div className="panel">
        <div className="panel-title">
          流量处理波形图（最近 60 分钟）
          <span className="legend">
            <span className="legend-item">
              <span className="legend-swatch" style={{ background: "#5fb3ff" }} />
              连接事件速率（eps）
            </span>
            <span className="legend-item">
              <span className="legend-swatch" style={{ background: "#7fd07f", opacity: 0.7 }} />
              字节速率（bps）
            </span>
          </span>
        </div>
        <TrafficChart samples={traffic?.samples ?? []} />
      </div>

      {/* 告警线索分时柱状图 */}
      <div className="panel">
        <div className="panel-title">
          今日告警线索分时柱状图
          <span className="legend">
            <span className="legend-item">共 {alertsToday?.total ?? 0} 条线索</span>
          </span>
        </div>
        <AlertsHistogram buckets={alertsToday?.buckets ?? []} />
      </div>

      {/* 系统健康 + 磁盘 + cleaner */}
      <div className="grid-2col">
        <div className="panel">
          <div className="panel-title">组件健康</div>
          {health?.components?.length ? (
            <table className="mini-table">
              <thead>
                <tr>
                  <th>组件</th>
                  <th>状态</th>
                </tr>
              </thead>
              <tbody>
                {health.components.map((c) => (
                  <tr key={c.name}>
                    <td className="mono">{c.name}</td>
                    <td>
                      <span
                        className={
                          "badge " +
                          (c.state === "running"
                            ? "ok"
                            : c.state === "exited"
                            ? "warn"
                            : "err")
                        }
                      >
                        {c.state}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="hint">未检测到 nss-* 容器或 docker 不可用</div>
          )}
          <div className="hint" style={{ marginTop: 8 }}>
            ES 集群：
            <span
              className={
                "badge " +
                (health?.es?.status === "green"
                  ? "ok"
                  : health?.es?.status === "yellow"
                  ? "warn"
                  : "err")
              }
            >
              {health?.es?.status ?? "unknown"}
            </span>
            {health?.es?.nodes != null && `（${health.es.nodes} 节点）`}
            {health?.es?.error && (
              <span style={{ color: "#ff6b6b" }}> — {health.es.error}</span>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-title">磁盘与 Cleaner</div>
          {health?.disk?.length ? (
            health.disk.map((d) => (
              <div key={d.mount} className="disk-row">
                <div className="disk-label">
                  <span className="mono">{d.mount}</span>
                  <span>
                    {formatPct(d.usage_pct)} 已用 · {d.free_gb.toFixed(1)} GB 可用
                  </span>
                </div>
                <div className="bar-track">
                  <div
                    className={
                      "bar-fill " +
                      (d.usage_pct >= 90
                        ? "danger"
                        : d.usage_pct >= 75
                        ? "warn"
                        : "ok")
                    }
                    style={{ width: Math.min(100, d.usage_pct) + "%" }}
                  />
                </div>
              </div>
            ))
          ) : (
            <div className="hint">未挂载 /nsm 或 /opt/ndr</div>
          )}

          <div className="cleaner-block">
            <div className="panel-sub-title">Cleaner 最近一次</div>
            {health?.cleaner?.error ? (
              <div className="hint">{health.cleaner.error}</div>
            ) : (
              <>
                <div className="hint">
                  {health?.cleaner?.last_run
                    ? `运行于 ${new Date(health.cleaner.last_run).toLocaleString()}`
                    : "尚未运行"}
                  {health?.cleaner?.pressure_triggered && (
                    <span className="badge warn" style={{ marginLeft: 8 }}>
                      触发压力清理
                    </span>
                  )}
                </div>
                <div className="hint">
                  删除 {health?.cleaner?.removed_files ?? 0} 个文件 ·{" "}
                  {((health?.cleaner?.removed_bytes ?? 0) / 1e9).toFixed(2)} GB 释放 ·{" "}
                  /nsm 用量 {formatPct(health?.cleaner?.fs_usage_pct ?? 0)}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 按 dataset 分布 + 探针基础 */}
      <div className="grid-2col">
        <div className="panel">
          <div className="panel-title">当日事件按 dataset 分布（Top 10）</div>
          {workload?.events_by_dataset?.length ? (
            <table className="mini-table">
              <thead>
                <tr>
                  <th>dataset</th>
                  <th style={{ textAlign: "right" }}>事件数</th>
                </tr>
              </thead>
              <tbody>
                {workload.events_by_dataset.slice(0, 10).map((d) => (
                  <tr key={d.dataset}>
                    <td className="mono">{d.dataset}</td>
                    <td style={{ textAlign: "right" }}>{formatNumber(d.count)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="hint">今日暂无事件</div>
          )}
        </div>
        <div className="panel">
          <div className="panel-title">探针基础</div>
          <div className="hint">
            探针 ID：<span className="mono">{status?.probe_id ?? "—"}</span>
            <br />
            镜像口：<span className="mono">{status?.interface || "未配置"}</span>
            <br />
            最近配置下发：<span className="mono">{status?.applied_hash ?? "—"}</span>
            <br />
            Strelka 今日处理：{" "}
            {workload ? formatNumber(workload.strelka_files_today) : "—"} 个文件
          </div>
        </div>
      </div>

      <p className="hint">
        本页面只展示本探针自身的运维监控指标（流量波形 / 当日工作量 / 组件健康 / 配置审计）。
        具体告警事件内容、跨会话关联、SOC 视图等安全数据分析可视化由 XDR 平台承担。
      </p>
    </div>
  );
}