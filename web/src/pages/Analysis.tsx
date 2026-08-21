import { useEffect, useState } from "react";
import { Activity, Bot, ChevronRight, Zap, ShieldAlert, ShieldCheck, Eye, Clock } from "lucide-react";

import { api, type AnalysisListItem, type AnalysisState } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

const VERDICT_VARIANT: Record<string, "success" | "warning" | "destructive" | "secondary"> = {
  real_threat: "destructive",
  suspicious: "warning",
  noise: "success",
  insufficient_evidence: "secondary",
};

const VERDICT_LABEL: Record<string, string> = {
  real_threat: "真实威胁",
  suspicious: "可疑",
  noise: "噪声",
  insufficient_evidence: "证据不足",
};

const STAGE_LABEL: Record<string, string> = {
  pre_aggregate: "预聚合",
  heuristic: "启发式",
  llm: "LLM 推理",
  escalated: "升级 XDR",
  finalized: "已完成",
  pipeline_failed: "失败",
};

export default function Analysis() {
  const [list, setList] = useState<AnalysisListItem[]>([]);
  const [selected, setSelected] = useState<AnalysisState | null>(null);
  const [err, setErr] = useState("");

  const load = () => {
    api.listAnalysis(100).then(setList).catch((e) => setErr(e.message));
  };

  useEffect(() => {
    load();
  }, []);

  const open = (taskId: string) => {
    api.getAnalysisState(taskId).then(setSelected).catch((e) => setErr(e.message));
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-semibold tracking-tight">分析任务状态</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            M14: LangGraph 4 步流水线（pre_aggregate → heuristic → llm → reconcile）+ 跨任务信誉缓存
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={load}>
          刷新
        </Button>
      </div>

      {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      {selected && (
        <Card className="border-primary/30">
          <CardHeader className="flex flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle className="text-base" title={selected.task_id}>
                推理路径：{selected.task_id}
              </CardTitle>
              <p className="mt-1 text-xs text-muted-foreground">
                {selected.instruction} · {selected.elapsed_ms}ms · {selected.llm_used ? "LLM" : "启发式"}
                {selected.escalated && " · 升级 XDR"}
              </p>
            </div>
            <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>
              关闭
            </Button>
          </CardHeader>
          <CardContent className="space-y-3">
            <StepRow icon={<Activity className="h-4 w-4" />} label="query_pcap / get_indicators / ..." stage="pre_aggregate" data={selected.metrics} />
            <StepRow icon={<Zap className="h-4 w-4" />} label="启发式" stage="heuristic" data={selected.heuristic_verdict} />
            <StepRow icon={<Bot className="h-4 w-4" />} label="LLM 推理" stage="llm" data={selected.llm_verdict} />
            <StepRow icon={<Zap className="h-4 w-4" />} label="XDR 升级" stage="escalate" data={selected.xdr_verdict} />
            <FinalStepRow data={selected.final_verdict} />
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle>任务列表（最近 100 条）</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Task ID</TableHead>
                <TableHead className="w-32">Instruction</TableHead>
                <TableHead className="w-32">Stage</TableHead>
                <TableHead className="w-32">Verdict</TableHead>
                <TableHead className="w-20">Conf</TableHead>
                <TableHead className="w-20">LLM</TableHead>
                <TableHead className="w-20">XDR</TableHead>
                <TableHead className="w-20">耗时</TableHead>
                <TableHead className="w-40">Updated</TableHead>
                <TableHead className="w-16"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((item) => (
                <TableRow key={item.task_id}>
                  <TableCell className="font-mono text-xs" title={item.task_id}>
                    {item.task_id.slice(0, 16)}…
                  </TableCell>
                  <TableCell>{item.instruction}</TableCell>
                  <TableCell>
                    <Badge variant="outline">{STAGE_LABEL[item.stage] || item.stage}</Badge>
                  </TableCell>
                  <TableCell>
                    {item.verdict ? (
                      <Badge variant={VERDICT_VARIANT[item.verdict] || "secondary"}>
                        {VERDICT_LABEL[item.verdict] || item.verdict}
                      </Badge>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {item.confidence ? (item.confidence * 100).toFixed(0) + "%" : "—"}
                  </TableCell>
                  <TableCell>{item.llm_used ? "✓" : "—"}</TableCell>
                  <TableCell>{item.escalated ? "✓" : "—"}</TableCell>
                  <TableCell className="text-xs">{item.elapsed_ms}ms</TableCell>
                  <TableCell className="text-xs text-muted-foreground">{item.updated_at?.slice(0, 19)}</TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => open(item.task_id)}>
                      <Eye className="h-3.5 w-3.5" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}

function StepRow({ icon, label, stage, data }: { icon: React.ReactNode; label: string; stage: string; data: any }) {
  const hasData = data && (typeof data !== "object" || Object.keys(data).length > 0);
  return (
    <div className="rounded-md border bg-card/50 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="rounded-md bg-muted p-1">{icon}</span>
        <span className="text-sm font-medium">{label}</span>
        <Badge variant="outline" className="text-xs">{stage}</Badge>
        {!hasData && <span className="text-xs text-muted-foreground">(skipped)</span>}
      </div>
      {hasData && (
        <pre className="overflow-x-auto rounded-md bg-muted/50 p-2 text-xs">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}

function FinalStepRow({ data }: { data: any }) {
  if (!data) return null;
  const verdict = data.verdict || "—";
  const variant = VERDICT_VARIANT[verdict] || "secondary";
  return (
    <div className="rounded-md border bg-card p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="rounded-md bg-primary/10 p-1 text-primary">
          <ShieldCheck className="h-4 w-4" />
        </span>
        <span className="text-sm font-medium">最终结论</span>
        <Badge variant={variant}>{VERDICT_LABEL[verdict] || verdict}</Badge>
        {data.confidence && (
          <span className="text-xs text-muted-foreground">
            confidence: {(data.confidence * 100).toFixed(0)}%
          </span>
        )}
      </div>
      {data.summary && (
        <p className="mb-2 text-sm text-foreground">{data.summary}</p>
      )}
      {data.key_indicators && data.key_indicators.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs text-muted-foreground">关键指标：</p>
          <ul className="space-y-1">
            {data.key_indicators.map((k: any, i: number) => (
              <li key={i} className="text-xs">
                <Badge variant="outline" className="mr-1">{k.type}</Badge>
                <span className="font-mono">{k.value}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}