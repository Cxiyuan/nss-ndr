import { useEffect, useState } from "react";
import { api } from "../api";

interface SigmaRule {
  id?: string;
  title: string;
  content: string;
  category?: string;
  product?: string;
  service?: string;
  level?: string;
  status?: string;
  schedule?: string;
  last_run_at?: string;
  type?: string;
  backend?: string;
  correlation?: {
    clue_product?: string;
    confirm_product?: string;
    group_by: string;
    timespan?: string;
    required: string;
    fallback: string;
    confidence: string;
  };
}

const CORR_TEMPLATE = `title: 关联规则示例：可疑 DNS + Suricata 线索
status: test
level: medium
backend: auto
# 主 logsource 仅作展示；执行以 correlation 内各阶段为准
logsource:
  product: zeek
  category: dns
correlation:
  clue:
    logsource:
      product: suricata
    detection:
      selection:
        rule.name|contains: "ET MALWARE"
      condition: selection
  confirm:
    logsource:
      product: zeek
      category: dns
    detection:
      selection:
        dns.question.name|endswith: ".xyz"
      condition: selection
  group_by: network.community_id
  timespan: 5m
  required: both
  fallback: none
  confidence: medium
`;

const requiredLabel: Record<string, string> = {
  both: "线索+确认",
  clue: "仅线索",
  confirm: "仅确认(Zeek-only)",
};
const fallbackLabel: Record<string, string> = {
  none: "未确认不出告警",
  clue_only: "线索未确认→降级告警",
  confirm_only: "确认无线索→降级告警",
};

export default function Sigma() {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [editing, setEditing] = useState<SigmaRule | null>(null);
  const [preview, setPreview] = useState<any>(null);
  const [evidence, setEvidence] = useState<any>(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = () => api.listSigma().then(setRules).catch((e) => setErr(e.message));

  useEffect(() => {
    load();
  }, []);

  const toggle = async (r: SigmaRule) => {
    await api.setSigmaStatus(r.id!, r.status === "enabled" ? "disabled" : "enabled");
    load();
  };

  const remove = async (r: SigmaRule) => {
    if (!confirm(`删除规则「${r.title}」？`)) return;
    await api.deleteSigma(r.id!);
    load();
  };

  const run = async (r: SigmaRule) => {
    setErr("");
    setMsg("");
    try {
      const res = await api.runSigma(r.id!);
      setMsg(res.message);
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const previewRule = async (r: SigmaRule) => {
    setErr("");
    setEvidence(null);
    setPreview(null);
    try {
      setPreview(await api.previewSigma(r.id!));
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const evidenceRule = async (r: SigmaRule) => {
    setErr("");
    setPreview(null);
    setEvidence(null);
    try {
      setEvidence(await api.evidenceSigma(r.id!));
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const saveEdit = async () => {
    if (!editing) return;
    setErr("");
    setMsg("");
    try {
      if (editing.id) {
        await api.updateSigma(editing.id, editing);
      } else {
        await api.createSigma(editing);
      }
      setEditing(null);
      load();
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const policyText = (r: SigmaRule) => {
    const c = r.correlation;
    if (!c) return "-";
    return `${requiredLabel[c.required] || c.required} / ${fallbackLabel[c.fallback] || c.fallback}`;
  };

  return (
    <div>
      <div className="row">
        <h2 style={{ margin: 0 }}>事件告警（Sigma 规则）</h2>
        <button className="btn primary" onClick={() => setEditing({ title: "", content: "" })}>
          新建规则
        </button>
      </div>
      <p className="hint">
        Sigma 规则由检测调度器按 schedule 定时在 ES 上执行，命中写入 <code>logs-detections.alerts-so</code>。
        普通规则直接查询；<b>关联规则</b>（correlation 段）先匹配 Suricata 线索，再按{" "}
        <code>group_by</code>（默认 community_id）联动 Zeek 元数据确认，最终输出告警，降低误报。
      </p>
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}

      {editing && (
        <div className="panel">
          <h3>{editing.id ? "编辑规则" : "新建规则"}</h3>
          <div className="row">
            <button
              className="btn"
              onClick={() =>
                setEditing({
                  ...editing,
                  content: editing.content ? editing.content + "\n" + CORR_TEMPLATE : CORR_TEMPLATE,
                })
              }
            >
              插入关联规则模板（Suricata线索 + Zeek确认）
            </button>
            {editing.content.includes("correlation:") && (
              <button
                className="btn"
                onClick={() =>
                  setEditing({
                    ...editing,
                    content: editing.content.replace(/correlation:/, "# 普通规则：删除 correlation 段即退化为单阶段查询\ncorrelation:"),
                  })
                }
              >
                查看普通规则写法
              </button>
            )}
          </div>
          <label>
            标题
            <input value={editing.title} onChange={(e) => setEditing({ ...editing, title: e.target.value })} />
          </label>
          <label>
            schedule（如 5m / 1h）
            <input
              value={editing.schedule || "5m"}
              onChange={(e) => setEditing({ ...editing, schedule: e.target.value })}
            />
          </label>
          <label>
            Sigma YAML
            <textarea
              rows={16}
              className="yaml-editor"
              value={editing.content}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              placeholder={"title: ...\nlogsource: ...\ndetection: ...\n# 关联规则可选 correlation 段"}
            />
          </label>
          <p className="hint">
            correlation 字段：clue（线索，默认 suricata）、confirm（确认，默认 zeek）、group_by（关联键）、
            timespan（时间窗）、required（both|clue|confirm）、fallback（none|clue_only|confirm_only）、confidence（low|medium|high）、
            backend（eql|esql|auto）。
          </p>
          <div className="row">
            <button className="btn primary" onClick={saveEdit}>
              保存
            </button>
            <button className="btn" onClick={() => setEditing(null)}>
              取消
            </button>
          </div>
        </div>
      )}

      <table>
        <thead>
          <tr>
            <th>启用</th>
            <th>标题</th>
            <th>类型</th>
            <th>级别/置信度</th>
            <th>数据源</th>
            <th>关联策略</th>
            <th>schedule</th>
            <th>最近执行</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>
                <input type="checkbox" checked={r.status === "enabled"} onChange={() => toggle(r)} />
              </td>
              <td>
                {r.title}
                {r.correlation && (
                  <div className="hint mono">
                    线索:{r.correlation.clue_product || "-"} → 确认:{r.correlation.confirm_product || "-"} ·{" "}
                    {r.correlation.group_by} · {r.correlation.timespan || "跟随schedule"}
                  </div>
                )}
              </td>
              <td>
                {r.type === "correlation" ? (
                  <span className="badge">关联</span>
                ) : (
                  <span className="badge plain">普通</span>
                )}
              </td>
              <td>
                {r.level}
                {r.correlation && <div className="hint">置信度:{r.correlation.confidence}</div>}
              </td>
              <td className="mono">
                {r.category}/{r.product}
              </td>
              <td className="hint">{policyText(r)}</td>
              <td>{r.schedule}</td>
              <td>{r.last_run_at || "-"}</td>
              <td>
                <button className="link" onClick={() => setEditing(r)}>
                  编辑
                </button>
                <button className="link" onClick={() => previewRule(r)}>
                  预览查询
                </button>
                <button className="link" onClick={() => evidenceRule(r)}>
                  证据预览
                </button>
                <button className="link" onClick={() => run(r)}>
                  立即执行
                </button>
                <button className="link danger" onClick={() => remove(r)}>
                  删除
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {preview && (
        <div className="panel">
          <h3>转换预览（ES 查询）</h3>
          {preview.type === "correlation" ? (
            <>
              <p className="hint">
                关联规则：{preview.required} / {preview.fallback} / {preview.confidence} / group_by={preview.group_by}
              </p>
              {preview.clue && (
                <>
                  <h4>线索（clue）EQL</h4>
                  <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                    {preview.clue.eql}
                  </pre>
                  {preview.clue.esql && (
                    <>
                      <h4>线索（clue）ES|QL</h4>
                      <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                        {preview.clue.esql}
                      </pre>
                    </>
                  )}
                </>
              )}
              {preview.confirm && (
                <>
                  <h4>确认（confirm）EQL</h4>
                  <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                    {preview.confirm.eql}
                  </pre>
                  {preview.confirm.esql && (
                    <>
                      <h4>确认（confirm）ES|QL</h4>
                      <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                        {preview.confirm.esql}
                      </pre>
                    </>
                  )}
                </>
              )}
            </>
          ) : (
            <>
              <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                {preview.eql}
              </pre>
              {preview.esql && (
                <>
                  <h4>ES|QL</h4>
                  <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
                    {preview.esql}
                  </pre>
                </>
              )}
            </>
          )}
        </div>
      )}

      {evidence && (
        <div className="panel">
          <h3>证据预览（dry-run，不写告警）· 窗口 {evidence.window}</h3>
          {evidence.count === 0 && <p className="hint">当前窗口无命中。</p>}
          {evidence.type === "correlation" && evidence.matches.length > 0 && (
            <table>
              <thead>
                <tr>
                  <th>关联键（group_by）</th>
                  <th>确认状态</th>
                  <th>线索命中数</th>
                  <th>确认命中数</th>
                </tr>
              </thead>
              <tbody>
                {evidence.matches.map((m: any, i: number) => (
                  <tr key={i}>
                    <td className="mono">{m.key || "(缺失)"}</td>
                    <td>{m.confirmed ? "已确认 ✅" : "未确认（回退）⚠️"}</td>
                    <td>{m.clue_hits?.length ?? 0}</td>
                    <td>{m.confirm_hits?.length ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {evidence.type === "simple" && evidence.count > 0 && (
            <p className="hint">命中 {evidence.count} 条（详见明细）</p>
          )}
          <details>
            <summary>查看证据明细</summary>
            <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
              {JSON.stringify(evidence, null, 2)}
            </pre>
          </details>
          <button className="btn" onClick={() => setEvidence(null)}>
            关闭
          </button>
        </div>
      )}
    </div>
  );
}
