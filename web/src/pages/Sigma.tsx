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
  builtin?: boolean;
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

// 数据源展示名中文化（产品 UI 不暴露引擎技术名词）
function productLabel(product?: string, category?: string) {
  if (product === "suricata") return "检测线索";
  if (product === "zeek") return "网络元数据";
  return [category, product].filter(Boolean).join("/") || "-";
}

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
        <h2 style={{ margin: 0 }}>事件告警</h2>
        <button className="btn primary" onClick={() => setEditing({ title: "", content: "" })}>
          新建规则
        </button>
      </div>
      <p className="hint">
        事件告警规则由检测调度器按调度周期定时执行，命中后写入告警库。
        普通规则直接查询；<b>关联规则</b>先匹配检测线索，再按关联键（默认会话标识）联动网络元数据确认，
        最终输出告警，降低误报。
        <b>内置规则</b>（产品规则库维护）仅可启停，不可编辑/删除；新建规则为用户自定义规则。
      </p>
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}

      {editing && (
        <div className="panel">
          <h3>{editing.id ? "编辑规则" : "新建规则"}</h3>
          <label>
            标题
            <input value={editing.title} onChange={(e) => setEditing({ ...editing, title: e.target.value })} />
          </label>
          <label>
            调度周期（如 5m / 1h）
            <input
              value={editing.schedule || "5m"}
              onChange={(e) => setEditing({ ...editing, schedule: e.target.value })}
            />
          </label>
          <label>
            规则内容
            <textarea
              rows={16}
              className="yaml-editor"
              value={editing.content}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              placeholder={"规则标题、检测条件等（自定义内容由管理员维护）"}
            />
          </label>
          <p className="hint">
            关联规则字段：线索（clue）、确认（confirm）、关联键（group_by，默认会话标识）、时间窗（timespan）、
            关联要求（both|clue|confirm）、回退策略（none|clue_only|confirm_only）、置信度（low|medium|high）。
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
            <th>调度周期</th>
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
                {r.builtin && <span className="badge">内置</span>} {r.title}
                {r.correlation && (
                  <div className="hint mono">
                    线索:{productLabel(r.correlation.clue_product)} → 确认:{productLabel(r.correlation.confirm_product)} ·{" "}
                    {r.correlation.group_by} · {r.correlation.timespan || "跟随调度"}
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
              <td>{productLabel(r.product, r.category)}</td>
              <td className="hint">{policyText(r)}</td>
              <td>{r.schedule}</td>
              <td>{r.last_run_at || "-"}</td>
              <td>
                {!r.builtin && (
                  <button className="link" onClick={() => setEditing(r)}>
                    编辑
                  </button>
                )}
                <button className="link" onClick={() => previewRule(r)}>
                  预览查询
                </button>
                <button className="link" onClick={() => evidenceRule(r)}>
                  证据预览
                </button>
                <button className="link" onClick={() => run(r)}>
                  立即执行
                </button>
                {!r.builtin && (
                  <button className="link danger" onClick={() => remove(r)}>
                    删除
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {preview && (
        <div className="panel">
          <h3>查询预览</h3>
          {preview.type === "correlation" ? (
            <>
              <p className="hint">
                关联规则：{requiredLabel[preview.required] || preview.required} / {fallbackLabel[preview.fallback] || preview.fallback} /{" "}
                置信度 {preview.confidence} / 关联键 {preview.group_by}
              </p>
              <p className="hint">线索阶段与确认阶段查询已就绪，可按关联键在时间窗内联动确认。</p>
            </>
          ) : (
            <p className="hint">查询已就绪，按调度周期在告警库中检索匹配事件。</p>
          )}
        </div>
      )}

      {evidence && (
        <div className="panel">
          <h3>证据预览（仅检查，不产生告警）· 窗口 {evidence.window}</h3>
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
          <button className="btn" onClick={() => setEvidence(null)}>
            关闭
          </button>
        </div>
      )}
    </div>
  );
}
