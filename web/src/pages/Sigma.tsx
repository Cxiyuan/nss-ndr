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
  created_at?: string;
  updated_at?: string;
}

export default function Sigma() {
  const [rules, setRules] = useState<SigmaRule[]>([]);
  const [editing, setEditing] = useState<SigmaRule | null>(null);
  const [preview, setPreview] = useState<any>(null);
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
    setPreview(null);
    try {
      setPreview(await api.previewSigma(r.id!));
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

  return (
    <div>
      <div className="row">
        <h2 style={{ margin: 0 }}>Sigma 规则</h2>
        <button className="btn primary" onClick={() => setEditing({ title: "", content: "" })}>
          新建规则
        </button>
      </div>
      <p className="hint">
        Sigma 规则由检测调度器按 schedule 定时在 ES 上执行，命中写入 <code>logs-detections.alerts-so</code>。
        字段按网络类数据源（zeek / suricata）映射。
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
            schedule（如 5m / 1h）
            <input
              value={editing.schedule || "5m"}
              onChange={(e) => setEditing({ ...editing, schedule: e.target.value })}
            />
          </label>
          <label>
            Sigma YAML
            <textarea
              rows={14}
              className="yaml-editor"
              value={editing.content}
              onChange={(e) => setEditing({ ...editing, content: e.target.value })}
              placeholder="title: ...&#10;logsource: ...&#10;detection: ..."
            />
          </label>
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
            <th>级别</th>
            <th>数据源</th>
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
              <td>{r.title}</td>
              <td>{r.level}</td>
              <td className="mono">
                {r.category}/{r.product}
              </td>
              <td>{r.schedule}</td>
              <td>{r.last_run_at || "-"}</td>
              <td>
                <button className="link" onClick={() => setEditing(r)}>
                  编辑
                </button>
                <button className="link" onClick={() => previewRule(r)}>
                  预览查询
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
          <pre className="mono" style={{ whiteSpace: "pre-wrap", fontSize: 12 }}>
            {JSON.stringify(preview, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
