import { useEffect, useState } from "react";
import { api, type Rule } from "../api";

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [editing, setEditing] = useState<Rule | null>(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const load = () => api.listRules().then(setRules).catch((e) => setErr(e.message));

  useEffect(() => {
    load();
  }, []);

  const toggle = async (r: Rule) => {
    await api.setRuleEnabled(r.id!, !r.enabled);
    load();
  };

  const remove = async (r: Rule) => {
    if (!confirm(`删除规则「${r.name}」？`)) return;
    await api.deleteRule(r.id!);
    load();
  };

  const apply = async () => {
    setErr("");
    setMsg("");
    try {
      const res = await api.applyRules();
      setMsg(res.message);
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
        await api.updateRule(editing.id, editing);
      } else {
        await api.createRule(editing);
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
        <h2 style={{ margin: 0 }}>规则管理</h2>
        <button className="btn primary" onClick={() => setEditing({ name: "", rule: "", threshold: "" })}>
          新建规则
        </button>
        <button className="btn" onClick={apply}>
          渲染并热加载
        </button>
      </div>
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}

      {editing && (
        <div className="panel">
          <h3>{editing.id ? "编辑规则" : "新建规则"}</h3>
          <label>
            名称
            <input value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} />
          </label>
          <label>
            Suricata 规则
            <textarea
              rows={4}
              value={editing.rule}
              onChange={(e) => setEditing({ ...editing, rule: e.target.value })}
              placeholder='alert tcp any any -> any any (msg:"test"; sid:1000001; rev:1;)'
            />
          </label>
          <label>
            threshold（可选）
            <textarea
              rows={2}
              value={editing.threshold || ""}
              onChange={(e) => setEditing({ ...editing, threshold: e.target.value })}
              placeholder='threshold gen_id 1, sig_id 1000001, type limit, track by_src, count 1, seconds 60'
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
            <th>名称</th>
            <th>类型</th>
            <th>规则</th>
            <th>更新时间</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>
          {rules.map((r) => (
            <tr key={r.id}>
              <td>
                <input type="checkbox" checked={!!r.enabled} onChange={() => toggle(r)} />
              </td>
              <td>{r.name}</td>
              <td>{r.type}</td>
              <td className="mono">{r.rule.slice(0, 80)}</td>
              <td>{r.updated_at}</td>
              <td>
                <button className="link" onClick={() => setEditing(r)}>
                  编辑
                </button>
                <button className="link danger" onClick={() => remove(r)}>
                  删除
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
