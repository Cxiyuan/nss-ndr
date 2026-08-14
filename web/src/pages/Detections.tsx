import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type ETOpenGroup, type Rule } from "../api";

const PAGE_SIZE = 50;

export default function Detections() {
  const [groups, setGroups] = useState<ETOpenGroup[]>([]);
  const [selCat, setSelCat] = useState<string>("");
  const [rulesPage, setRulesPage] = useState<{ total: number; rules: Rule[] } | null>(null);
  const [q, setQ] = useState("");
  const [offset, setOffset] = useState(0);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const loadTree = useCallback(() => api.etopenTree().then(setGroups).catch((e) => setErr(e.message)), []);

  const loadRules = useCallback(
    async (cat: string, query: string, off: number) => {
      setErr("");
      try {
        const page = await api.etopenRules(cat, query, off, PAGE_SIZE);
        setRulesPage(page);
      } catch (e: any) {
        setErr(e.message);
      }
    },
    []
  );

  useEffect(() => {
    loadTree();
  }, [loadTree]);

  // 树加载完成后默认选中第一个分类
  useEffect(() => {
    if (groups.length === 0) return;
    const first = groups[0]?.categories?.[0]?.key;
    if (first) {
      setSelCat((cur) => (cur ? cur : first));
      if (!selCat) loadRules(first, "", 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groups]);

  useEffect(() => {
    if (selCat) loadRules(selCat, q, offset);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selCat, offset]);

  const totals = useMemo(() => {
    let total = 0;
    let enabled = 0;
    for (const g of groups)
      for (const c of g.categories) {
        total += c.total;
        enabled += c.enabled_count;
      }
    return { total, enabled };
  }, [groups]);

  const selMeta = useMemo(() => {
    for (const g of groups)
      for (const c of g.categories) if (c.key === selCat) return c;
    return null;
  }, [groups, selCat]);

  const selectCat = (key: string) => {
    setSelCat(key);
    setOffset(0);
    setQ("");
  };

  const toggleCategory = async (cat: string, enabled: boolean) => {
    setBusy(true);
    setErr("");
    try {
      await api.etopenCategory(cat, enabled);
      await loadTree();
      if (selCat === cat) await loadRules(cat, q, 0);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleGroup = async (g: ETOpenGroup, enabled: boolean) => {
    setBusy(true);
    setErr("");
    try {
      for (const c of g.categories) {
        if (c.enabled !== enabled) await api.etopenCategory(c.key, enabled);
      }
      await loadTree();
      if (selCat) await loadRules(selCat, q, 0);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleRule = async (r: Rule, enabled: boolean) => {
    setBusy(true);
    setErr("");
    try {
      await api.etopenRule(r.id!, enabled);
      await loadRules(selCat, q, offset);
      await loadTree();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      const res = await api.applyRules();
      setMsg(res.message);
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const search = () => {
    setOffset(0);
    if (selCat) loadRules(selCat, q, 0);
  };

  const groupTotal = (g: ETOpenGroup) => g.categories.reduce((s, c) => s + c.total, 0);

  return (
    <div className="detect-layout">
      <div className="detect-tree">
        <div className="row between" style={{ marginTop: 0 }}>
          <h2 style={{ margin: 0 }}>事件检测</h2>
        </div>
        <p className="hint">
          ET Open 内置规则集（来源：rules.emergingthreats.net），已启用 {totals.enabled} / {totals.total} 条。
          勾选分类加载为 Suricata 检测线索，配合 Zeek 上下文与 Sigma 事件告警确认。
        </p>
        {groups.map((g) => (
          <div className="tree-group" key={g.key}>
            <div className="tree-group-head">
              <span className="tree-group-name">{g.name}</span>
              <span className="tree-group-count">{groupTotal(g)} 条</span>
              <button className="link" disabled={busy} onClick={() => toggleGroup(g, true)}>
                启用全部
              </button>
              <button className="link danger" disabled={busy} onClick={() => toggleGroup(g, false)}>
                停用全部
              </button>
            </div>
            <p className="hint">{g.desc}</p>
            <div className="tree-cats">
              {g.categories.map((c) => (
                <div
                  key={c.key}
                  className={"tree-cat" + (selCat === c.key ? " selected" : "")}
                  onClick={() => selectCat(c.key)}
                >
                  <label onClick={(e) => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={c.enabled}
                      disabled={busy}
                      onChange={(e) => toggleCategory(c.key, e.target.checked)}
                    />
                    <span className="tree-cat-name">{c.name_cn}</span>
                    <span className="tree-cat-count">
                      {c.enabled_count}/{c.total}
                    </span>
                  </label>
                  <div className="hint">{c.desc_cn}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      <div className="detect-rules">
        <div className="row between">
          <h2 style={{ margin: 0 }}>
            {selMeta?.name_cn || "规则明细"}
            {selMeta && (
              <span className="hint">
                {" "}
                （{selMeta.file} · 共 {rulesPage?.total ?? selMeta.total} 条）
              </span>
            )}
          </h2>
          <button className="btn primary" disabled={busy} onClick={apply}>
            渲染并热加载
          </button>
        </div>
        {msg && <div className="alert ok">{msg}</div>}
        {err && <div className="alert error">{err}</div>}
        <div className="row">
          <input
            className="comment"
            placeholder="搜索规则内容 / msg（回车搜索）"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && search()}
          />
          <button className="btn" onClick={search}>
            搜索
          </button>
        </div>
        <table>
          <thead>
            <tr>
              <th style={{ width: 40 }}>启用</th>
              <th style={{ width: "38%" }}>规则描述</th>
              <th>规则内容</th>
            </tr>
          </thead>
          <tbody>
            {(rulesPage?.rules || []).map((r) => (
              <tr key={r.id}>
                <td>
                  <input
                    type="checkbox"
                    checked={!!r.enabled}
                    disabled={busy}
                    onChange={(e) => toggleRule(r, e.target.checked)}
                  />
                </td>
                <td>{r.name}</td>
                <td className="mono" title={r.rule} style={{ wordBreak: "break-all" }}>
                  {r.rule.length > 120 ? r.rule.slice(0, 120) + "…" : r.rule}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="row between">
          <span className="hint">
            第 {rulesPage && rulesPage.total > 0 ? offset + 1 : 0} -{" "}
            {rulesPage ? Math.min(offset + PAGE_SIZE, rulesPage.total) : 0} / {rulesPage?.total ?? 0} 条
          </span>
          <div className="row">
            <button className="btn" disabled={offset <= 0 || busy} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
              上一页
            </button>
            <button
              className="btn"
              disabled={!rulesPage || offset + PAGE_SIZE >= rulesPage.total || busy}
              onClick={() => setOffset(offset + PAGE_SIZE)}
            >
              下一页
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
