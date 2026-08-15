import { useCallback, useEffect, useMemo, useState } from "react";
import { api, type ETOpenGroup, type Rule } from "../api";

const PAGE_SIZE = 50;

export default function Detections() {
  const [groups, setGroups] = useState<ETOpenGroup[]>([]);
  const [collapsedGroups, setCollapsedGroups] = useState<Set<string>>(new Set());
  const [expandedCats, setExpandedCats] = useState<Set<string>>(new Set());
  const [catRules, setCatRules] = useState<Record<string, { total: number; rules: Rule[]; offset: number; q: string }>>({});
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const loadTree = useCallback(() => api.etopenTree().then(setGroups).catch((e) => setErr(e.message)), []);

  useEffect(() => {
    loadTree();
  }, [loadTree]);

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

  const loadCatRules = useCallback(
    async (cat: string, q: string, offset: number, append = false) => {
      try {
        const page = await api.etopenRules(cat, q, offset, PAGE_SIZE);
        setCatRules((prev) => {
          const cur = prev[cat] || { total: 0, rules: [], offset: 0, q: "" };
          return {
            ...prev,
            [cat]: {
              total: page.total,
              rules: append ? [...cur.rules, ...page.rules] : page.rules,
              offset: append ? offset : offset,
              q,
            },
          };
        });
      } catch (e: any) {
        setErr(e.message);
      }
    },
    []
  );

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleCat = (cat: string, total: number) => {
    setExpandedCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) {
        next.delete(cat);
      } else {
        next.add(cat);
        if (!catRules[cat]) loadCatRules(cat, "", 0);
      }
      return next;
    });
  };

  const toggleCategoryEnabled = async (cat: string, enabled: boolean) => {
    setBusy(true);
    setErr("");
    try {
      await api.etopenCategory(cat, enabled);
      await loadTree();
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const toggleGroupEnabled = async (g: ETOpenGroup, enabled: boolean) => {
    setBusy(true);
    setErr("");
    try {
      for (const c of g.categories) {
        if (c.enabled !== enabled) await api.etopenCategory(c.key, enabled);
      }
      await loadTree();
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
      await loadTree();
      const cur = catRules[r.category!];
      if (cur) await loadCatRules(r.category!, cur.q, cur.offset);
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

  const catNode = (g: ETOpenGroup, c: any) => {
    const expanded = expandedCats.has(c.key);
    const data = catRules[c.key];
    return (
      <div key={c.key} className="tree-node">
        <div className="tree-row tree-row-cat" onClick={() => toggleCat(c.key, c.total)}>
          <span className={"tree-arrow" + (expanded ? " open" : "")}>▸</span>
          <label
            className="tree-check"
            onClick={(e) => {
              e.stopPropagation();
              toggleCategoryEnabled(c.key, !c.enabled);
            }}
          >
            <input type="checkbox" checked={c.enabled} disabled={busy} onChange={() => {}} />
          </label>
          <span className="tree-name">{c.name_cn}</span>
          <span className="tree-count">
            {c.enabled_count}/{c.total}
          </span>
        </div>
        <div className="tree-desc">{c.desc_cn}</div>
        {expanded && (
          <div className="tree-children">
            <div className="tree-search-row" onClick={(e) => e.stopPropagation()}>
              <input
                className="comment"
                placeholder="搜索规则描述（回车）"
                defaultValue={data?.q || ""}
                onKeyDown={(e: any) => {
                  if (e.key === "Enter") {
                    const q = e.target.value;
                    setCatRules((prev) => ({ ...prev, [c.key]: { total: 0, rules: [], offset: 0, q } }));
                    loadCatRules(c.key, q, 0);
                  }
                }}
              />
              <button className="link" onClick={() => loadCatRules(c.key, data?.q || "", 0)}>
                刷新
              </button>
            </div>
            {(data?.rules || []).map((r) => (
              <div key={r.id} className="tree-row tree-row-rule">
                <label
                  className="tree-check"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleRule(r, !r.enabled);
                  }}
                >
                  <input type="checkbox" checked={!!r.enabled} disabled={busy} onChange={() => {}} />
                </label>
                <span className="tree-name tree-name-rule">{r.name_cn || r.name}</span>
              </div>
            ))}
            {data && data.total > (data.rules?.length || 0) && (
              <button
                className="link tree-more"
                onClick={() => loadCatRules(c.key, data.q, (data.rules?.length || 0) + (data.offset || 0), true)}
              >
                加载更多（{data.total - (data.rules?.length || 0)} 条）
              </button>
            )}
            {data && data.total === 0 && <div className="hint tree-empty">无匹配规则</div>}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="detect-page">
      <div className="row between" style={{ marginTop: 0 }}>
        <h2 style={{ margin: 0 }}>事件检测</h2>
        <button className="btn primary" disabled={busy} onClick={apply}>
          保存并应用
        </button>
      </div>
      <p className="hint">
        内置检测规则库，已启用 {totals.enabled} / {totals.total} 条。规则按分类勾选加载，仅可启停，不可编辑。
      </p>
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}
      <div className="detect-tree-full">
        {groups.map((g) => {
          const collapsed = collapsedGroups.has(g.key);
          const gEnabled = g.categories.length > 0 && g.categories.every((c) => c.enabled);
          return (
            <div key={g.key} className="tree-node">
              <div className="tree-row tree-row-group" onClick={() => toggleGroup(g.key)}>
                <span className={"tree-arrow" + (!collapsed ? " open" : "")}>▸</span>
                <label
                  className="tree-check"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleGroupEnabled(g, !gEnabled);
                  }}
                >
                  <input type="checkbox" checked={gEnabled} disabled={busy} onChange={() => {}} />
                </label>
                <span className="tree-name tree-group-name">{g.name}</span>
                <span className="tree-count">
                  {g.categories.reduce((s, c) => s + c.enabled_count, 0)}/{g.categories.reduce((s, c) => s + c.total, 0)}
                </span>
              </div>
              {!collapsed && (
                <div className="tree-children">
                  <div className="tree-desc">{g.desc}</div>
                  {g.categories.map((c) => catNode(g, c))}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
