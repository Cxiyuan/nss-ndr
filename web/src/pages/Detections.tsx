import { useCallback, useEffect, useMemo, useState } from "react";
import { ChevronRight, Save, RefreshCw, Search } from "lucide-react";

import { api, type ETOpenGroup, type Rule } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";

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
    let total = 0, enabled = 0;
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
    [],
  );

  const toggleGroup = (key: string) => {
    setCollapsedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  const toggleCat = (cat: string) => {
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
      <div key={c.key} className="space-y-2">
        <div className="flex items-center gap-2 rounded-md border bg-card px-3 py-2 hover:bg-accent/40">
          <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => toggleCat(c.key)}>
            <ChevronRight className={"h-4 w-4 transition-transform " + (expanded ? "rotate-90" : "")} />
          </Button>
          <label
            className="inline-flex items-center"
            onClick={(e) => {
              e.stopPropagation();
              toggleCategoryEnabled(c.key, !c.enabled);
            }}
          >
            <Checkbox checked={c.enabled} disabled={busy} />
          </label>
          <span className="font-medium">{c.name_cn}</span>
          <Badge variant="outline" className="ml-auto">
            {c.enabled_count}/{c.total}
          </Badge>
        </div>
        <p className="ml-10 text-xs text-muted-foreground">{c.desc_cn}</p>
        {expanded && (
          <div className="ml-10 space-y-2 border-l pl-4">
            <div className="flex items-center gap-2">
              <div className="relative flex-1 max-w-md">
                <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-8"
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
              </div>
              <Button variant="ghost" size="sm" onClick={() => loadCatRules(c.key, data?.q || "", 0)}>
                刷新
              </Button>
            </div>
            {(data?.rules || []).map((r) => (
              <div key={r.id} className="flex items-start gap-2 rounded-md border bg-background px-3 py-2">
                <label className="inline-flex items-center pt-0.5" onClick={(e) => { e.stopPropagation(); toggleRule(r, !r.enabled); }}>
                  <Checkbox checked={!!r.enabled} disabled={busy} />
                </label>
                <span className="text-sm" title={r.name}>{r.name_cn || r.name}</span>
              </div>
            ))}
            {data && data.total > (data.rules?.length || 0) && (
              <Button
                variant="link"
                size="sm"
                onClick={() => loadCatRules(c.key, data.q, (data.rules?.length || 0) + (data.offset || 0), true)}
                className="text-muted-foreground"
              >
                加载更多（{data.total - (data.rules?.length || 0)} 条）
              </Button>
            )}
            {data && data.total === 0 && <p className="text-xs text-muted-foreground">无匹配规则</p>}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-2xl font-semibold tracking-tight">事件检测</h2>
        <Button disabled={busy} onClick={apply}>
          <Save className="mr-2 h-4 w-4" />
          保存并应用
        </Button>
      </div>

      <p className="text-sm text-muted-foreground">
        内置检测规则库，已启用 {totals.enabled} / {totals.total} 条。规则按分类勾选加载，仅可启停，不可编辑。
      </p>

      {msg && <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{msg}</div>}
      {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      <div className="space-y-2">
        {groups.map((g) => {
          const collapsed = collapsedGroups.has(g.key);
          const gEnabled = g.categories.length > 0 && g.categories.every((c) => c.enabled);
          return (
            <Card key={g.key}>
              <CardHeader className="flex flex-row items-center gap-2 space-y-0 py-3">
                <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => toggleGroup(g.key)}>
                  <ChevronRight className={"h-4 w-4 transition-transform " + (!collapsed ? "rotate-90" : "")} />
                </Button>
                <label
                  className="inline-flex items-center"
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleGroupEnabled(g, !gEnabled);
                  }}
                >
                  <Checkbox checked={gEnabled} disabled={busy} />
                </label>
                <CardTitle className="text-base">{g.name}</CardTitle>
                <Badge variant="outline" className="ml-auto">
                  {g.categories.reduce((s, c) => s + c.enabled_count, 0)}/{g.categories.reduce((s, c) => s + c.total, 0)}
                </Badge>
              </CardHeader>
              {!collapsed && (
                <CardContent className="space-y-3 pt-0">
                  <p className="text-sm text-muted-foreground">{g.desc}</p>
                  <div className="space-y-2 pl-4">
                    {g.categories.map((c) => catNode(g, c))}
                  </div>
                </CardContent>
              )}
            </Card>
          );
        })}
      </div>
    </div>
  );
}