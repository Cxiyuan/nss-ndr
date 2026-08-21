import { useEffect, useState } from "react";
import { Pencil, Trash2, Save, X, RefreshCw } from "lucide-react";

import { api, type Rule } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";

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
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-2xl font-semibold tracking-tight">自定义规则</h2>
        <div className="flex gap-2">
          <Button onClick={() => setEditing({ name: "", rule: "", threshold: "" })}>
            <Pencil className="mr-2 h-4 w-4" />
            新建规则
          </Button>
          <Button variant="outline" onClick={apply}>
            <RefreshCw className="mr-2 h-4 w-4" />
            渲染并热加载
          </Button>
        </div>
      </div>

      <p className="text-sm text-muted-foreground">
        自定义单条检测规则。内置检测规则库在「事件检测」中按分类勾选加载。
        <b>内置规则</b>（产品规则库维护）仅可启停，不可编辑/删除。
      </p>
      {msg && <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{msg}</div>}
      {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      {editing && (
        <Card>
          <CardHeader>
            <CardTitle>{editing.id ? "编辑规则" : "新建规则"}</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="rule-name">名称</Label>
              <Input
                id="rule-name"
                value={editing.name}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-content">检测规则内容</Label>
              <Textarea
                id="rule-content"
                rows={4}
                value={editing.rule}
                onChange={(e) => setEditing({ ...editing, rule: e.target.value })}
                placeholder="检测规则内容（由管理员维护）"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="rule-threshold">阈值（可选）</Label>
              <Textarea
                id="rule-threshold"
                rows={2}
                value={editing.threshold || ""}
                onChange={(e) => setEditing({ ...editing, threshold: e.target.value })}
                placeholder="阈值配置（可选）"
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={saveEdit}>
                <Save className="mr-2 h-4 w-4" />
                保存
              </Button>
              <Button variant="outline" onClick={() => setEditing(null)}>
                <X className="mr-2 h-4 w-4" />
                取消
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-16">启用</TableHead>
              <TableHead>名称</TableHead>
              <TableHead className="w-24">类型</TableHead>
              <TableHead>规则</TableHead>
              <TableHead className="w-40">更新时间</TableHead>
              <TableHead className="w-32">操作</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rules.map((r) => (
              <TableRow key={r.id}>
                <TableCell>
                  <input
                    type="checkbox"
                    className="h-4 w-4 rounded-sm"
                    checked={!!r.enabled}
                    onChange={() => toggle(r)}
                  />
                </TableCell>
                <TableCell>
                  {r.type === "builtin" && (
                    <Badge variant="outline" className="mr-2">
                      内置
                    </Badge>
                  )}
                  {r.name}
                </TableCell>
                <TableCell>{r.type === "builtin" ? "内置" : r.type}</TableCell>
                <TableCell className="max-w-md truncate font-mono text-xs" title={r.rule}>
                  {r.rule.slice(0, 80)}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{r.updated_at}</TableCell>
                <TableCell>
                  {r.type !== "builtin" && (
                    <div className="flex gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setEditing(r)}
                      >
                        <Pencil className="mr-1 h-3.5 w-3.5" />
                        编辑
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        className="text-destructive hover:text-destructive"
                        onClick={() => remove(r)}
                      >
                        <Trash2 className="mr-1 h-3.5 w-3.5" />
                        删除
                      </Button>
                    </div>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}