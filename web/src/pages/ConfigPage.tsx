import { useEffect, useMemo, useState } from "react";
import { Save, ArrowDownToLine } from "lucide-react";

import { api, type ConfigField, type ConfigGroup } from "@/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";

type Mode = "form" | "yaml";

const sections = [
  { key: "probe", title: "探针基础" },
  { key: "suricata", title: "检测引擎" },
  { key: "zeek", title: "网络元数据" },
  { key: "elasticsearch", title: "数据存储" },
  { key: "xdr", title: "告警推送" },
  { key: "strelka", title: "文件分析" },
  { key: "detections", title: "检测" },
  { key: "resources", title: "资源限制" },
] as const;

export default function ConfigPage() {
  const [groups, setGroups] = useState<ConfigGroup[]>([]);
  const [fields, setFields] = useState<ConfigField[]>([]);
  const [values, setValues] = useState<Record<string, any>>({});
  const [activeGroup, setActiveGroup] = useState("");
  const [mode, setMode] = useState<Mode>("form");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  // YAML 模式
  const [advSection, setAdvSection] = useState("probe");
  const [advValue, setAdvValue] = useState("");
  const [advComment, setAdvComment] = useState("");

  const loadSchema = async () => {
    try {
      const s = await api.configSchema();
      setGroups(s.groups);
      setFields(s.fields);
      setActiveGroup((g) => g || s.groups[0]?.key || "");
      const v: Record<string, any> = {};
      s.fields.forEach((f) => {
        v[f.key] = f.value !== undefined ? f.value : f.default;
      });
      setValues(v);
    } catch (e: any) {
      setErr(e.message);
    }
  };

  useEffect(() => {
    loadSchema();
  }, []);

  const groupFields = useMemo(
    () => fields.filter((f) => f.group === activeGroup).sort((a, b) => a.order - b.order),
    [fields, activeGroup],
  );

  const setField = (key: string, val: any) => setValues((v) => ({ ...v, [key]: val }));

  const saveGroup = async (apply = false) => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      const patch: Record<string, any> = {};
      groupFields.forEach((f) => {
        patch[f.key] = values[f.key];
      });
      await api.saveFormConfig(patch, "表单保存: " + (groups.find((g) => g.key === activeGroup)?.label || activeGroup));
      if (apply) {
        await api.apply("表单配置下发");
        setMsg("已保存并下发，组件滚动重启中（约 1-2 分钟）");
      } else {
        setMsg("已保存（未下发），点击「保存并下发」生效");
      }
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const loadSection = async (key: string) => {
    try {
      const s = await api.getSection(key);
      setAdvValue(s.value);
    } catch (e: any) {
      setErr(e.message);
    }
  };

  const saveAdvanced = async (apply = false) => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await api.saveSection(advSection, advValue, advComment || "高级模式保存");
      if (apply) {
        await api.apply(advComment || "高级模式下发");
        setMsg("已保存并下发，组件滚动重启中（约 1-2 分钟）");
      } else {
        setMsg("已保存（未下发）");
      }
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (mode === "yaml") {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h2 className="text-2xl font-semibold tracking-tight">高级配置（YAML）</h2>
          <Button variant="outline" size="sm" onClick={() => setMode("form")}>
            返回参数表单
          </Button>
        </div>
        <p className="text-sm text-muted-foreground">
          高级模式直接编辑配置节 YAML，适用于熟悉配置结构的运维；参数化配置项请尽量使用表单。
        </p>
        <div className="space-y-3">
          <Label htmlFor="yaml-section">配置节</Label>
          <Select value={advSection} onValueChange={(v) => { setAdvSection(v); loadSection(v); }}>
            <SelectTrigger id="yaml-section" className="w-full md:w-64">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {sections.map((s) => (
                <SelectItem key={s.key} value={s.key}>
                  {s.title}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Textarea
            value={advValue}
            onChange={(e) => setAdvValue(e.target.value)}
            spellCheck={false}
            placeholder="YAML 配置…"
            className="font-mono min-h-[360px] text-xs"
          />
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="max-w-md"
              placeholder="变更说明（写入审计日志）"
              value={advComment}
              onChange={(e) => setAdvComment(e.target.value)}
            />
            <Button variant="outline" disabled={busy} onClick={() => saveAdvanced(false)}>
              <Save className="mr-2 h-4 w-4" />保存
            </Button>
            <Button disabled={busy} onClick={() => saveAdvanced(true)}>
              <ArrowDownToLine className="mr-2 h-4 w-4" />保存并下发
            </Button>
          </div>
        </div>
        {msg && <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{msg}</div>}
        {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-semibold tracking-tight">参数配置</h2>
        <Button variant="outline" size="sm" onClick={() => setMode("yaml")}>
          高级 YAML 模式
        </Button>
      </div>

      {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      <Tabs value={activeGroup} onValueChange={setActiveGroup}>
        <TabsList className="flex-wrap">
          {groups.map((g) => (
            <TabsTrigger key={g.key} value={g.key}>
              {g.label}
            </TabsTrigger>
          ))}
        </TabsList>
        {groups.map((g) => (
          <TabsContent key={g.key} value={g.key}>
            <Card>
              <CardHeader>
                <CardTitle>{g.label}</CardTitle>
                <CardDescription>编辑此分组的参数。点击「保存并下发」会同步到所有组件。</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {fields
                  .filter((f) => f.group === g.key)
                  .sort((a, b) => a.order - b.order)
                  .map((f) => (
                    <FieldEditor key={f.key} field={f} value={values[f.key]} onChange={(v) => setField(f.key, v)} />
                  ))}
                {fields.filter((f) => f.group === g.key).length === 0 && (
                  <p className="text-sm text-muted-foreground">该分组暂无配置项</p>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        ))}
      </Tabs>

      <Separator />

      <div className="flex items-center gap-2">
        <Button variant="outline" disabled={busy} onClick={() => saveGroup(false)}>
          <Save className="mr-2 h-4 w-4" />保存
        </Button>
        <Button disabled={busy} onClick={() => saveGroup(true)}>
          <ArrowDownToLine className="mr-2 h-4 w-4" />保存并下发
        </Button>
      </div>

      {msg && <div className="rounded-md bg-emerald-500/10 px-3 py-2 text-sm text-emerald-300">{msg}</div>}
      {err && <div className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">{err}</div>}

      <p className="text-xs text-muted-foreground">
        保存仅写入配置库；下发会更新 ConfigMap 并按需调整资源限制/ES 堆内存，滚动重启组件（约 1-2 分钟）。
      </p>
    </div>
  );
}

function FieldEditor({
  field,
  value,
  onChange,
}: {
  field: ConfigField;
  value: any;
  onChange: (v: any) => void;
}) {
  const label = (
    <Label className="text-sm font-medium">
      {field.label}
      {field.unit && <span className="ml-1 text-xs text-muted-foreground">{field.unit}</span>}
    </Label>
  );
  let control: JSX.Element;
  switch (field.type) {
    case "number":
      control = (
        <Input
          type="number"
          min={field.min}
          max={field.max}
          step={field.step || 1}
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))}
        />
      );
      break;
    case "bool":
      control = (
        <div className="flex items-center gap-2">
          <Switch checked={!!value} onCheckedChange={onChange} />
          <span className="text-sm text-muted-foreground">{value ? "已启用" : "已禁用"}</span>
        </div>
      );
      break;
    case "select":
      control = (
        <Select value={value ?? ""} onValueChange={onChange}>
          <SelectTrigger>
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {field.options?.map((o) => (
              <SelectItem key={o} value={o}>
                {o}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      );
      break;
    case "list":
      control = (
        <Textarea
          rows={4}
          value={Array.isArray(value) ? value.join("\n") : value ?? ""}
          onChange={(e) =>
            onChange(
              e.target.value
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean),
            )
          }
        />
      );
      break;
    case "secret":
      control = (
        <Input
          type="password"
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value)}
          autoComplete="new-password"
        />
      );
      break;
    default:
      control = <Input value={value ?? ""} onChange={(e) => onChange(e.target.value)} />;
  }
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        {label}
        {field.type === "secret" && (
          <Badge variant="outline" className="text-xs">
            secret
          </Badge>
        )}
      </div>
      {control}
      {field.help && <p className="text-xs text-muted-foreground">{field.help}</p>}
    </div>
  );
}