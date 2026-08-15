import { useEffect, useMemo, useState } from "react";
import { api, ConfigField, ConfigGroup } from "../api";

const sections = [
  { key: "probe", title: "探针基础" },
  { key: "suricata", title: "检测引擎" },
  { key: "zeek", title: "网络元数据" },
  { key: "elasticsearch", title: "数据存储" },
  { key: "xdr", title: "告警推送" },
  { key: "strelka", title: "文件分析" },
  { key: "detections", title: "检测" },
  { key: "resources", title: "资源限制" },
];

export default function ConfigPage() {
  const [groups, setGroups] = useState<ConfigGroup[]>([]);
  const [fields, setFields] = useState<ConfigField[]>([]);
  const [values, setValues] = useState<Record<string, any>>({});
  const [activeGroup, setActiveGroup] = useState("");
  const [advanced, setAdvanced] = useState(false);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  // 高级 YAML 模式状态
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
    [fields, activeGroup]
  );

  const setField = (key: string, val: any) =>
    setValues((v) => ({ ...v, [key]: val }));

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
        setMsg("已保存（未下发），点击“保存并下发”生效");
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

  if (advanced) {
    return (
      <div>
        <div className="row between">
          <h2>高级配置（YAML）</h2>
          <div className="row">
            <button className="btn" onClick={() => setAdvanced(false)}>
              返回参数表单
            </button>
          </div>
        </div>
        <p className="hint">
          高级模式直接编辑配置节 YAML，适用于熟悉配置结构的运维；参数化配置项请尽量使用表单。
        </p>
        <select
          value={advSection}
          onChange={(e) => {
            setAdvSection(e.target.value);
            loadSection(e.target.value);
          }}
        >
          {sections.map((s) => (
            <option key={s.key} value={s.key}>
              {s.title}
            </option>
          ))}
        </select>
        <textarea
          className="yaml-editor"
          value={advValue}
          onChange={(e) => setAdvValue(e.target.value)}
          spellCheck={false}
          placeholder="YAML 配置…"
        />
        <div className="row">
          <input
            className="comment"
            placeholder="变更说明（写入审计日志）"
            value={advComment}
            onChange={(e) => setAdvComment(e.target.value)}
          />
          <button className="btn" disabled={busy} onClick={() => saveAdvanced(false)}>
            保存
          </button>
          <button className="btn primary" disabled={busy} onClick={() => saveAdvanced(true)}>
            保存并下发
          </button>
        </div>
        {msg && <div className="alert ok">{msg}</div>}
        {err && <div className="alert error">{err}</div>}
      </div>
    );
  }

  return (
    <div>
      <div className="row between">
        <h2>参数配置</h2>
        <div className="row">
          <button className="btn" onClick={() => setAdvanced(true)}>
            高级 YAML 模式
          </button>
        </div>
      </div>
      <div className="tabs">
        {groups.map((g) => (
          <button
            key={g.key}
            className={"tab" + (activeGroup === g.key ? " active" : "")}
            onClick={() => setActiveGroup(g.key)}
          >
            {g.label}
          </button>
        ))}
      </div>
      <div className="form-grid">
        {groupFields.map((f) => (
          <FieldEditor key={f.key} field={f} value={values[f.key]} onChange={(v) => setField(f.key, v)} />
        ))}
      </div>
      {groupFields.length === 0 && <p className="hint">该分组暂无配置项</p>}
      <div className="row" style={{ marginTop: 16 }}>
        <button className="btn" disabled={busy} onClick={() => saveGroup(false)}>
          保存
        </button>
        <button className="btn primary" disabled={busy} onClick={() => saveGroup(true)}>
          保存并下发
        </button>
      </div>
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}
      <p className="hint">
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
    <label className="field-label">
      {field.label}
      {field.unit && <span className="unit">{field.unit}</span>}
    </label>
  );
  let control: JSX.Element;
  switch (field.type) {
    case "number":
      control = (
        <input
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
        <input type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
      );
      break;
    case "select":
      control = (
        <select value={value ?? ""} onChange={(e) => onChange(e.target.value)}>
          {field.options?.map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      );
      break;
    case "list":
      control = (
        <textarea
          rows={4}
          value={Array.isArray(value) ? value.join("\n") : value ?? ""}
          onChange={(e) =>
            onChange(
              e.target.value
                .split("\n")
                .map((s) => s.trim())
                .filter(Boolean)
            )
          }
        />
      );
      break;
    case "secret":
      control = (
        <input
          type="password"
          value={value ?? ""}
          onChange={(e) => onChange(e.target.value)}
        />
      );
      break;
    default:
      control = (
        <input value={value ?? ""} onChange={(e) => onChange(e.target.value)} />
      );
  }
  return (
    <div className="field">
      {label}
      {control}
      {field.help && <p className="hint">{field.help}</p>}
    </div>
  );
}
