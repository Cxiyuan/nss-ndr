import { useEffect, useState } from "react";
import { api } from "../api";

interface Props {
  section: string;
  title: string;
}

export default function ConfigPage({ section, title }: Props) {
  const [value, setValue] = useState("");
  const [comment, setComment] = useState("");
  const [describe, setDescribe] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api
      .getSection(section)
      .then((s) => {
        setValue(s.value);
        setDescribe(s.describe || "");
      })
      .catch((e) => setErr(e.message));
  }, [section]);

  const save = async () => {
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      await api.saveSection(section, value, comment);
      setMsg("配置已保存（未下发）");
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
      await api.apply(`应用配置变更：${title}`);
      setMsg("已下发：ConfigMap 更新并滚动重启组件");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h2>{title}</h2>
      {describe && <p className="hint">{describe}</p>}
      {msg && <div className="alert ok">{msg}</div>}
      {err && <div className="alert error">{err}</div>}
      <textarea
        className="yaml-editor"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        spellCheck={false}
        placeholder="YAML 配置…"
      />
      <div className="row">
        <input
          className="comment"
          placeholder="变更说明（写入审计日志）"
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
        <button className="btn" disabled={busy} onClick={save}>
          保存
        </button>
        <button className="btn primary" disabled={busy} onClick={apply}>
          保存并应用下发
        </button>
      </div>
      <p className="hint">
        保存仅写入配置库；应用下发会渲染生成 ConfigMap 并滚动重启 suricata / zeek / filebeat 等组件（约 1-2 分钟）。
      </p>
    </div>
  );
}
