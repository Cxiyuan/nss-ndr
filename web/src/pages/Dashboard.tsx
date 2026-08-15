import { useEffect, useState } from "react";
import { api } from "../api";

export default function Dashboard() {
  const [status, setStatus] = useState<any>(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api
      .status()
      .then(setStatus)
      .catch((e) => setErr(e.message));
  }, []);

  return (
    <div>
      <h2>总览</h2>
      {err && <div className="alert error">{err}</div>}
      {status && (
        <div className="cards">
          <div className="card">
            <div className="card-label">探针 ID</div>
            <div className="card-value">{status.probe_id}</div>
          </div>
          <div className="card">
            <div className="card-label">镜像口</div>
            <div className="card-value">{status.interface || "未配置"}</div>
          </div>
          <div className="card">
            <div className="card-label">最近下发</div>
            <div className="card-value">{status.applied_hash}</div>
          </div>
        </div>
      )}
      <p className="hint">
        通过顶部菜单统一维护探针、检测引擎、网络元数据、存储、告警推送与规则集配置。
        修改配置后点击「保存」，再「应用下发」将更新 ConfigMap 并滚动重启组件。
      </p>
    </div>
  );
}
