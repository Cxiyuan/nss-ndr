import { useEffect, useState } from "react";
import { api } from "../api";

export default function History() {
  const [versions, setVersions] = useState<any[]>([]);
  const [audits, setAudits] = useState<any[]>([]);

  useEffect(() => {
    api.history().then(setVersions).catch(() => {});
    api.audit().then(setAudits).catch(() => {});
  }, []);

  return (
    <div>
      <h2>配置历史</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>分组</th>
            <th>动作</th>
            <th>说明</th>
            <th>时间(UTC)</th>
          </tr>
        </thead>
        <tbody>
          {versions.map((v) => (
            <tr key={v.id}>
              <td>{v.id}</td>
              <td>{v.key}</td>
              <td>{v.action}</td>
              <td>{v.comment}</td>
              <td>{v.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <h2>审计日志</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>动作</th>
            <th>目标</th>
            <th>详情</th>
            <th>时间(UTC)</th>
          </tr>
        </thead>
        <tbody>
          {audits.map((a) => (
            <tr key={a.id}>
              <td>{a.id}</td>
              <td>{a.action}</td>
              <td>{a.target}</td>
              <td>{a.detail}</td>
              <td>{a.created_at}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
