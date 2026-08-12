import { useState } from "react";
import { api, setToken } from "../api";

export default function Login() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setMsg("");
    try {
      const r = await api.login(username, password);
      setToken(r.token);
      setMsg("登录成功，正在跳转…");
      window.location.assign("/");
    } catch (e: any) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>NSS-NDR 探针管理</h1>
        <p className="hint">请输入管理员账号登录</p>
        <label>
          账号
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label>
          密码
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
        </label>
        {err && <div className="alert error">{err}</div>}
        {msg && <div className="alert ok">{msg}</div>}
        <button className="btn primary" disabled={busy}>
          {busy ? "登录中…" : "登录"}
        </button>
        <p className="hint">初始账号 admin / admin，登录后请及时修改密码</p>
      </form>
    </div>
  );
}
