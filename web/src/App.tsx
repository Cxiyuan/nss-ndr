import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { api, clearToken, isAuthed } from "./api";
import Dashboard from "./pages/Dashboard";
import ConfigPage from "./pages/ConfigPage";
import History from "./pages/History";
import RulesIndex from "./pages/RulesIndex";
import Login from "./pages/Login";

const nav = [
  { to: "/", label: "总览", end: true },
  { to: "/config", label: "参数配置" },
  { to: "/rules", label: "规则" },
  { to: "/history", label: "历史与审计" },
];

export default function App() {
  const [authed, setAuthed] = useState(isAuthed());
  const [showPwd, setShowPwd] = useState(false);
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [pwdMsg, setPwdMsg] = useState("");
  const [pwdErr, setPwdErr] = useState("");

  if (!authed) {
    return <Login />;
  }

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    clearToken();
    setAuthed(false);
  };

  const changePwd = async () => {
    setPwdErr("");
    setPwdMsg("");
    if (newPwd.length < 6) {
      setPwdErr("新密码至少 6 位");
      return;
    }
    try {
      await api.changePassword(oldPwd, newPwd);
      setPwdMsg("密码已修改");
      setOldPwd("");
      setNewPwd("");
      setShowPwd(false);
    } catch (e: any) {
      setPwdErr(e.message);
    }
  };

  return (
    <div className="layout">
      <header className="topbar">
        <div className="brand">NSS-NDR 探针管理</div>
        <nav className="topnav">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.end}
              className={({ isActive }) => "nav-item" + (isActive ? " active" : "")}
            >
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="user-area">
          <span className="user-name">admin</span>
          <button className="link-btn" onClick={() => setShowPwd(!showPwd)}>
            修改密码
          </button>
          <button className="link-btn" onClick={logout}>
            退出登录
          </button>
        </div>
      </header>
      <main className="content">
        {showPwd && (
          <div className="pwd-box">
            <input
              type="password"
              placeholder="原密码"
              value={oldPwd}
              onChange={(e) => setOldPwd(e.target.value)}
            />
            <input
              type="password"
              placeholder="新密码（至少 6 位）"
              value={newPwd}
              onChange={(e) => setNewPwd(e.target.value)}
            />
            <button className="btn primary" onClick={changePwd}>
              确认修改
            </button>
            {pwdErr && <div className="alert error">{pwdErr}</div>}
            {pwdMsg && <div className="alert ok">{pwdMsg}</div>}
          </div>
        )}
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/config" element={<ConfigPage />} />
          <Route path="/rules/*" element={<RulesIndex />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>
    </div>
  );
}
