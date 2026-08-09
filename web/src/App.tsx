import { NavLink, Route, Routes } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import ConfigPage from "./pages/ConfigPage";
import Rules from "./pages/Rules";
import History from "./pages/History";
import Sigma from "./pages/Sigma";

const nav = [
  { to: "/", label: "总览", end: true },
  { to: "/config/probe", label: "探针" },
  { to: "/config/suricata", label: "Suricata" },
  { to: "/config/zeek", label: "Zeek" },
  { to: "/config/elasticsearch", label: "Elasticsearch" },
  { to: "/config/xdr", label: "告警推送" },
  { to: "/rules", label: "规则管理" },
  { to: "/sigma", label: "Sigma 检测" },
  { to: "/history", label: "历史与审计" },
];

export default function App() {
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">NSS-NDR 探针管理</div>
        <nav>
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
      </aside>
      <main className="content">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/config/probe" element={<ConfigPage section="probe" title="探针基础配置" />} />
          <Route path="/config/suricata" element={<ConfigPage section="suricata" title="Suricata 配置" />} />
          <Route path="/config/zeek" element={<ConfigPage section="zeek" title="Zeek 配置" />} />
          <Route path="/config/elasticsearch" element={<ConfigPage section="elasticsearch" title="Elasticsearch 配置" />} />
          <Route path="/config/xdr" element={<ConfigPage section="xdr" title="告警推送配置" />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/sigma" element={<Sigma />} />
          <Route path="/history" element={<History />} />
        </Routes>
      </main>
    </div>
  );
}
