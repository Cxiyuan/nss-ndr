import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import Detections from "./Detections";
import Rules from "./Rules";

const subs = [
  { to: "/rules/detections", label: "事件检测" },
  { to: "/rules/custom", label: "自定义规则" },
];

export default function RulesIndex() {
  return (
    <div className="rules-layout">
      <aside className="rules-sidebar">
        <div className="rules-sidebar-title">检测规则</div>
        {subs.map((s) => (
          <NavLink
            key={s.to}
            to={s.to}
            className={({ isActive }) => "side-item" + (isActive ? " active" : "")}
          >
            {s.label}
          </NavLink>
        ))}
      </aside>
      <section className="rules-content">
        <Routes>
          <Route index element={<Navigate to="/rules/detections" replace />} />
          <Route path="detections" element={<Detections />} />
          <Route path="custom" element={<Rules />} />
        </Routes>
      </section>
    </div>
  );
}
