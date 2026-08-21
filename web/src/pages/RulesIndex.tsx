import { NavLink, Navigate, Route, Routes } from "react-router-dom";

import Detections from "./Detections";
import Rules from "./Rules";

const subs = [
  { to: "/rules/detections", label: "事件检测" },
  { to: "/rules/custom", label: "自定义规则" },
];

export default function RulesIndex() {
  return (
    <div className="grid gap-6 md:grid-cols-[200px_1fr]">
      <aside>
        <h3 className="mb-3 px-2 text-sm font-medium text-muted-foreground">检测规则</h3>
        <nav className="flex flex-col gap-1">
          {subs.map((s) => (
            <NavLink
              key={s.to}
              to={s.to}
              className={({ isActive }) =>
                "rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent hover:text-accent-foreground " +
                (isActive ? "bg-accent font-medium text-accent-foreground" : "text-muted-foreground")
              }
            >
              {s.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <section>
        <Routes>
          <Route index element={<Navigate to="/rules/detections" replace />} />
          <Route path="detections" element={<Detections />} />
          <Route path="custom" element={<Rules />} />
        </Routes>
      </section>
    </div>
  );
}