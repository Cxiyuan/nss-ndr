import { useState } from "react";
import { NavLink, Route, Routes, useNavigate } from "react-router-dom";
import {
  Activity,
  FileClock,
  ListChecks,
  LogOut,
  Settings,
  ShieldCheck,
} from "lucide-react";

import { api, clearToken, isAuthed } from "@/api";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { toast } from "sonner";

import ConfigPage from "./pages/ConfigPage";
import Dashboard from "./pages/Dashboard";
import History from "./pages/History";
import Login from "./pages/Login";
import RulesIndex from "./pages/RulesIndex";

const nav = [
  { to: "/", label: "运维监控", icon: Activity, end: true },
  { to: "/config", label: "参数配置", icon: Settings },
  { to: "/rules", label: "规则", icon: ListChecks },
  { to: "/history", label: "历史与审计", icon: FileClock },
];

export default function App() {
  const [authed, setAuthed] = useState(isAuthed());
  const [showPwd, setShowPwd] = useState(false);
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [pwdMsg, setPwdMsg] = useState("");
  const [pwdErr, setPwdErr] = useState("");
  const navigate = useNavigate();

  if (!authed) {
    return (
      <TooltipProvider>
        <Login />
        <Toaster />
      </TooltipProvider>
    );
  }

  const logout = async () => {
    try {
      await api.logout();
    } catch {
      /* ignore */
    }
    clearToken();
    setAuthed(false);
    navigate("/");
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
      toast.success("密码已修改");
      setOldPwd("");
      setNewPwd("");
      setShowPwd(false);
    } catch (e: any) {
      setPwdErr(e.message);
      toast.error(e.message);
    }
  };

  return (
    <TooltipProvider delayDuration={300}>
      <div className="flex min-h-screen flex-col bg-background">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/95 px-6 backdrop-blur">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            <span className="text-base font-semibold tracking-tight">NSS-NDR 探针管理</span>
          </div>
          <nav className="ml-6 flex items-center gap-1">
            {nav.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                end={n.end}
                className={({ isActive }) =>
                  "inline-flex h-9 items-center gap-2 rounded-md px-3 text-sm font-medium transition-colors " +
                  (isActive
                    ? "bg-accent text-accent-foreground"
                    : "text-muted-foreground hover:bg-accent/50 hover:text-foreground")
                }
              >
                <n.icon className="h-4 w-4" />
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setShowPwd(!showPwd)}>
              修改密码
            </Button>
            <Button variant="ghost" size="sm" onClick={logout}>
              <LogOut className="mr-1 h-4 w-4" />
              退出登录
            </Button>
          </div>
        </header>

        {showPwd && (
          <div className="border-b bg-muted/40 px-6 py-4">
            <div className="flex flex-wrap items-center gap-2">
              <input
                type="password"
                placeholder="原密码"
                className="flex h-9 w-40 rounded-md border border-input bg-background px-3 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={oldPwd}
                onChange={(e) => setOldPwd(e.target.value)}
              />
              <input
                type="password"
                placeholder="新密码（至少 6 位）"
                className="flex h-9 w-48 rounded-md border border-input bg-background px-3 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                value={newPwd}
                onChange={(e) => setNewPwd(e.target.value)}
              />
              <Button size="sm" onClick={changePwd}>
                确认修改
              </Button>
            </div>
            {pwdErr && <p className="mt-2 text-sm text-destructive">{pwdErr}</p>}
            {pwdMsg && <p className="mt-2 text-sm text-emerald-300">{pwdMsg}</p>}
          </div>
        )}

        <Separator />

        <main className="container mx-auto max-w-screen-2xl flex-1 px-6 py-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/config" element={<ConfigPage />} />
            <Route path="/rules/*" element={<RulesIndex />} />
            <Route path="/history" element={<History />} />
          </Routes>
        </main>
      </div>
      <Toaster />
    </TooltipProvider>
  );
}