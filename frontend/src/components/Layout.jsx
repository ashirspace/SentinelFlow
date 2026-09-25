import { NavLink, useNavigate } from "react-router-dom";
import {
  ShieldAlert, LayoutDashboard, Search, Bell, Upload, Radar,
  Users, FileText, LogOut, Circle, AlertTriangle, HardDrive, BarChart3, MessageSquare,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { Toaster } from "sonner";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard, testid: "nav-dashboard" },
  { to: "/alerts", label: "Alerts", icon: Bell, testid: "nav-alerts" },
  { to: "/incidents", label: "Incidents", icon: AlertTriangle, testid: "nav-incidents" },
  { to: "/explorer", label: "Log Explorer", icon: Search, testid: "nav-explorer" },
  { to: "/sources", label: "Log Sources", icon: HardDrive, testid: "nav-sources" },
  { to: "/ingest", label: "Ingestion", icon: Upload, testid: "nav-ingest" },
  { to: "/rules", label: "Detection Rules", icon: Radar, testid: "nav-rules" },
  { to: "/reports", label: "Reports", icon: BarChart3, testid: "nav-reports" },
  { to: "/notifications", label: "Notifications", icon: MessageSquare, testid: "nav-notifications" },
];
const ADMIN_NAV = [
  { to: "/users", label: "Users", icon: Users, testid: "nav-users" },
  { to: "/audit", label: "Audit Log", icon: FileText, testid: "nav-audit" },
];

export default function Layout({ children }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="min-h-screen flex bg-background text-foreground">
      <Toaster theme="dark" position="top-right" />
      {/* Sidebar */}
      <aside className="sticky top-0 h-screen w-64 shrink-0 border-r border-border/60 bg-card/60 backdrop-blur-md flex flex-col z-30 select-none">
        <div className="px-5 py-5 border-b border-border/60 flex items-center gap-3">
          <ShieldAlert className="w-6 h-6 text-primary critical-glow shrink-0" />
          <div className="min-w-0">
            <div className="text-base font-semibold tracking-tight truncate" data-testid="brand-title">
              SentinelFlow
            </div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              Enterprise SIEM
            </div>
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="px-3 py-1.5 text-[10px] font-mono uppercase tracking-widest text-muted-foreground/80">
            Operations
          </div>
          {NAV.map((item) => (
            <NavItem key={item.to} {...item} />
          ))}
          {user?.role === "admin" && (
            <>
              <div className="px-3 pt-5 pb-1.5 text-[10px] font-mono uppercase tracking-widest text-muted-foreground/80">
                Administration
              </div>
              {ADMIN_NAV.map((item) => (
                <NavItem key={item.to} {...item} />
              ))}
            </>
          )}
        </nav>

        <div className="border-t border-border/60 p-3 bg-card/40 shrink-0">
          <div className="px-3 py-2 flex items-center gap-2.5 rounded-md bg-white/[0.02] border border-border/40">
            <Circle className="w-2.5 h-2.5 fill-emerald-500 text-emerald-500 shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="text-xs font-medium truncate" data-testid="current-user-email">
                {user?.email}
              </div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-400">
                {user?.role}
              </div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            data-testid="logout-btn"
            className="mt-2 w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-white/5 rounded-md transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Content */}
      <main className="flex-1 min-w-0 bg-grid">
        {children}
      </main>
    </div>
  );
}

function NavItem({ to, label, icon: Icon, testid }) {
  return (
    <NavLink
      to={to}
      data-testid={testid}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-all duration-150 ` +
        (isActive
          ? "bg-primary/15 text-primary-foreground border border-primary/30 shadow-sm"
          : "text-muted-foreground hover:text-foreground hover:bg-white/5 border border-transparent")
      }
    >
      <Icon className="w-4 h-4 shrink-0" />
      <span className="truncate">{label}</span>
    </NavLink>
  );
}
