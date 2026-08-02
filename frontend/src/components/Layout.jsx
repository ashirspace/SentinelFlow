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
      <aside className="w-64 shrink-0 border-r border-border/60 bg-card/40 flex flex-col">
        <div className="px-5 py-5 border-b border-border/60 flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-primary critical-glow" />
          <div>
            <div className="text-base font-semibold tracking-tight" data-testid="brand-title">
              SentinelFlow
            </div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
              SIEM · MVP
            </div>
          </div>
        </div>

        <nav className="flex-1 px-2 py-4 space-y-0.5">
          <div className="px-3 py-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            Operations
          </div>
          {NAV.map((item) => (
            <NavItem key={item.to} {...item} />
          ))}
          {user?.role === "admin" && (
            <>
              <div className="px-3 pt-4 pb-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Administration
              </div>
              {ADMIN_NAV.map((item) => (
                <NavItem key={item.to} {...item} />
              ))}
            </>
          )}
        </nav>

        <div className="border-t border-border/60 p-3">
          <div className="px-2 py-2 flex items-center gap-2">
            <Circle className="w-2 h-2 fill-emerald-500 text-emerald-500" />
            <div className="min-w-0">
              <div className="text-xs font-medium truncate" data-testid="current-user-email">
                {user?.email}
              </div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {user?.role}
              </div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            data-testid="logout-btn"
            className="mt-2 w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-white/5 rounded-md"
            style={{ transition: "color 0.15s ease, background-color 0.15s ease" }}
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
        `flex items-center gap-3 px-3 py-2 mx-1 rounded-md text-sm ` +
        (isActive
          ? "bg-primary/10 text-foreground border border-primary/25"
          : "text-muted-foreground hover:text-foreground hover:bg-white/5 border border-transparent")
      }
      style={{ transition: "background-color 0.15s ease, color 0.15s ease" }}
    >
      <Icon className="w-4 h-4" />
      <span>{label}</span>
    </NavLink>
  );
}
