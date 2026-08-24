import { useEffect, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import { Link } from "react-router-dom";
import {
  LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
  BarChart, Bar, PieChart, Pie, Cell, Legend,
} from "recharts";
import { Activity, Bell, AlertOctagon, EyeOff, ArrowUpRight, Mail, MailX } from "lucide-react";
import api from "@/lib/api";
import { PageHeader, SeverityBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";

const SEV_COLOR = {
  "Likely malicious": "#ef4444",
  Suspicious: "#f59e0b",
  Informational: "#06b6d4",
};

export default function Dashboard() {
  useDocumentTitle("Dashboard · SentinelFlow");
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [seeding, setSeeding] = useState(false);
  const [notifier, setNotifier] = useState(null);

  const load = async () => {
    try {
      const [s, a, n] = await Promise.all([
        api.get("/dashboard/stats"),
        api.get("/alerts"),
        api.get("/notifier/status"),
      ]);
      setStats(s.data);
      setAlerts(a.data.slice(0, 6));
      setNotifier(n.data);
    } catch (e) {
      toast.error("Failed to load dashboard");
    }
  };

  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const seed = async () => {
    setSeeding(true);
    try {
      const { data } = await api.post("/ingest/seed");
      toast.success(`Seeded ${data.ingested} events · ${data.alerts} alerts`);
      await load();
    } catch (e) {
      toast.error("Seed failed");
    } finally {
      setSeeding(false);
    }
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Security Operations"
        subtitle="Real-time posture across your ingested log sources."
        right={
          <div className="flex items-center gap-3">
            {notifier && (
              <div
                data-testid="notifier-pill"
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm border text-[10px] font-mono uppercase tracking-widest ${
                  notifier.enabled
                    ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/25"
                    : "bg-zinc-500/10 text-zinc-400 border-zinc-500/25"
                }`}
                title={notifier.enabled
                  ? `SMTP: ${notifier.smtp_host} · to ${notifier.recipients.length} recipients`
                  : "SMTP not configured — set SMTP_HOST, SMTP_FROM, ALERT_EMAIL_TO in backend/.env"}
              >
                {notifier.enabled ? <Mail className="w-3 h-3" /> : <MailX className="w-3 h-3" />}
                Email · {notifier.enabled ? "on" : "off"}
              </div>
            )}
            {user?.role === "admin" && (
              <Button
                onClick={seed}
                disabled={seeding}
                variant="outline"
                data-testid="seed-demo-btn"
                className="font-mono text-xs uppercase tracking-widest"
              >
                {seeding ? "Loading…" : "Load Demo Data"}
              </Button>
            )}
          </div>
        }
      />

      <div className="px-8 grid grid-cols-1 md:grid-cols-4 gap-4">
        <StatCard label="Events (24h)" value={stats?.events_24h ?? "—"} icon={Activity} testid="stat-events-24h" />
        <StatCard label="Open Alerts" value={stats?.open_alerts ?? "—"} icon={Bell} testid="stat-open-alerts" />
        <StatCard label="Critical Alerts" value={stats?.critical_alerts ?? "—"} icon={AlertOctagon} tone="critical" testid="stat-critical-alerts" />
        <StatCard label="Silent Sources" value={stats?.silent_sources ?? "—"} icon={EyeOff} tone="warning" testid="stat-silent-sources" />
      </div>

      <div className="px-8 mt-6 grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Timeseries */}
        <div className="lg:col-span-8 border border-border/60 rounded-md bg-card/40 p-5" data-testid="chart-timeseries">
          <div className="flex items-center justify-between mb-4">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                /// Event volume
              </div>
              <div className="text-base font-semibold">Last 24 hours</div>
            </div>
          </div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={stats?.timeseries || []} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
                <XAxis dataKey="hour" tick={{ fill: "#6b7280", fontSize: 10, fontFamily: "JetBrains Mono" }} tickFormatter={(v) => v?.slice(11)} />
                <YAxis tick={{ fill: "#6b7280", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="count" stroke="#6366f1" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts by Severity */}
        <div className="lg:col-span-4 border border-border/60 rounded-md bg-card/40 p-5" data-testid="chart-severity">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            /// Alerts by severity
          </div>
          <div className="text-base font-semibold mb-2">Distribution</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={stats?.alerts_by_severity || []}
                  dataKey="count"
                  nameKey="severity"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={2}
                >
                  {(stats?.alerts_by_severity || []).map((entry, i) => (
                    <Cell key={i} fill={SEV_COLOR[entry.severity] || "#64748b"} />
                  ))}
                </Pie>
                <Tooltip contentStyle={tooltipStyle} />
                <Legend wrapperStyle={{ fontSize: 10, fontFamily: "JetBrains Mono" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top IPs */}
        <div className="lg:col-span-6 border border-border/60 rounded-md bg-card/40 p-5" data-testid="chart-top-ips">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            /// Top source IPs
          </div>
          <div className="text-base font-semibold mb-2">Traffic volume</div>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.top_ips || []} layout="vertical" margin={{ top: 0, right: 20, left: 30, bottom: 0 }}>
                <CartesianGrid stroke="rgba(255,255,255,0.05)" strokeDasharray="3 3" />
                <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <YAxis type="category" dataKey="src_ip" tick={{ fill: "#d1d5db", fontSize: 10, fontFamily: "JetBrains Mono" }} width={110} />
                <Tooltip contentStyle={tooltipStyle} />
                <Bar dataKey="count" fill="#06b6d4" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Recent alerts */}
        <div className="lg:col-span-6 border border-border/60 rounded-md bg-card/40 p-5" data-testid="recent-alerts">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                /// Recent alerts
              </div>
              <div className="text-base font-semibold">Latest 6</div>
            </div>
            <Link to="/alerts" className="text-xs text-primary hover:underline flex items-center gap-1" data-testid="view-all-alerts">
              View all <ArrowUpRight className="w-3 h-3" />
            </Link>
          </div>
          <div className="space-y-2">
            {alerts.length === 0 && (
              <div className="text-xs text-muted-foreground font-mono py-8 text-center">
                No alerts yet. Load demo data or upload logs.
              </div>
            )}
            {alerts.map((a) => (
              <Link
                to={`/alerts?id=${a.id}`}
                key={a.id}
                data-testid={`recent-alert-${a.id}`}
                className="block border border-border/60 rounded-sm px-3 py-2 hover:bg-white/5"
                style={{ transition: "background-color 0.15s ease" }}
              >
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={a.severity} />
                  <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                    {a.rule_id}
                  </span>
                </div>
                <div className="text-xs mt-1.5 line-clamp-2 text-foreground/90">
                  {a.explanation}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

const tooltipStyle = {
  backgroundColor: "hsl(225 17% 10%)",
  border: "1px solid hsl(225 16% 14%)",
  borderRadius: 6,
  fontSize: 11,
  fontFamily: "JetBrains Mono",
};

function StatCard({ label, value, icon: Icon, tone, testid }) {
  const toneCls = tone === "critical"
    ? "text-red-400"
    : tone === "warning"
      ? "text-amber-400"
      : "text-foreground";
  return (
    <div
      className="border border-border/60 rounded-md bg-card/40 p-5"
      data-testid={testid}
    >
      <div className="flex items-center justify-between">
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          {label}
        </div>
        <Icon className={`w-4 h-4 ${toneCls}`} />
      </div>
      <div className={`text-3xl font-semibold mt-3 tabular-nums ${toneCls}`}>
        {value}
      </div>
    </div>
  );
}
