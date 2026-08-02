import { useEffect, useState } from "react";
import api, { API_BASE } from "@/lib/api";
import { PageHeader, SeverityBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Download, FileText, FileSpreadsheet, Calendar } from "lucide-react";

function toLocalIso(d) {
  const tz = d.getTimezoneOffset();
  const local = new Date(d.getTime() - tz * 60000);
  return local.toISOString().slice(0, 16);
}

export default function Reports() {
  const [start, setStart] = useState(toLocalIso(new Date(Date.now() - 7 * 86400000)));
  const [end, setEnd] = useState(toLocalIso(new Date()));
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(false);

  const rangeParams = () => {
    const p = new URLSearchParams();
    if (start) p.set("start", new Date(start).toISOString());
    if (end) p.set("end", new Date(end).toISOString());
    return p.toString();
  };

  const load = async () => {
    setLoading(true);
    try {
      const { data } = await api.get(`/reports/summary?${rangeParams()}`);
      setSummary(data);
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const dl = (path) => {
    window.open(`${API_BASE}${path}?${rangeParams()}`, "_blank");
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Reports"
        subtitle="Export alerts and incidents for any date range, grouped by severity. CSV for spreadsheets, PDF for share-out."
      />

      <div className="px-8 grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Range controls */}
        <div className="lg:col-span-4 border border-border/60 rounded-md bg-card/40 p-5 space-y-3" data-testid="reports-range">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
            <Calendar className="w-3 h-3" /> Range
          </div>
          <div>
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Start</Label>
            <Input
              type="datetime-local"
              value={start}
              onChange={(e) => setStart(e.target.value)}
              className="mt-1.5 font-mono"
              data-testid="report-start"
            />
          </div>
          <div>
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">End</Label>
            <Input
              type="datetime-local"
              value={end}
              onChange={(e) => setEnd(e.target.value)}
              className="mt-1.5 font-mono"
              data-testid="report-end"
            />
          </div>
          <Button onClick={load} disabled={loading} data-testid="report-refresh" className="w-full font-mono text-xs uppercase tracking-widest">
            {loading ? "Loading…" : "Refresh preview"}
          </Button>
        </div>

        {/* Summary preview */}
        <div className="lg:col-span-8 border border-border/60 rounded-md bg-card/40 p-5" data-testid="reports-summary">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
            Preview
          </div>
          {summary && (
            <div className="mt-3 grid grid-cols-2 md:grid-cols-4 gap-3">
              <StatBox label="Alerts (total)" value={summary.alerts_total} />
              <StatBox label="Incidents (total)" value={summary.incidents_total} />
              <div className="md:col-span-2 border border-border/50 rounded-sm p-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Alerts by severity
                </div>
                <div className="space-y-1.5">
                  {["Likely malicious", "Suspicious", "Informational"].map((s) => (
                    <div key={s} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={s} />
                      <span className="font-mono tabular-nums text-cyan-300">
                        {summary.alerts_by_severity?.[s] ?? 0}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="md:col-span-2 border border-border/50 rounded-sm p-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Incidents by severity
                </div>
                <div className="space-y-1.5">
                  {["Likely malicious", "Suspicious", "Informational"].map((s) => (
                    <div key={s} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={s} />
                      <span className="font-mono tabular-nums text-cyan-300">
                        {summary.incidents_by_severity?.[s] ?? 0}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="md:col-span-2 border border-border/50 rounded-sm p-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Incidents by status
                </div>
                <div className="space-y-1 text-xs font-mono">
                  {Object.entries(summary.incidents_by_status || {}).map(([k, v]) => (
                    <div key={k}>{k}: <span className="text-cyan-300">{v}</span></div>
                  ))}
                  {Object.keys(summary.incidents_by_status || {}).length === 0 && (
                    <div className="text-muted-foreground">—</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Downloads */}
        <div className="lg:col-span-12 border border-border/60 rounded-md bg-card/40 p-5" data-testid="reports-downloads">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-3">
            Export
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <DownloadTile
              icon={FileSpreadsheet}
              title="Alerts CSV"
              hint="One row per alert, grouped by severity"
              onClick={() => dl("/reports/alerts.csv")}
              testid="download-alerts-csv"
            />
            <DownloadTile
              icon={FileSpreadsheet}
              title="Incidents CSV"
              hint="One row per incident with root-cause + counts"
              onClick={() => dl("/reports/incidents.csv")}
              testid="download-incidents-csv"
            />
            <DownloadTile
              icon={FileText}
              title="Combined PDF"
              hint="Executive report — summary + tables per severity"
              onClick={() => dl("/reports/combined.pdf")}
              testid="download-combined-pdf"
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function StatBox({ label, value }) {
  return (
    <div className="border border-border/50 rounded-sm p-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="text-2xl font-semibold mt-1 tabular-nums">{value ?? "—"}</div>
    </div>
  );
}

function DownloadTile({ icon: Icon, title, hint, onClick, testid }) {
  return (
    <button
      onClick={onClick}
      data-testid={testid}
      className="text-left border border-border/60 rounded-md p-4 hover:bg-white/5 hover:border-primary/40"
      style={{ transition: "background-color 0.15s ease, border-color 0.15s ease" }}
    >
      <div className="flex items-center gap-2">
        <Icon className="w-4 h-4 text-primary" />
        <div className="text-sm font-medium">{title}</div>
      </div>
      <div className="text-[11px] font-mono text-muted-foreground mt-1">{hint}</div>
      <div className="mt-2 text-[10px] font-mono uppercase tracking-widest text-primary inline-flex items-center gap-1">
        <Download className="w-3 h-3" /> Download
      </div>
    </button>
  );
}
