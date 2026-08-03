import { useEffect, useMemo, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import { useSearchParams } from "react-router-dom";
import api from "@/lib/api";
import { PageHeader, SeverityBadge, StatusBadge, JsonView } from "@/components/common";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { ShieldOff, UserX, LogOut, GitBranch, ShieldCheck } from "lucide-react";

const STATUSES = ["New", "Under Review", "Investigating", "Confirmed", "False Positive", "Resolved"];

const ACTION_LABEL = {
  block_ip: "Block IP",
  disable_account: "Disable account",
  revoke_session: "Revoke session",
  escalate_incident: "Escalate to incident",
};
const ACTION_ICON = {
  block_ip: ShieldOff,
  disable_account: UserX,
  revoke_session: LogOut,
  escalate_incident: GitBranch,
};
const ACTION_HINT = {
  block_ip: "Adds the source IP to SentinelFlow's internal blocklist. Future events from this IP will auto-flag under R010.",
  disable_account: "Sets disabled=true on SentinelFlow-managed accounts. For external accounts, records a clear recommendation instead — SentinelFlow cannot reach into another system's user table.",
  revoke_session: "Bumps the account's token_version, invalidating any JWTs SentinelFlow issued. External accounts: records a recommendation.",
  escalate_incident: "Opens a new incident pre-filled with this alert's evidence and links this alert to it.",
};

export default function Alerts() {
  useDocumentTitle("Alerts · SentinelFlow");
  const [params, setParams] = useSearchParams();
  const [alerts, setAlerts] = useState([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [detail, setDetail] = useState(null);
  const [newStatus, setNewStatus] = useState("");
  const [note, setNote] = useState("");
  const [updating, setUpdating] = useState(false);
  const [recommended, setRecommended] = useState([]);
  const [history, setHistory] = useState([]);
  const [targetOverride, setTargetOverride] = useState({}); // per-action
  const [openIncidents, setOpenIncidents] = useState([]);
  const [linkTarget, setLinkTarget] = useState("");

  const load = async () => {
    try {
      const q = {};
      if (statusFilter !== "all") q.status = statusFilter;
      if (severityFilter !== "all") q.severity = severityFilter;
      const { data } = await api.get("/alerts", { params: q });
      setAlerts(data);
    } catch {
      toast.error("Failed to load alerts");
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [statusFilter, severityFilter]);

  // deep-link ?id=...
  useEffect(() => {
    const id = params.get("id");
    if (id) openDetail(id);
    // eslint-disable-next-line
  }, [params]);

  const openDetail = async (id) => {
    try {
      const [{ data }, { data: rec }, { data: hist }, { data: incList }] = await Promise.all([
        api.get(`/alerts/${id}`),
        api.get(`/alerts/${id}/recommended-actions`),
        api.get(`/alerts/${id}/actions`),
        api.get(`/incidents`),
      ]);
      setDetail(data);
      setNewStatus(data.status);
      setNote("");
      setRecommended(rec);
      setHistory(hist);
      setOpenIncidents(incList.filter((i) => i.status !== "Closed"));
      setLinkTarget("");
      const overrides = {};
      rec.forEach((r) => { overrides[r.type] = r.default_target || ""; });
      setTargetOverride(overrides);
    } catch {
      toast.error("Failed to load alert");
    }
  };

  const linkToIncident = async () => {
    if (!detail || !linkTarget) return;
    try {
      await api.post(`/incidents/${linkTarget}/alerts`, { alert_ids: [detail.id] });
      toast.success("Alert linked to incident");
      setLinkTarget("");
      await openDetail(detail.id);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    }
  };

  const approve = async (action_type) => {
    if (!detail) return;
    try {
      const res = await api.post(`/alerts/${detail.id}/approve`, {
        action_type,
        target: targetOverride[action_type] || undefined,
        note,
      });
      const r = res.data;
      const label = ACTION_LABEL[action_type] || action_type;
      const detailMsg = r.result === "recommended_external"
        ? `${label}: manual recommendation recorded`
        : `${label}: ${r.result.replace(/_/g, " ")}`;
      toast.success(detailMsg);
      setNote("");
      await openDetail(detail.id);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Action failed");
    }
  };

  const closeDetail = () => {
    setDetail(null);
    if (params.get("id")) {
      params.delete("id");
      setParams(params, { replace: true });
    }
  };

  const updateStatus = async () => {
    if (!detail) return;
    if (newStatus === detail.status && !note.trim()) {
      toast.info("No changes to save");
      return;
    }
    setUpdating(true);
    try {
      await api.patch(`/alerts/${detail.id}`, { status: newStatus, note });
      toast.success("Alert updated");
      await load();
      await openDetail(detail.id);
    } catch (e) {
      toast.error("Update failed");
    } finally {
      setUpdating(false);
    }
  };

  const grouped = useMemo(() => {
    const g = { critical: [], suspicious: [], info: [] };
    for (const a of alerts) {
      if (a.severity === "Likely malicious") g.critical.push(a);
      else if (a.severity === "Suspicious") g.suspicious.push(a);
      else g.info.push(a);
    }
    return g;
  }, [alerts]);

  return (
    <div className="pb-16">
      <PageHeader
        title="Alerts Inbox"
        subtitle="Every finding cites the raw evidence. Triage, comment, and close the loop."
      />

      <div className="px-8 flex flex-wrap items-center gap-3 mb-4">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[200px] font-mono text-xs" data-testid="alerts-status-filter">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-popover border border-border">
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map((s) => (<SelectItem key={s} value={s}>{s}</SelectItem>))}
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[200px] font-mono text-xs" data-testid="alerts-severity-filter">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-popover border border-border">
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="Informational">Informational</SelectItem>
            <SelectItem value="Suspicious">Suspicious</SelectItem>
            <SelectItem value="Likely malicious">Likely malicious</SelectItem>
          </SelectContent>
        </Select>
        <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-widest ml-auto" data-testid="alerts-count">
          {alerts.length} alerts
        </div>
      </div>

      <div className="px-8 space-y-6">
        <AlertGroup title="Likely malicious" tone="critical" alerts={grouped.critical} onOpen={openDetail} />
        <AlertGroup title="Suspicious" tone="warning" alerts={grouped.suspicious} onOpen={openDetail} />
        <AlertGroup title="Informational" tone="info" alerts={grouped.info} onOpen={openDetail} />
      </div>

      <Sheet open={!!detail} onOpenChange={(o) => !o && closeDetail()}>
        <SheetContent side="right" className="w-full sm:max-w-2xl bg-card border-l border-border/60 overflow-y-auto" data-testid="alert-drawer">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Alert · {detail?.rule_id}
            </SheetTitle>
          </SheetHeader>
          {detail && (
            <div className="mt-6 space-y-6">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={detail.severity} />
                <StatusBadge status={detail.status} />
                <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
                  {new Date(detail.created_at).toLocaleString()}
                </span>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
                  Rule fired
                </div>
                <div className="text-sm font-medium">{detail.rule_name}</div>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
                  Explanation
                </div>
                <div className="text-sm leading-relaxed">{detail.explanation}</div>
              </div>
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
                  Recommended action <span className="text-amber-500">(requires human approval)</span>
                </div>
                <div className="text-sm leading-relaxed border border-amber-500/30 bg-amber-500/5 rounded-sm p-3">
                  {detail.recommended_action}
                </div>
              </div>

              {/* Response actions (human-approved) */}
              {recommended.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                    Response actions
                  </div>
                  <div className="space-y-2" data-testid="response-actions">
                    {recommended.map((r) => {
                      const Icon = ACTION_ICON[r.type];
                      return (
                        <div key={r.type} className="border border-border/60 rounded-sm p-3 space-y-2" data-testid={`action-${r.type}`}>
                          <div className="flex items-center gap-2">
                            <Icon className="w-3.5 h-3.5 text-primary" />
                            <span className="text-sm font-medium">{ACTION_LABEL[r.type]}</span>
                          </div>
                          <div className="text-[11px] text-muted-foreground leading-relaxed">
                            {ACTION_HINT[r.type]}
                          </div>
                          {(r.type === "block_ip" || r.type === "disable_account" || r.type === "revoke_session") && (
                            <Input
                              value={targetOverride[r.type] || ""}
                              onChange={(e) => setTargetOverride({ ...targetOverride, [r.type]: e.target.value })}
                              placeholder={r.type === "block_ip" ? "IP address" : "Account (email or username)"}
                              className="font-mono text-xs h-8"
                              data-testid={`target-${r.type}`}
                            />
                          )}
                          <Button
                            onClick={() => approve(r.type)}
                            size="sm"
                            className="w-full font-mono text-[11px] uppercase tracking-widest"
                            data-testid={`approve-${r.type}`}
                          >
                            <ShieldCheck className="w-3 h-3 mr-1.5" />
                            Approve {ACTION_LABEL[r.type]}
                          </Button>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Executed actions history */}
              {history.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                    Approvals · {history.length}
                  </div>
                  <div className="space-y-1.5" data-testid="approval-history">
                    {history.map((h) => (
                      <div key={h.id} className="text-[11px] font-mono border border-emerald-500/25 bg-emerald-500/5 rounded-sm px-2 py-1.5">
                        <span className="text-emerald-400 uppercase tracking-widest">{h.result.replace(/_/g, " ")}</span>
                        {" · "}
                        <span className="text-cyan-300">{h.approver}</span>
                        {" · "}
                        <span>{ACTION_LABEL[h.action_type] || h.action_type}</span>
                        {h.target && <span className="text-muted-foreground"> → {h.target}</span>}
                        <div className="text-muted-foreground">{new Date(h.created_at).toLocaleString()}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Link to existing incident */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Link to existing incident
                </div>
                {(detail.linked_incidents || []).length > 0 && (
                  <div className="mb-2 space-y-1" data-testid="linked-incidents">
                    {detail.linked_incidents.map((i) => (
                      <div key={i.id} className="text-[11px] font-mono border border-primary/25 bg-primary/5 rounded-sm px-2 py-1.5 flex items-center gap-2">
                        <GitBranch className="w-3 h-3 text-primary" />
                        <span className="text-primary">{i.status}</span>
                        <span className="text-muted-foreground">·</span>
                        <a href={`/incidents`} className="hover:underline">{i.title}</a>
                      </div>
                    ))}
                  </div>
                )}
                {openIncidents.length === 0 ? (
                  <div className="text-[11px] font-mono text-muted-foreground">
                    No open incidents. Use "Escalate to incident" above to open one.
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <Select value={linkTarget} onValueChange={setLinkTarget}>
                      <SelectTrigger className="flex-1 font-mono text-xs" data-testid="link-incident-select">
                        <SelectValue placeholder="Choose an incident…" />
                      </SelectTrigger>
                      <SelectContent className="bg-popover border border-border">
                        {openIncidents.map((i) => (
                          <SelectItem key={i.id} value={i.id}>
                            {i.status} · {i.title.slice(0, 60)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <Button
                      size="sm"
                      onClick={linkToIncident}
                      disabled={!linkTarget}
                      data-testid="link-incident-btn"
                      className="font-mono text-[10px] uppercase tracking-widest"
                    >
                      Link
                    </Button>
                  </div>
                )}
              </div>

              {/* Evidence */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Evidence · {detail.evidence_events?.length || 0} events
                </div>
                <div className="space-y-2" data-testid="alert-evidence">
                  {(detail.evidence_events || []).map((e) => (
                    <div key={e.event_id} className="border border-border/60 rounded-sm p-3">
                      <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                        <span>{new Date(e.timestamp).toLocaleString()}</span>
                        <span>·</span>
                        <span className="text-cyan-300">{e.src_ip || "—"}</span>
                        {e.user && <><span>·</span><span>{e.user}</span></>}
                      </div>
                      <div className="mt-1 text-xs font-mono">
                        {e.app}/{e.action || "event"} — status {String(e.http_status ?? "—")}
                      </div>
                    </div>
                  ))}
                  {(!detail.evidence_events || detail.evidence_events.length === 0) && (
                    <div className="text-xs text-muted-foreground font-mono">
                      No linked events (this may be a source-silence alert).
                    </div>
                  )}
                </div>
              </div>

              {/* Status update */}
              <div className="border-t border-border/60 pt-5 space-y-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  Update status
                </div>
                <div className="flex items-center gap-2">
                  <Select value={newStatus} onValueChange={setNewStatus}>
                    <SelectTrigger className="w-[220px] font-mono text-xs" data-testid="alert-status-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-popover border border-border">
                      {STATUSES.map((s) => (<SelectItem key={s} value={s}>{s}</SelectItem>))}
                    </SelectContent>
                  </Select>
                </div>
                <Textarea
                  data-testid="alert-note"
                  placeholder="Add investigator note (optional)…"
                  value={note}
                  onChange={(e) => setNote(e.target.value)}
                  className="font-mono text-xs"
                />
                <Button onClick={updateStatus} disabled={updating} data-testid="alert-save" className="font-mono text-xs uppercase tracking-widest">
                  {updating ? "Saving…" : "Save update"}
                </Button>
              </div>

              {/* History */}
              {detail.notes?.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                    Status history
                  </div>
                  <div className="space-y-1.5">
                    {detail.notes.map((n, i) => (
                      <div key={i} className="text-[11px] font-mono border border-border/50 rounded-sm px-2 py-1.5">
                        <span className="text-muted-foreground">{new Date(n.at).toLocaleString()}</span>
                        {" — "}
                        <span className="text-cyan-300">{n.by}</span>
                        {": "}
                        <span>{n.from} → {n.to}</span>
                        {n.note && <span className="text-muted-foreground"> — {n.note}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Alert payload
                </div>
                <JsonView value={{ id: detail.id, rule_id: detail.rule_id, key_fields: detail.key_fields }} />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function AlertGroup({ title, tone, alerts, onOpen }) {
  if (alerts.length === 0) return null;
  const dotCls = tone === "critical" ? "bg-red-500" : tone === "warning" ? "bg-amber-500" : "bg-cyan-500";
  return (
    <div>
      <div className="flex items-center gap-2 mb-3">
        <span className={`w-2 h-2 rounded-full ${dotCls}`} />
        <h2 className="text-sm font-semibold" data-testid={`alert-group-${tone}`}>{title}</h2>
        <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
          {alerts.length}
        </span>
      </div>
      <div className="space-y-2">
        {alerts.map((a) => (
          <button
            key={a.id}
            onClick={() => onOpen(a.id)}
            data-testid={`alert-item-${a.id}`}
            className={`w-full text-left border border-border/60 rounded-md bg-card/40 p-4 hover:bg-white/[0.04] block ${tone === "critical" ? "critical-glow" : ""}`}
            style={{ transition: "background-color 0.15s ease" }}
          >
            <div className="flex items-center gap-2">
              <SeverityBadge severity={a.severity} />
              <StatusBadge status={a.status} />
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {a.rule_id} · {new Date(a.created_at).toLocaleString()}
              </span>
            </div>
            <div className="mt-2 text-sm font-medium">{a.rule_name}</div>
            <div className="mt-1 text-xs text-muted-foreground line-clamp-2">
              {a.explanation}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}
