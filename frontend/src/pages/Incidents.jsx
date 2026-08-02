import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader, SeverityBadge } from "@/components/common";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { toast } from "sonner";
import { Plus, Unlink, Clock, MessageSquare, RefreshCw, FileText, GitBranch } from "lucide-react";

const STATUSES = ["Open", "Investigating", "Resolved", "Closed"];
const STATUS_CLS = {
  Open: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  Investigating: "bg-indigo-500/10 text-indigo-400 border-indigo-500/25",
  Resolved: "bg-cyan-500/10 text-cyan-400 border-cyan-500/25",
  Closed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
};

const KIND_ICON = {
  opened: GitBranch,
  status: RefreshCw,
  root_cause: FileText,
  note: MessageSquare,
  alerts_added: Plus,
  alerts_removed: Unlink,
  title: FileText,
};

export default function Incidents() {
  const [items, setItems] = useState([]);
  const [statusFilter, setStatusFilter] = useState("all");
  const [detail, setDetail] = useState(null);
  const [status, setStatus] = useState("");
  const [rootCause, setRootCause] = useState("");
  const [note, setNote] = useState("");
  const [newOpen, setNewOpen] = useState(false);
  const [newForm, setNewForm] = useState({ title: "", severity: "Suspicious", summary: "" });
  const [creating, setCreating] = useState(false);

  const load = async () => {
    const params = statusFilter !== "all" ? { status: statusFilter } : {};
    const { data } = await api.get("/incidents", { params });
    setItems(data);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [statusFilter]);

  const open = async (id) => {
    const { data } = await api.get(`/incidents/${id}`);
    setDetail(data);
    setStatus(data.status);
    setRootCause(data.root_cause || "");
    setNote("");
  };

  const save = async (payload) => {
    if (!detail) return;
    try {
      await api.patch(`/incidents/${detail.id}`, payload);
      toast.success("Incident updated");
      await load();
      await open(detail.id);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    }
  };

  const saveStatus = () => save({ status });
  const saveRootCause = () => save({ root_cause: rootCause });
  const saveNote = () => {
    if (!note.trim()) return;
    save({ note });
    setNote("");
  };

  const unlink = async (alertId) => {
    if (!detail) return;
    if (!confirm("Unlink this alert from the incident?")) return;
    try {
      await api.delete(`/incidents/${detail.id}/alerts/${alertId}`);
      toast.success("Alert unlinked");
      await open(detail.id);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    }
  };

  const createIncident = async (e) => {
    e.preventDefault();
    if (!newForm.title.trim()) return;
    setCreating(true);
    try {
      const { data } = await api.post("/incidents", newForm);
      toast.success("Incident opened");
      setNewOpen(false);
      setNewForm({ title: "", severity: "Suspicious", summary: "" });
      await load();
      await open(data.id);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setCreating(false);
    }
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Incidents"
        subtitle="Group related alerts into an investigation. Timeline, evidence, and root cause live here."
        right={
          <div className="flex items-center gap-3">
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[180px] font-mono text-xs" data-testid="incident-status-filter">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent className="bg-popover border border-border">
                <SelectItem value="all">All statuses</SelectItem>
                {STATUSES.map((s) => (<SelectItem key={s} value={s}>{s}</SelectItem>))}
              </SelectContent>
            </Select>
            <Button
              onClick={() => setNewOpen(true)}
              data-testid="new-incident-btn"
              className="font-mono text-xs uppercase tracking-widest"
            >
              <Plus className="w-3.5 h-3.5 mr-1.5" />
              New incident
            </Button>
          </div>
        }
      />

      <div className="px-8 space-y-2">
        {items.length === 0 && (
          <div className="text-xs font-mono text-muted-foreground py-12 text-center border border-border/60 rounded-md bg-card/40">
            No incidents yet. Open an alert and click "Escalate to incident" to start one.
          </div>
        )}
        {items.map((i) => (
          <button
            key={i.id}
            onClick={() => open(i.id)}
            data-testid={`incident-item-${i.id}`}
            className="w-full text-left border border-border/60 rounded-md bg-card/40 p-4 hover:bg-white/[0.04] block"
            style={{ transition: "background-color 0.15s ease" }}
          >
            <div className="flex items-center gap-2">
              <SeverityBadge severity={i.severity} />
              <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] uppercase tracking-widest border ${STATUS_CLS[i.status]}`}>
                {i.status}
              </span>
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {new Date(i.opened_at).toLocaleString()} · opened by {i.opened_by}
              </span>
            </div>
            <div className="mt-2 text-sm font-medium">{i.title}</div>
            <div className="mt-1 text-xs text-muted-foreground line-clamp-2">{i.summary}</div>
            <div className="mt-1 text-[10px] font-mono text-muted-foreground uppercase tracking-widest">
              {i.alert_ids?.length || 0} alerts · {i.evidence_event_ids?.length || 0} events
            </div>
          </button>
        ))}
      </div>

      <Sheet open={!!detail} onOpenChange={(o) => !o && setDetail(null)}>
        <SheetContent side="right" className="w-full sm:max-w-2xl bg-card border-l border-border/60 overflow-y-auto" data-testid="incident-drawer">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Incident · {detail?.title}
            </SheetTitle>
          </SheetHeader>
          {detail && (
            <div className="mt-6 space-y-6">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={detail.severity} />
                <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] uppercase tracking-widest border ${STATUS_CLS[detail.status]}`}>
                  {detail.status}
                </span>
                <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  opened {new Date(detail.opened_at).toLocaleString()} · {detail.opened_by}
                </span>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Summary</div>
                <div className="text-sm leading-relaxed">{detail.summary}</div>
              </div>

              {/* Status + Root cause */}
              <div className="grid grid-cols-1 gap-3">
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">Lifecycle</div>
                  <div className="flex items-center gap-2">
                    <Select value={status} onValueChange={setStatus}>
                      <SelectTrigger className="w-[220px] font-mono text-xs" data-testid="incident-status-select"><SelectValue /></SelectTrigger>
                      <SelectContent className="bg-popover border border-border">
                        {STATUSES.map((s) => (<SelectItem key={s} value={s}>{s}</SelectItem>))}
                      </SelectContent>
                    </Select>
                    <Button size="sm" onClick={saveStatus} disabled={status === detail.status} data-testid="incident-status-save" className="font-mono text-[10px] uppercase tracking-widest">
                      Update status
                    </Button>
                  </div>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">Root cause</div>
                  <Textarea
                    value={rootCause}
                    onChange={(e) => setRootCause(e.target.value)}
                    placeholder="Describe what actually caused this — evidence-backed. Empty until you fill it in."
                    className="font-mono text-xs"
                    rows={3}
                    data-testid="incident-root-cause"
                  />
                  <Button size="sm" onClick={saveRootCause} disabled={rootCause === (detail.root_cause || "")} data-testid="incident-root-cause-save" className="mt-1 font-mono text-[10px] uppercase tracking-widest">
                    Save root cause
                  </Button>
                </div>

                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">Add note</div>
                  <Textarea
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    placeholder="What did you just observe or decide?"
                    className="font-mono text-xs"
                    data-testid="incident-note"
                  />
                  <Button size="sm" onClick={saveNote} disabled={!note.trim()} data-testid="incident-note-save" className="mt-1 font-mono text-[10px] uppercase tracking-widest">
                    Add note
                  </Button>
                </div>
              </div>

              {/* Linked alerts w/ unlink */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Linked alerts · {detail.alerts?.length || 0}
                </div>
                <div className="space-y-2" data-testid="incident-alerts">
                  {(detail.alerts || []).map((a) => (
                    <div key={a.id} className="border border-border/60 rounded-sm p-2 flex items-start gap-2">
                      <div className="flex-1 min-w-0">
                        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                          {a.rule_id} · {a.severity}
                        </div>
                        <div className="text-xs mt-1">{a.explanation}</div>
                      </div>
                      <button
                        onClick={() => unlink(a.id)}
                        data-testid={`unlink-${a.id}`}
                        title="Unlink from incident"
                        className="p-1.5 rounded-sm border border-border/60 text-muted-foreground hover:text-red-400 hover:bg-white/5"
                        style={{ transition: "color 0.15s ease" }}
                      >
                        <Unlink className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  ))}
                  {(!detail.alerts || detail.alerts.length === 0) && (
                    <div className="text-xs font-mono text-muted-foreground py-2">
                      No linked alerts. Use "Link to incident" on any alert to attach.
                    </div>
                  )}
                </div>
              </div>

              {/* Timeline */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2 flex items-center gap-1.5">
                  <Clock className="w-3 h-3" />
                  Timeline · {detail.timeline?.length || 0}
                </div>
                <div className="space-y-2 border-l border-border/60 pl-3 ml-1" data-testid="incident-timeline">
                  {(detail.timeline || []).slice().reverse().map((t, i) => {
                    const Icon = KIND_ICON[t.kind] || Clock;
                    return (
                      <div key={i} className="relative">
                        <span className="absolute -left-[19px] top-1 w-3 h-3 rounded-full bg-card border border-primary/40 flex items-center justify-center">
                          <Icon className="w-2 h-2 text-primary" />
                        </span>
                        <div className="text-[11px] font-mono">
                          <span className="text-muted-foreground">{new Date(t.at).toLocaleString()}</span>
                          {" — "}
                          <span className="text-cyan-300">{t.by}</span>
                          {" — "}
                          <span className="uppercase tracking-widest text-[9px] text-primary">{t.kind}</span>
                        </div>
                        <div className="text-xs mt-0.5">{t.text}</div>
                      </div>
                    );
                  })}
                  {(!detail.timeline || detail.timeline.length === 0) && (
                    <div className="text-xs font-mono text-muted-foreground">No timeline entries yet.</div>
                  )}
                </div>
              </div>

              {/* Evidence */}
              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Evidence events · {detail.evidence_events?.length || 0}
                </div>
                <div className="space-y-1 max-h-64 overflow-auto" data-testid="incident-evidence">
                  {(detail.evidence_events || []).slice(0, 60).map((e) => (
                    <div key={e.event_id} className="text-[11px] font-mono border border-border/40 rounded-sm px-2 py-1">
                      {new Date(e.timestamp).toLocaleString()} · <span className="text-cyan-300">{e.src_ip || "—"}</span> · {e.app}/{e.action || "event"}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* New incident dialog */}
      <Dialog open={newOpen} onOpenChange={setNewOpen}>
        <DialogContent className="bg-card border border-border/60" data-testid="new-incident-dialog">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Open incident
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={createIncident} className="space-y-3">
            <div>
              <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Title</label>
              <Input
                data-testid="new-incident-title"
                value={newForm.title}
                onChange={(e) => setNewForm({ ...newForm, title: e.target.value })}
                placeholder="Short label, e.g. Credential-stuffing wave from Tor"
                className="mt-1.5 font-mono"
                required
              />
            </div>
            <div>
              <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Severity</label>
              <Select value={newForm.severity} onValueChange={(v) => setNewForm({ ...newForm, severity: v })}>
                <SelectTrigger className="mt-1.5 font-mono" data-testid="new-incident-severity"><SelectValue /></SelectTrigger>
                <SelectContent className="bg-popover border border-border">
                  <SelectItem value="Informational">Informational</SelectItem>
                  <SelectItem value="Suspicious">Suspicious</SelectItem>
                  <SelectItem value="Likely malicious">Likely malicious</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Summary</label>
              <Textarea
                value={newForm.summary}
                onChange={(e) => setNewForm({ ...newForm, summary: e.target.value })}
                placeholder="What's the story so far?"
                className="mt-1.5 font-mono text-xs"
                data-testid="new-incident-summary"
              />
            </div>
            <p className="text-[11px] font-mono text-muted-foreground leading-relaxed">
              Alerts can be linked later from an alert's drawer via "Link to incident".
            </p>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setNewOpen(false)} className="font-mono text-xs uppercase tracking-widest">Cancel</Button>
              <Button type="submit" disabled={creating} data-testid="new-incident-submit" className="font-mono text-xs uppercase tracking-widest">
                {creating ? "Opening…" : "Open incident"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
