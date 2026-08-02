import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader, SeverityBadge } from "@/components/common";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";

const STATUSES = ["Open", "Investigating", "Closed"];
const STATUS_CLS = {
  Open: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  Investigating: "bg-indigo-500/10 text-indigo-400 border-indigo-500/25",
  Closed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
};

export default function Incidents() {
  const [items, setItems] = useState([]);
  const [detail, setDetail] = useState(null);
  const [status, setStatus] = useState("");
  const [note, setNote] = useState("");

  const load = async () => {
    const { data } = await api.get("/incidents");
    setItems(data);
  };
  useEffect(() => { load(); }, []);

  const open = async (id) => {
    const { data } = await api.get(`/incidents/${id}`);
    setDetail(data);
    setStatus(data.status);
    setNote("");
  };

  const save = async () => {
    if (!detail) return;
    try {
      await api.patch(`/incidents/${detail.id}`, { status, note });
      toast.success("Incident updated");
      await load();
      await open(detail.id);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    }
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Incidents"
        subtitle="Escalated alerts grouped for investigation. Every incident carries its originating alerts and evidence events."
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
              <div className="flex items-center gap-2">
                <SeverityBadge severity={detail.severity} />
                <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] uppercase tracking-widest border ${STATUS_CLS[detail.status]}`}>
                  {detail.status}
                </span>
                <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                  opened {new Date(detail.opened_at).toLocaleString()}
                </span>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">Summary</div>
                <div className="text-sm leading-relaxed">{detail.summary}</div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Linked alerts · {detail.alerts?.length || 0}
                </div>
                <div className="space-y-2">
                  {(detail.alerts || []).map((a) => (
                    <div key={a.id} className="border border-border/60 rounded-sm p-2">
                      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                        {a.rule_id} · {a.severity}
                      </div>
                      <div className="text-xs mt-1">{a.explanation}</div>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Evidence events · {detail.evidence_events?.length || 0}
                </div>
                <div className="space-y-1 max-h-64 overflow-auto">
                  {(detail.evidence_events || []).slice(0, 40).map((e) => (
                    <div key={e.event_id} className="text-[11px] font-mono border border-border/40 rounded-sm px-2 py-1">
                      {new Date(e.timestamp).toLocaleString()} · <span className="text-cyan-300">{e.src_ip || "—"}</span> · {e.app}/{e.action || "event"}
                    </div>
                  ))}
                </div>
              </div>

              <div className="border-t border-border/60 pt-5 space-y-3">
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">Update</div>
                <Select value={status} onValueChange={setStatus}>
                  <SelectTrigger className="w-[220px] font-mono text-xs" data-testid="incident-status-select"><SelectValue /></SelectTrigger>
                  <SelectContent className="bg-popover border border-border">
                    {STATUSES.map((s) => (<SelectItem key={s} value={s}>{s}</SelectItem>))}
                  </SelectContent>
                </Select>
                <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="Add a note…" className="font-mono text-xs" data-testid="incident-note" />
                <Button onClick={save} data-testid="incident-save" className="font-mono text-xs uppercase tracking-widest">Save</Button>
              </div>

              {detail.notes?.length > 0 && (
                <div>
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">Notes</div>
                  <div className="space-y-1.5">
                    {detail.notes.map((n, i) => (
                      <div key={i} className="text-[11px] font-mono border border-border/50 rounded-sm px-2 py-1.5">
                        <span className="text-muted-foreground">{new Date(n.at).toLocaleString()}</span> — <span className="text-cyan-300">{n.by}</span> — {n.text}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
