import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Server, Pause, Play, KeyRound, Trash2, Copy } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";

const HEALTH = {
  healthy: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
  delayed: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  silent: "bg-red-500/10 text-red-400 border-red-500/25",
};

export default function Sources() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [sources, setSources] = useState([]);
  const [busy, setBusy] = useState("");
  const [editing, setEditing] = useState(null);
  const [retention, setRetention] = useState(72);
  const [rotated, setRotated] = useState(null);

  const load = async () => {
    const { data } = await api.get("/sources");
    setSources(data);
  };
  useEffect(() => { load(); }, []);

  const patch = async (name, body) => {
    setBusy(name);
    try {
      await api.patch(`/sources/${name}`, body);
      toast.success("Updated");
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setBusy("");
    }
  };

  const rotate = async (name) => {
    setBusy(name);
    try {
      const { data } = await api.post(`/sources/${name}/rotate-key`);
      setRotated({ name, key: data.ingest_api_key });
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setBusy("");
    }
  };

  const del = async (name) => {
    if (!confirm(`Delete source "${name}"? Events remain unless you also purge them.`)) return;
    const purge = confirm(`Also purge all events and raw logs from "${name}"? (Cancel keeps them for retention.)`);
    setBusy(name);
    try {
      await api.delete(`/sources/${name}?purge_events=${purge}`);
      toast.success("Deleted");
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setBusy("");
    }
  };

  const openEdit = (s) => {
    setEditing(s);
    setRetention(s.retention_hours || 72);
  };
  const saveRetention = async () => {
    const val = Math.max(1, Math.min(72, Number(retention) || 72));
    await patch(editing.name, { retention_hours: val });
    setEditing(null);
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Log Sources"
        subtitle="Every connected source, its ingestion health, and per-source retention (≤ 72h)."
      />

      <div className="px-8">
        <div className="border border-border/60 rounded-md bg-card/40 overflow-hidden">
          <table className="w-full text-xs" data-testid="sources-table">
            <thead className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground border-b border-border/60 bg-black/20">
              <tr>
                <th className="text-left px-4 py-2.5">Name</th>
                <th className="text-left px-4 py-2.5">Type</th>
                <th className="text-left px-4 py-2.5">Health</th>
                <th className="text-left px-4 py-2.5">Last event</th>
                <th className="text-left px-4 py-2.5">Retention</th>
                <th className="text-left px-4 py-2.5">State</th>
                <th className="text-right px-4 py-2.5">Actions</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {sources.map((s) => (
                <tr key={s.name} className="border-b border-border/40" data-testid={`source-row-${s.name}`}>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <Server className="w-3.5 h-3.5 text-primary" />
                      <span className="font-medium">{s.name}</span>
                    </div>
                    {s.description && (
                      <div className="text-[10px] text-muted-foreground mt-0.5">{s.description}</div>
                    )}
                  </td>
                  <td className="px-4 py-3 uppercase tracking-widest text-[10px] text-muted-foreground">
                    {s.type}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] uppercase tracking-widest border ${HEALTH[s.health] || HEALTH.silent}`}>
                      {s.health}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : "never"}
                  </td>
                  <td className="px-4 py-3">{s.retention_hours || 72}h</td>
                  <td className="px-4 py-3">
                    {s.paused
                      ? <span className="text-amber-400 uppercase tracking-widest text-[10px]">paused</span>
                      : <span className="text-emerald-400 uppercase tracking-widest text-[10px]">active</span>}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      {isAdmin && (
                        <>
                          <IconBtn
                            testid={`pause-${s.name}`}
                            title={s.paused ? "Resume" : "Pause"}
                            onClick={() => patch(s.name, { paused: !s.paused })}
                            disabled={busy === s.name}
                          >
                            {s.paused ? <Play className="w-3.5 h-3.5" /> : <Pause className="w-3.5 h-3.5" />}
                          </IconBtn>
                          <IconBtn testid={`retention-${s.name}`} title="Retention" onClick={() => openEdit(s)}>
                            <span className="text-[10px] font-mono px-1">{s.retention_hours || 72}h</span>
                          </IconBtn>
                          <IconBtn testid={`rotate-${s.name}`} title="Rotate ingest key" onClick={() => rotate(s.name)} disabled={busy === s.name}>
                            <KeyRound className="w-3.5 h-3.5" />
                          </IconBtn>
                          <IconBtn testid={`delete-${s.name}`} title="Delete" tone="danger" onClick={() => del(s.name)} disabled={busy === s.name}>
                            <Trash2 className="w-3.5 h-3.5" />
                          </IconBtn>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {sources.length === 0 && (
                <tr><td colSpan="7" className="text-center text-muted-foreground py-12 text-xs">No sources yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Retention edit dialog */}
      <Dialog open={!!editing} onOpenChange={(o) => !o && setEditing(null)}>
        <DialogContent className="bg-card border border-border/60">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Retention · {editing?.name}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Raw log retention (hours) — 1 to 72
            </Label>
            <Input
              type="number" min={1} max={72}
              value={retention}
              onChange={(e) => setRetention(e.target.value)}
              className="font-mono"
              data-testid="retention-input"
            />
            <p className="text-[11px] font-mono text-muted-foreground leading-relaxed">
              Normalized events and alert evidence keep their own longer retention — this
              only affects the raw log copy for this source.
            </p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setEditing(null)} className="font-mono text-xs uppercase tracking-widest">Cancel</Button>
            <Button onClick={saveRetention} data-testid="retention-save" className="font-mono text-xs uppercase tracking-widest">Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotated key dialog */}
      <Dialog open={!!rotated} onOpenChange={(o) => !o && setRotated(null)}>
        <DialogContent className="bg-card border border-border/60">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              New ingest key · {rotated?.name}
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <p className="text-xs text-muted-foreground leading-relaxed">
              Copy the key now. It won't be shown again.
            </p>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-xs bg-black/40 border border-border/60 rounded-sm p-3 break-all" data-testid="rotated-key">
                {rotated?.key}
              </code>
              <Button
                size="icon"
                variant="outline"
                onClick={() => { navigator.clipboard.writeText(rotated?.key || ""); toast.success("Copied"); }}
                data-testid="copy-key"
              >
                <Copy className="w-4 h-4" />
              </Button>
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => setRotated(null)} className="font-mono text-xs uppercase tracking-widest">Done</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function IconBtn({ children, tone, ...rest }) {
  return (
    <button
      data-testid={rest.testid}
      title={rest.title}
      onClick={rest.onClick}
      disabled={rest.disabled}
      className={`p-1.5 rounded-sm border border-border/60 hover:bg-white/5 ${tone === "danger" ? "text-red-400 hover:text-red-300" : "text-muted-foreground hover:text-foreground"}`}
      style={{ transition: "background-color 0.15s ease, color 0.15s ease" }}
    >
      {children}
    </button>
  );
}
