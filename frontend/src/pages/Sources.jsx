import { useEffect, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Server, Pause, Play, KeyRound, Trash2, Copy, Plus, ShieldOff, Radio } from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/context/AuthContext";
import IngestSnippets from "@/components/IngestSnippets";

const HEALTH = {
  healthy: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
  delayed: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  silent: "bg-red-500/10 text-red-400 border-red-500/25",
};

export default function Sources() {
  useDocumentTitle("Sources · SentinelFlow");
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [sources, setSources] = useState([]);
  const [busy, setBusy] = useState("");
  const [editing, setEditing] = useState(null);
  const [retention, setRetention] = useState(72);
  const [reveal, setReveal] = useState(null);       // {name, key} — shown ONCE
  const [ingestCfg, setIngestCfg] = useState(null); // {endpoint, ...}
  const [newOpen, setNewOpen] = useState(false);
  const [newSrc, setNewSrc] = useState({ name: "", type: "web", description: "" });
  const [creating, setCreating] = useState(false);

  const load = async () => {
    const [{ data }, { data: cfg }] = await Promise.all([
      api.get("/sources"),
      api.get("/ingest/config"),
    ]);
    setSources(data);
    setIngestCfg(cfg);
  };
  useEffect(() => {
    load();
    const id = setInterval(load, 15000);
    return () => clearInterval(id);
  }, []);

  const createSource = async (e) => {
    e.preventDefault();
    if (!newSrc.name.trim()) return;
    setCreating(true);
    try {
      const { data } = await api.post("/sources", newSrc);
      setNewOpen(false);
      setNewSrc({ name: "", type: "web", description: "" });
      setReveal({ name: data.name, key: data.ingest_api_key });
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Create failed");
    } finally {
      setCreating(false);
    }
  };

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
    if (!confirm(`Rotate the ingest key for "${name}"? The previous key stops working immediately.`)) return;
    setBusy(name);
    try {
      const { data } = await api.post(`/sources/${name}/rotate-key`);
      setReveal({ name, key: data.ingest_api_key });
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed");
    } finally {
      setBusy("");
    }
  };

  const revoke = async (name) => {
    if (!confirm(`Revoke the ingest key for "${name}"? Ingestion will stop until you rotate a new one.`)) return;
    setBusy(name);
    try {
      await api.post(`/sources/${name}/revoke-key`);
      toast.success("Key revoked");
      await load();
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
        right={
          isAdmin && (
            <Button
              onClick={() => setNewOpen(true)}
              data-testid="new-source-btn"
              className="font-mono text-xs uppercase tracking-widest"
            >
              <Plus className="w-3.5 h-3.5 mr-1.5" />
              Add source
            </Button>
          )
        }
      />

      {/* Ingest endpoint info */}
      {ingestCfg && (
        <div className="px-8 mb-4">
          <div className="border border-border/60 rounded-md bg-card/40 p-4 flex items-start gap-3" data-testid="ingest-endpoint-card">
            <Radio className="w-4 h-4 text-primary mt-0.5" />
            <div className="flex-1 min-w-0">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                Push-only ingest endpoint
              </div>
              <code className="block mt-1 font-mono text-xs break-all text-cyan-300">{ingestCfg.endpoint}</code>
              <div className="mt-1 text-[11px] font-mono text-muted-foreground">
                {ingestCfg.rate_limit_per_min} req/min · {ingestCfg.max_events_per_request} events/req · {Math.round(ingestCfg.max_body_bytes / 1000)} KB max · Bearer sfk_...
              </div>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => { navigator.clipboard.writeText(ingestCfg.endpoint); toast.success("Copied"); }}
              data-testid="copy-endpoint-btn"
              className="font-mono text-[10px] uppercase tracking-widest"
            >
              <Copy className="w-3 h-3 mr-1" />
              Copy
            </Button>
          </div>
        </div>
      )}

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
                    <div className="text-[10px] text-muted-foreground mt-0.5 space-x-2">
                      {s.description && <span>{s.description}</span>}
                      {s.ingest_api_key_hint
                        ? <span className="font-mono text-cyan-300">key: {s.ingest_api_key_hint}</span>
                        : <span className="text-amber-400 uppercase tracking-widest">no key — rotate to create</span>}
                    </div>
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
                          {s.ingest_api_key_hint && (
                            <IconBtn testid={`revoke-${s.name}`} title="Revoke ingest key" tone="warning" onClick={() => revoke(s.name)} disabled={busy === s.name}>
                              <ShieldOff className="w-3.5 h-3.5" />
                            </IconBtn>
                          )}
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

      {/* Rotated/created key reveal dialog */}
      <Dialog open={!!reveal} onOpenChange={(o) => !o && setReveal(null)}>
        <DialogContent className="bg-card border border-border/60 max-w-2xl max-h-[90vh] overflow-y-auto" data-testid="reveal-dialog">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Connect · {reveal?.name}
            </DialogTitle>
          </DialogHeader>
          {reveal && ingestCfg && (
            <IngestSnippets
              ingestEndpoint={ingestCfg.endpoint}
              apiKey={reveal.key}
              sourceName={reveal.name}
            />
          )}
          <DialogFooter>
            <Button onClick={() => setReveal(null)} data-testid="reveal-done" className="font-mono text-xs uppercase tracking-widest">
              I've saved the key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add source dialog */}
      <Dialog open={newOpen} onOpenChange={setNewOpen}>
        <DialogContent className="bg-card border border-border/60" data-testid="new-source-dialog">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              New log source
            </DialogTitle>
          </DialogHeader>
          <form onSubmit={createSource} className="space-y-3">
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Name</Label>
              <Input
                data-testid="new-source-name"
                value={newSrc.name}
                onChange={(e) => setNewSrc({ ...newSrc, name: e.target.value })}
                placeholder="e.g. www-prod-nginx"
                className="mt-1.5 font-mono"
                required
              />
            </div>
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Type</Label>
              <Select value={newSrc.type} onValueChange={(v) => setNewSrc({ ...newSrc, type: v })}>
                <SelectTrigger className="mt-1.5 font-mono" data-testid="new-source-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-popover border border-border">
                  <SelectItem value="web">web</SelectItem>
                  <SelectItem value="akamai">akamai</SelectItem>
                  <SelectItem value="auth">auth</SelectItem>
                  <SelectItem value="os">os</SelectItem>
                  <SelectItem value="db">db</SelectItem>
                  <SelectItem value="api">api</SelectItem>
                  <SelectItem value="network">network</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Description</Label>
              <Input
                data-testid="new-source-desc"
                value={newSrc.description}
                onChange={(e) => setNewSrc({ ...newSrc, description: e.target.value })}
                placeholder="Optional"
                className="mt-1.5"
              />
            </div>
            <p className="text-[11px] font-mono text-muted-foreground leading-relaxed">
              An API key limited to this source will be generated. It grants
              write-only access to the ingest endpoint — no reads, no config,
              nothing else.
            </p>
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setNewOpen(false)} className="font-mono text-xs uppercase tracking-widest">
                Cancel
              </Button>
              <Button type="submit" disabled={creating} data-testid="new-source-submit" className="font-mono text-xs uppercase tracking-widest">
                {creating ? "Creating…" : "Create & get key"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function IconBtn({ children, tone, ...rest }) {
  const toneCls = tone === "danger"
    ? "text-red-400 hover:text-red-300"
    : tone === "warning"
      ? "text-amber-400 hover:text-amber-300"
      : "text-muted-foreground hover:text-foreground";
  return (
    <button
      data-testid={rest.testid}
      title={rest.title}
      onClick={rest.onClick}
      disabled={rest.disabled}
      className={`p-1.5 rounded-sm border border-border/60 hover:bg-white/5 ${toneCls}`}
      style={{ transition: "background-color 0.15s ease, color 0.15s ease" }}
    >
      {children}
    </button>
  );
}
