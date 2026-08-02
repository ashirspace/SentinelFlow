import { useEffect, useState } from "react";
import { PageHeader, SeverityBadge, JsonView } from "@/components/common";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import api, { API_BASE } from "@/lib/api";
import { toast } from "sonner";
import { Search, Download, Check, Tag as TagIcon } from "lucide-react";

export default function Explorer() {
  const [events, setEvents] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("all");
  const [appName, setAppName] = useState("all");
  const [selected, setSelected] = useState(null);
  const [tagInput, setTagInput] = useState("");
  const [noteInput, setNoteInput] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const params = { limit: 200 };
      if (q) params.q = q;
      if (severity !== "all") params.severity = severity;
      if (appName !== "all") params.app_name = appName;
      const { data } = await api.get("/events", { params });
      setEvents(data.events);
      setTotal(data.total);
    } catch (e) {
      toast.error("Failed to fetch events");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [severity, appName]);

  return (
    <div className="pb-16">
      <PageHeader
        title="Log Explorer"
        subtitle="Search and filter normalized events. Click any row to inspect the raw log."
      />

      {/* Filter bar */}
      <div className="px-8 flex flex-wrap items-center gap-3 mb-4">
        <form
          onSubmit={(e) => { e.preventDefault(); load(); }}
          className="flex items-center gap-2 flex-1 min-w-[240px]"
        >
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
            <Input
              data-testid="explorer-search"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search IP, user, host, URL, action…"
              className="pl-9 font-mono"
            />
          </div>
          <Button type="submit" data-testid="explorer-search-btn" className="font-mono uppercase text-xs tracking-widest">
            Search
          </Button>
        </form>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="w-[180px] font-mono text-xs" data-testid="filter-severity">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent className="bg-popover border border-border">
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="Informational">Informational</SelectItem>
            <SelectItem value="Suspicious">Suspicious</SelectItem>
            <SelectItem value="Likely malicious">Likely malicious</SelectItem>
          </SelectContent>
        </Select>
        <Select value={appName} onValueChange={setAppName}>
          <SelectTrigger className="w-[160px] font-mono text-xs" data-testid="filter-app">
            <SelectValue placeholder="App" />
          </SelectTrigger>
          <SelectContent className="bg-popover border border-border">
            <SelectItem value="all">All apps</SelectItem>
            <SelectItem value="auth">auth</SelectItem>
            <SelectItem value="web">web</SelectItem>
            <SelectItem value="linux">linux</SelectItem>
          </SelectContent>
        </Select>
        <div className="text-[11px] font-mono text-muted-foreground uppercase tracking-widest ml-auto" data-testid="events-count">
          {loading ? "loading…" : `${events.length} / ${total} events`}
        </div>
        <Button
          onClick={exportCsv}
          variant="outline"
          data-testid="export-csv-btn"
          className="font-mono text-xs uppercase tracking-widest"
        >
          <Download className="w-3.5 h-3.5 mr-1.5" />
          Export CSV
        </Button>
      </div>

      {/* Table */}
      <div className="px-8">
        <div className="border border-border/60 rounded-md bg-card/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground border-b border-border/60 bg-black/20 sticky top-0">
                <tr>
                  <Th>Timestamp</Th>
                  <Th>Severity</Th>
                  <Th>Src IP</Th>
                  <Th>User</Th>
                  <Th>App</Th>
                  <Th>Action</Th>
                  <Th>Host</Th>
                  <Th>Status</Th>
                </tr>
              </thead>
              <tbody className="font-mono">
                {events.map((e) => (
                  <tr
                    key={e.event_id}
                    onClick={() => openRow(e)}
                    data-testid={`event-row-${e.event_id}`}
                    className="hover-row border-b border-border/40 cursor-pointer"
                  >
                    <Td>{new Date(e.timestamp).toLocaleString()}</Td>
                    <Td><SeverityBadge severity={e.severity} /></Td>
                    <Td className="text-cyan-300">{e.src_ip || "—"}</Td>
                    <Td>{e.user || "—"}</Td>
                    <Td>{e.app || "—"}</Td>
                    <Td>{e.action || "—"}</Td>
                    <Td>{e.host || "—"}</Td>
                    <Td>{e.http_status ?? "—"}</Td>
                    <Td>
                      {e.reviewed && (
                        <span className="inline-flex items-center gap-1 text-emerald-400" title={`Reviewed by ${e.reviewed_by || "?"}`}>
                          <Check className="w-3 h-3" />
                        </span>
                      )}
                      {(e.tags || []).length > 0 && (
                        <span className="inline-flex items-center gap-1 text-cyan-300 ml-2" title={(e.tags || []).join(", ")}>
                          <TagIcon className="w-3 h-3" />
                          {e.tags.length}
                        </span>
                      )}
                    </Td>
                  </tr>
                ))}
                {events.length === 0 && !loading && (
                  <tr>
                    <td colSpan="9" className="text-center text-muted-foreground py-12 font-mono text-xs">
                      No events found. Try adjusting filters or ingesting data.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Right drawer */}
      <Sheet open={!!selected} onOpenChange={(o) => !o && setSelected(null)}>
        <SheetContent
          side="right"
          className="w-full sm:max-w-2xl bg-card border-l border-border/60 overflow-y-auto"
          data-testid="event-drawer"
        >
          <SheetHeader>
            <SheetTitle className="font-mono text-sm uppercase tracking-widest text-muted-foreground">
              Event · {selected?.event_id?.slice(0, 8)}
            </SheetTitle>
          </SheetHeader>
          {selected && (
            <div className="mt-6 space-y-6">
              <div className="grid grid-cols-2 gap-3 text-xs">
                <Field label="Timestamp" value={selected.timestamp} mono />
                <Field label="Severity"><SeverityBadge severity={selected.severity} /></Field>
                <Field label="Src IP" value={selected.src_ip} mono />
                <Field label="Dst IP" value={selected.dst_ip} mono />
                <Field label="User" value={selected.user} mono />
                <Field label="Host" value={selected.host} mono />
                <Field label="App" value={selected.app} mono />
                <Field label="Action" value={selected.action} mono />
                <Field label="URL" value={selected.url} mono />
                <Field label="HTTP Method" value={selected.http_method} mono />
                <Field label="HTTP Status" value={selected.http_status} mono />
                <Field label="Country" value={selected.country} mono />
              </div>

              {/* Annotations */}
              <div className="border-t border-border/60 pt-4 space-y-3" data-testid="event-annotations">
                <div className="flex items-center justify-between">
                  <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                    Analyst annotations
                  </div>
                  <Button
                    size="sm"
                    variant={selected.reviewed ? "default" : "outline"}
                    onClick={toggleReviewed}
                    data-testid="event-reviewed-toggle"
                    className="font-mono text-[10px] uppercase tracking-widest"
                  >
                    <Check className="w-3 h-3 mr-1" />
                    {selected.reviewed ? "Reviewed" : "Mark reviewed"}
                  </Button>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                    Tags (comma-separated)
                  </label>
                  <div className="flex items-center gap-2 mt-1">
                    <Input
                      value={tagInput}
                      onChange={(e) => setTagInput(e.target.value)}
                      placeholder="e.g. tor, scraping, low-priority"
                      className="font-mono text-xs h-8"
                      data-testid="event-tags-input"
                    />
                    <Button size="sm" onClick={saveTags} data-testid="event-tags-save" className="font-mono text-[10px] uppercase tracking-widest">
                      Save
                    </Button>
                  </div>
                </div>
                <div>
                  <label className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                    Add note
                  </label>
                  <Textarea
                    value={noteInput}
                    onChange={(e) => setNoteInput(e.target.value)}
                    placeholder="What did you find?"
                    className="mt-1 font-mono text-xs"
                    data-testid="event-note-input"
                  />
                  <Button size="sm" onClick={addNote} disabled={!noteInput.trim()} data-testid="event-note-save" className="mt-1 font-mono text-[10px] uppercase tracking-widest">
                    Add note
                  </Button>
                </div>
                {(selected.notes || []).length > 0 && (
                  <div className="space-y-1">
                    {selected.notes.map((n, i) => (
                      <div key={i} className="text-[11px] font-mono border border-border/50 rounded-sm px-2 py-1.5">
                        <span className="text-muted-foreground">{new Date(n.at).toLocaleString()}</span> — <span className="text-cyan-300">{n.by}</span> — {n.text}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
                  Raw log
                </div>
                <JsonView value={selected.raw_log} />
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

const Th = ({ children }) => (
  <th className="text-left px-4 py-2.5 font-medium">{children}</th>
);
const Td = ({ children, className = "" }) => (
  <td className={`px-4 py-2.5 whitespace-nowrap ${className}`}>{children}</td>
);

function Field({ label, value, mono, children }) {
  return (
    <div className="border border-border/50 rounded-sm p-2">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
        {label}
      </div>
      <div className={`mt-1 ${mono ? "font-mono" : ""} text-xs break-all`}>
        {children ?? (value ?? "—")}
      </div>
    </div>
  );
}
