import { useEffect, useRef, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { UploadCloud, Server, Terminal } from "lucide-react";
import { toast } from "sonner";

export default function Ingest() {
  useDocumentTitle("Ingest · SentinelFlow");
  const [sources, setSources] = useState([]);
  const [selectedSource, setSelectedSource] = useState("");
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [syslogText, setSyslogText] = useState("");
  const [syslogBusy, setSyslogBusy] = useState(false);
  const fileRef = useRef(null);

  const load = async () => {
    const { data } = await api.get("/sources");
    setSources(data);
    if (!selectedSource && data.length) setSelectedSource(data[0].name);
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const upload = async (e) => {
    e.preventDefault();
    if (!file || !selectedSource) {
      toast.error("Select a source and a file");
      return;
    }
    setUploading(true);
    try {
      const form = new FormData();
      form.append("file", file);
      const { data } = await api.post(
        `/ingest?source_name=${encodeURIComponent(selectedSource)}`,
        form,
        { headers: { "Content-Type": "multipart/form-data" } }
      );
      toast.success(`Ingested ${data.ingested} events · ${data.alerts} alerts triggered`);
      setFile(null);
      if (fileRef.current) fileRef.current.value = "";
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Upload failed");
    } finally {
      setUploading(false);
    }
  };

  const submitSyslog = async (e) => {
    e.preventDefault();
    if (!selectedSource || !syslogText.trim()) {
      toast.error("Pick a source and paste syslog lines");
      return;
    }
    setSyslogBusy(true);
    try {
      const { data } = await api.post("/ingest/syslog", {
        source_name: selectedSource,
        text: syslogText,
      });
      toast.success(`Parsed ${data.ingested} syslog lines · ${data.alerts} alerts`);
      setSyslogText("");
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Syslog ingest failed");
    } finally {
      setSyslogBusy(false);
    }
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Log Ingestion (batch)"
        subtitle="One-time batch upload for JSON, NDJSON, CSV, or Syslog files. For live streaming from a website, create a source under Log Sources and use the push endpoint."
      />

      <div className="px-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload */}
        <div className="border border-border/60 rounded-md bg-card/40 p-6" data-testid="ingest-panel">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
            /// Ingest logs
          </div>
          <h2 className="text-base font-semibold mb-4">New batch</h2>

          <div className="mb-4">
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Source
            </Label>
            <Select value={selectedSource} onValueChange={setSelectedSource}>
              <SelectTrigger className="mt-1.5 font-mono" data-testid="ingest-source-select">
                <SelectValue placeholder="Select a source" />
              </SelectTrigger>
              <SelectContent className="bg-popover border border-border">
                {sources.map((s) => (
                  <SelectItem key={s.name} value={s.name}>{s.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Tabs defaultValue="file" className="w-full">
            <TabsList className="grid grid-cols-2 w-full bg-secondary">
              <TabsTrigger value="file" data-testid="tab-file" className="font-mono text-xs uppercase tracking-widest">
                File upload
              </TabsTrigger>
              <TabsTrigger value="syslog" data-testid="tab-syslog" className="font-mono text-xs uppercase tracking-widest">
                Paste syslog
              </TabsTrigger>
            </TabsList>

            <TabsContent value="file">
              <form onSubmit={upload} className="space-y-4 mt-4" data-testid="ingest-form">
                <div>
                  <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
                    File (.json, .ndjson, .csv, .log/.syslog)
                  </Label>
                  <label className="mt-1.5 block border border-dashed border-border rounded-md p-6 text-center cursor-pointer hover:bg-white/[0.03]" style={{ transition: "background-color 0.15s ease" }}>
                    <input
                      ref={fileRef}
                      data-testid="ingest-file-input"
                      type="file"
                      className="hidden"
                      accept=".json,.ndjson,.csv,.log,.syslog,.txt"
                      onChange={(e) => setFile(e.target.files?.[0] || null)}
                    />
                    <UploadCloud className="w-6 h-6 mx-auto text-muted-foreground" />
                    <div className="mt-2 text-xs font-mono">
                      {file ? file.name : "Click to choose a file"}
                    </div>
                  </label>
                </div>
                <Button
                  type="submit"
                  disabled={uploading || !file || !selectedSource}
                  data-testid="ingest-submit"
                  className="w-full font-mono text-xs uppercase tracking-widest"
                >
                  {uploading ? "Uploading…" : "Ingest & detect"}
                </Button>
              </form>
            </TabsContent>

            <TabsContent value="syslog">
              <form onSubmit={submitSyslog} className="space-y-4 mt-4" data-testid="syslog-form">
                <div>
                  <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground flex items-center gap-1.5">
                    <Terminal className="w-3 h-3" />
                    Syslog lines (RFC-5424 or RFC-3164)
                  </Label>
                  <Textarea
                    data-testid="syslog-textarea"
                    value={syslogText}
                    onChange={(e) => setSyslogText(e.target.value)}
                    placeholder={`<38>1 2026-02-02T18:00:00Z auth-01 sshd 1234 ID47 - Failed password user=eve src_ip=45.155.205.233\n<34>Aug  2 18:05:12 auth-01 sshd[9821]: Failed password for admin from 203.0.113.99 port 55432`}
                    className="mt-1.5 font-mono text-[11px] min-h-[160px]"
                  />
                </div>
                <Button
                  type="submit"
                  disabled={syslogBusy || !syslogText.trim() || !selectedSource}
                  data-testid="syslog-submit"
                  className="w-full font-mono text-xs uppercase tracking-widest"
                >
                  {syslogBusy ? "Parsing…" : "Parse & detect"}
                </Button>
              </form>
            </TabsContent>
          </Tabs>

          <div className="mt-6 border-t border-border/60 pt-4">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
              Supported field aliases
            </div>
            <div className="text-[11px] font-mono text-muted-foreground leading-relaxed">
              ip / source_ip / client_ip → src_ip · username / userid → user ·
              status / code → http_status · time / ts / @timestamp → timestamp ·
              method → http_method · path / uri → url · user-agent / ua → user_agent
            </div>
          </div>
        </div>

        {/* Sources */}
        <div>
          <div className="border border-border/60 rounded-md bg-card/40 p-6" data-testid="sources-list">
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-2">
              /// Registered sources
            </div>
            <p className="text-[11px] font-mono text-muted-foreground mb-3 leading-relaxed">
              Create and manage sources on the <a href="/sources" className="text-primary hover:underline">Log Sources</a> page.
            </p>
            <div className="space-y-2">
              {sources.length === 0 && (
                <div className="text-xs font-mono text-muted-foreground">No sources yet.</div>
              )}
              {sources.map((s) => (
                <div key={s.name} className="border border-border/60 rounded-sm px-3 py-2 flex items-start gap-3">
                  <Server className="w-4 h-4 mt-0.5 text-primary" />
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium">{s.name}</div>
                    <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                      {s.type} · last event {s.last_event_at ? new Date(s.last_event_at).toLocaleString() : "never"}
                    </div>
                    {s.description && (
                      <div className="text-xs text-muted-foreground mt-1">{s.description}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
