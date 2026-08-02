import { useState } from "react";
import { Copy, Check as CheckIcon, Terminal, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { toast } from "sonner";

/**
 * Reveals a freshly-created or rotated ingest API key exactly once, along
 * with ready-to-paste snippets for common log shippers.
 *
 * Props:
 *   ingestEndpoint: full URL of POST /api/v1/ingest
 *   apiKey:         plaintext key (shown once)
 *   sourceName:     display + used in agent config comments
 */
export default function IngestSnippets({ ingestEndpoint, apiKey, sourceName }) {
  const [copied, setCopied] = useState("");

  const copy = (label, text) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    toast.success(`${label} copied`);
    setTimeout(() => setCopied(""), 1500);
  };

  const curlSnippet =
`curl -X POST "${ingestEndpoint}" \\
  -H "Authorization: Bearer ${apiKey}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "events": [
      { "timestamp": "2026-01-01T12:00:00Z",
        "app": "web", "src_ip": "1.2.3.4",
        "user": "alice", "http_method": "GET",
        "url": "/dashboard", "http_status": 200 }
    ]
  }'`;

  const fluentBit =
`# fluent-bit.conf — send existing logs to SentinelFlow (${sourceName})
[OUTPUT]
    Name              http
    Match             *
    Host              ${new URL(ingestEndpoint).host}
    Port              443
    URI               /api/v1/ingest
    tls               On
    Format            json
    Header            Authorization Bearer ${apiKey}
    Retry_Limit       3
    json_date_key     timestamp
    json_date_format  iso8601`;

  const vector =
`# vector.toml — forward logs to SentinelFlow (${sourceName})
[sinks.sentinelflow]
type = "http"
inputs = ["your_source_id"]
uri = "${ingestEndpoint}"
encoding.codec = "json"
request.headers.Authorization = "Bearer ${apiKey}"
request.headers.Content-Type = "application/json"
framing.method = "newline_delimited"
batch.max_events = 500`;

  const nodeMiddleware =
`// One-line log shipper for any Node/Express app
async function shipToSentinelFlow(event) {
  await fetch("${ingestEndpoint}", {
    method: "POST",
    headers: {
      "Authorization": "Bearer ${apiKey}",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ events: [event] }),
  });
}`;

  return (
    <div className="space-y-4">
      <div className="border border-amber-500/30 bg-amber-500/5 rounded-sm p-3">
        <div className="text-[10px] font-mono uppercase tracking-widest text-amber-400 mb-1">
          One-time reveal
        </div>
        <p className="text-xs text-muted-foreground leading-relaxed">
          This key is shown once. Copy it now — SentinelFlow only stores a hash and
          cannot recover it later. If you lose it, rotate to generate a new one.
        </p>
      </div>

      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">
          Ingest endpoint
        </div>
        <CopyRow label="Endpoint" value={ingestEndpoint} copied={copied} onCopy={copy} testid="copy-endpoint" />
      </div>
      <div>
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1.5">
          API key ({sourceName})
        </div>
        <CopyRow label="API key" value={apiKey} copied={copied} onCopy={copy} testid="copy-api-key" />
      </div>

      <Tabs defaultValue="curl" className="w-full">
        <TabsList className="grid grid-cols-4 w-full bg-secondary">
          <TabsTrigger value="curl" data-testid="snippet-tab-curl" className="font-mono text-[10px] uppercase tracking-widest">
            <Terminal className="w-3 h-3 mr-1.5" /> curl
          </TabsTrigger>
          <TabsTrigger value="fluent" data-testid="snippet-tab-fluent" className="font-mono text-[10px] uppercase tracking-widest">
            Fluent Bit
          </TabsTrigger>
          <TabsTrigger value="vector" data-testid="snippet-tab-vector" className="font-mono text-[10px] uppercase tracking-widest">
            Vector
          </TabsTrigger>
          <TabsTrigger value="node" data-testid="snippet-tab-node" className="font-mono text-[10px] uppercase tracking-widest">
            Node
          </TabsTrigger>
        </TabsList>
        <SnippetTab value="curl" code={curlSnippet} label="curl one-liner" copied={copied} onCopy={copy} />
        <SnippetTab value="fluent" code={fluentBit} label="fluent-bit.conf" copied={copied} onCopy={copy} />
        <SnippetTab value="vector" code={vector} label="vector.toml" copied={copied} onCopy={copy} />
        <SnippetTab value="node" code={nodeMiddleware} label="Node middleware" copied={copied} onCopy={copy} />
      </Tabs>

      <div className="text-[11px] font-mono text-muted-foreground border-l-2 border-primary/40 pl-3 leading-relaxed">
        Push-only: the site sends outbound HTTPS to SentinelFlow. SentinelFlow never
        connects into your site and cannot read anything else with this key.
        Rate limit: 60 requests/min · max 1000 events/req · max 1&nbsp;MB body.
      </div>
    </div>
  );
}

function CopyRow({ label, value, onCopy, copied, testid }) {
  return (
    <div className="flex items-center gap-2">
      <code className="flex-1 font-mono text-[11px] bg-black/40 border border-border/60 rounded-sm p-2.5 break-all" data-testid={testid ? `${testid}-value` : undefined}>
        {value}
      </code>
      <Button
        size="icon"
        variant="outline"
        onClick={() => onCopy(label, value)}
        data-testid={testid}
        title={`Copy ${label}`}
      >
        {copied === label ? <CheckIcon className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
      </Button>
    </div>
  );
}

function SnippetTab({ value, code, label, copied, onCopy }) {
  return (
    <TabsContent value={value} className="mt-3">
      <div className="relative">
        <pre className="text-[11px] font-mono leading-relaxed p-3 rounded-md bg-black/50 border border-border/60 overflow-auto max-h-72" data-testid={`snippet-${value}`}>
{code}
        </pre>
        <button
          onClick={() => onCopy(label, code)}
          data-testid={`snippet-copy-${value}`}
          className="absolute top-2 right-2 p-1.5 rounded-sm bg-card/80 border border-border/60 text-muted-foreground hover:text-foreground hover:bg-card"
          style={{ transition: "color 0.15s ease, background-color 0.15s ease" }}
          title={`Copy ${label}`}
        >
          {copied === label ? <CheckIcon className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
        </button>
      </div>
    </TabsContent>
  );
}

export function DocsLink() {
  return (
    <a
      href="https://docs.fluentbit.io/manual/pipeline/outputs/http"
      target="_blank" rel="noreferrer"
      className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
    >
      Fluent Bit HTTP docs <ExternalLink className="w-3 h-3" />
    </a>
  );
}
