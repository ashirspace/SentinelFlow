export function SeverityBadge({ severity }) {
  const map = {
    "Likely malicious": "severity-critical",
    "Suspicious": "severity-suspicious",
    "Informational": "severity-info",
  };
  const cls = map[severity] || "severity-info";
  return (
    <span
      data-testid={`severity-${(severity || "info").toLowerCase().replace(/\s+/g, "-")}`}
      className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-mono uppercase tracking-widest ${cls}`}
    >
      {severity || "Informational"}
    </span>
  );
}

const STATUS_STYLES = {
  New: "bg-cyan-500/10 text-cyan-400 border-cyan-500/25",
  "Under Review": "bg-indigo-500/10 text-indigo-400 border-indigo-500/25",
  Investigating: "bg-amber-500/10 text-amber-400 border-amber-500/25",
  Confirmed: "bg-red-500/10 text-red-400 border-red-500/25",
  "False Positive": "bg-zinc-500/10 text-zinc-400 border-zinc-500/25",
  Resolved: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25",
};

export function StatusBadge({ status }) {
  const cls = STATUS_STYLES[status] || "bg-zinc-500/10 text-zinc-400";
  return (
    <span
      data-testid={`status-${(status || "new").toLowerCase().replace(/\s+/g, "-")}`}
      className={`inline-flex items-center px-2 py-0.5 rounded-sm text-[10px] font-mono uppercase tracking-widest border ${cls}`}
    >
      {status}
    </span>
  );
}

export function JsonView({ value }) {
  const highlight = (json) => {
    const str = JSON.stringify(json, null, 2);
    return str.replace(
      /("(\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
      (m) => {
        let cls = "json-number";
        if (/^"/.test(m)) cls = /:$/.test(m) ? "json-key" : "json-string";
        else if (/true|false/.test(m)) cls = "json-bool";
        else if (/null/.test(m)) cls = "json-null";
        return `<span class="${cls}">${m}</span>`;
      }
    );
  };
  return (
    <pre
      className="text-[11px] font-mono leading-relaxed p-3 rounded-md bg-black/50 border border-border/60 overflow-auto"
      dangerouslySetInnerHTML={{ __html: highlight(value) }}
    />
  );
}

export function PageHeader({ title, subtitle, right }) {
  return (
    <div className="px-8 pt-8 pb-4 flex items-start justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight" data-testid="page-title">
          {title}
        </h1>
        {subtitle && (
          <p className="mt-1 text-sm text-muted-foreground">{subtitle}</p>
        )}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}
