import { useEffect, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";

export default function Audit() {
  useDocumentTitle("Audit · SentinelFlow");
  const [logs, setLogs] = useState([]);
  useEffect(() => {
    api.get("/audit").then(({ data }) => setLogs(data)).catch(() => {});
  }, []);

  return (
    <div className="pb-16">
      <PageHeader
        title="Audit Log"
        subtitle="Immutable record of every action — logins, alert triage, user changes, ingestions."
      />
      <div className="px-8">
        <div className="border border-border/60 rounded-md bg-card/40 overflow-hidden">
          <table className="w-full text-xs" data-testid="audit-table">
            <thead className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground border-b border-border/60 bg-black/20">
              <tr>
                <th className="text-left px-4 py-2.5">When</th>
                <th className="text-left px-4 py-2.5">Actor</th>
                <th className="text-left px-4 py-2.5">Action</th>
                <th className="text-left px-4 py-2.5">Target</th>
                <th className="text-left px-4 py-2.5">Meta</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {logs.map((l) => (
                <tr key={l.id} className="border-b border-border/40" data-testid={`audit-row-${l.id}`}>
                  <td className="px-4 py-3 text-muted-foreground whitespace-nowrap">
                    {new Date(l.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-3 text-cyan-300">{l.actor}</td>
                  <td className="px-4 py-3">
                    <span className="px-2 py-0.5 text-[10px] uppercase tracking-widest rounded-sm border border-primary/25 bg-primary/10 text-primary">
                      {l.action}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{l.target || "—"}</td>
                  <td className="px-4 py-3 text-muted-foreground text-[11px]">
                    {l.meta && Object.keys(l.meta).length ? JSON.stringify(l.meta) : "—"}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && (
                <tr>
                  <td colSpan="5" className="text-center text-muted-foreground py-12 text-xs">
                    No audit entries yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
