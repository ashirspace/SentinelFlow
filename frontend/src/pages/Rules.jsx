import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader, SeverityBadge } from "@/components/common";
import { Radar } from "lucide-react";

export default function Rules() {
  const [rules, setRules] = useState([]);

  useEffect(() => {
    api.get("/rules").then(({ data }) => setRules(data)).catch(() => {});
  }, []);

  return (
    <div className="pb-16">
      <PageHeader
        title="Detection Rules"
        subtitle="Deterministic rules — no black box. Every alert is explainable and evidence-backed."
      />
      <div className="px-8 grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((r) => (
          <div
            key={r.rule_id}
            data-testid={`rule-card-${r.rule_id}`}
            className="border border-border/60 rounded-md bg-card/40 p-5"
          >
            <div className="flex items-center gap-2 mb-2">
              <Radar className="w-4 h-4 text-primary" />
              <span className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
                {r.rule_id}
              </span>
              <SeverityBadge severity={r.severity} />
            </div>
            <h3 className="text-base font-semibold">{r.name}</h3>
            <p className="mt-2 text-sm text-muted-foreground leading-relaxed">
              {r.condition}
            </p>
            <div className="mt-4 grid grid-cols-2 gap-2 text-[11px] font-mono">
              <div className="border border-border/50 rounded-sm p-2">
                <div className="text-muted-foreground uppercase tracking-widest text-[10px]">
                  Threshold
                </div>
                <div className="mt-0.5">{r.threshold}</div>
              </div>
              <div className="border border-border/50 rounded-sm p-2">
                <div className="text-muted-foreground uppercase tracking-widest text-[10px]">
                  Window
                </div>
                <div className="mt-0.5">
                  {r.window_minutes === 0 ? "instant" : `${r.window_minutes} min`}
                </div>
              </div>
            </div>
            <div className="mt-3 text-[11px] font-mono text-muted-foreground border-l-2 border-primary/40 pl-3">
              {r.template}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
