import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { Zap, TestTube2, Slack } from "lucide-react";

export default function Notifications() {
  const [prefs, setPrefs] = useState(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);

  const load = async () => {
    const { data } = await api.get("/me/notifications");
    setPrefs(data);
  };
  useEffect(() => { load(); }, []);

  const save = async () => {
    setSaving(true);
    try {
      const { data } = await api.put("/me/notifications", prefs);
      setPrefs(data);
      toast.success("Preferences saved");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  const test = async () => {
    setTesting(true);
    try {
      const { data } = await api.post("/me/notifications/test");
      if (data.result === "sent") toast.success("Test message delivered");
      else toast.error(`Test failed: ${data.result}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Test failed");
    } finally { setTesting(false); }
  };

  if (!prefs) return null;
  const detectedType = /office\.com|webhook\.office|teams\.microsoft/i.test(prefs.webhook_url || "")
    ? "teams" : "slack";

  return (
    <div className="pb-16">
      <PageHeader
        title="Notification preferences"
        subtitle="Send new alerts to your Slack or Microsoft Teams channel via an incoming webhook — separate from the global email pipeline."
      />

      <div className="px-8 max-w-3xl space-y-4">
        <div className="border border-border/60 rounded-md bg-card/40 p-6 space-y-4" data-testid="notifications-form">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {detectedType === "teams" ? <Zap className="w-4 h-4 text-primary" /> : <Slack className="w-4 h-4 text-primary" />}
              <div>
                <div className="text-base font-semibold">Chat webhook</div>
                <div className="text-[11px] font-mono text-muted-foreground">
                  Detected type: <span className="text-cyan-300">{detectedType}</span>
                </div>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Label htmlFor="wh-enabled" className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
                Enabled
              </Label>
              <Switch
                id="wh-enabled"
                checked={!!prefs.webhook_enabled}
                onCheckedChange={(v) => setPrefs({ ...prefs, webhook_enabled: v })}
                data-testid="wh-enabled"
              />
            </div>
          </div>

          <div>
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Webhook URL
            </Label>
            <Input
              value={prefs.webhook_url || ""}
              onChange={(e) => setPrefs({ ...prefs, webhook_url: e.target.value })}
              placeholder="https://hooks.slack.com/services/… OR https://outlook.office.com/webhook/…"
              className="mt-1.5 font-mono text-xs"
              data-testid="wh-url"
            />
            <p className="text-[11px] font-mono text-muted-foreground mt-1 leading-relaxed">
              Slack: create at api.slack.com → Incoming Webhooks. Teams: add an "Incoming Webhook"
              connector to your channel. The URL is a shared secret — anyone with it can post.
            </p>
          </div>

          <div>
            <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
              Minimum severity
            </Label>
            <Select
              value={prefs.webhook_min_severity || "Suspicious"}
              onValueChange={(v) => setPrefs({ ...prefs, webhook_min_severity: v })}
            >
              <SelectTrigger className="mt-1.5 font-mono w-[240px]" data-testid="wh-min-severity">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-popover border border-border">
                <SelectItem value="Informational">Informational (everything)</SelectItem>
                <SelectItem value="Suspicious">Suspicious and above</SelectItem>
                <SelectItem value="Likely malicious">Likely malicious only</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <div className="flex items-center gap-2 pt-2">
            <Button onClick={save} disabled={saving} data-testid="wh-save" className="font-mono text-xs uppercase tracking-widest">
              {saving ? "Saving…" : "Save preferences"}
            </Button>
            <Button
              onClick={test}
              disabled={testing || !prefs.webhook_url}
              variant="outline"
              data-testid="wh-test"
              className="font-mono text-xs uppercase tracking-widest"
            >
              <TestTube2 className="w-3.5 h-3.5 mr-1.5" />
              {testing ? "Sending…" : "Send test"}
            </Button>
          </div>
        </div>

        <div className="text-[11px] font-mono text-muted-foreground border-l-2 border-primary/40 pl-3 leading-relaxed">
          Deduplication: identical alerts (same rule + source + hour) send at most one message per hour.
          Webhook + email pipelines run independently — you can use either or both.
        </div>
      </div>
    </div>
  );
}
