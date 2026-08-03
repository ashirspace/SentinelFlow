import { useEffect, useState } from "react";
import useDocumentTitle from "@/hooks/useDocumentTitle";
import { useNavigate, useLocation } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/context/AuthContext";
import { formatApiError } from "@/lib/api";

export default function Login() {
  useDocumentTitle("Sign in · SentinelFlow");
  const { login, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("admin@sentinelflow.io");
  const [password, setPassword] = useState("Admin@12345");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (user && typeof user === "object") {
      const dest = location.state?.from?.pathname || "/dashboard";
      navigate(dest, { replace: true });
    }
  }, [user, location, navigate]);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      await login(email, password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      setError(formatApiError(err.response?.data?.detail) || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex bg-background text-foreground">
      {/* Left: marketing/context panel */}
      <div className="hidden lg:flex flex-col justify-between w-1/2 p-12 bg-card/40 border-r border-border/60 bg-grid">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-primary critical-glow" />
          <span className="text-lg font-semibold tracking-tight">SentinelFlow</span>
        </div>
        <div className="max-w-md">
          <p className="text-[11px] font-mono uppercase tracking-widest text-primary/80 mb-4">
            /// Explainable SIEM
          </p>
          <h2 className="text-4xl font-semibold tracking-tight leading-tight">
            Every alert cites the log line.<br />
            <span className="text-muted-foreground">Never an unverified accusation.</span>
          </h2>
          <p className="mt-6 text-sm text-muted-foreground leading-relaxed">
            Ingest, normalize, and correlate security logs across your fleet.
            Six deterministic detection rules — no black-box ML — every finding
            traceable back to the raw evidence.
          </p>
        </div>
        <div className="grid grid-cols-3 gap-4 max-w-md">
          <Stat label="Rules" value="6" />
          <Stat label="Retention" value="72h raw" />
          <Stat label="Model" value="Rule-based" />
        </div>
      </div>

      {/* Right: login form */}
      <div className="flex-1 flex items-center justify-center p-8">
        <form
          onSubmit={submit}
          className="w-full max-w-sm space-y-6"
          data-testid="login-form"
        >
          <div className="lg:hidden flex items-center gap-2 mb-4">
            <ShieldAlert className="w-6 h-6 text-primary" />
            <span className="text-lg font-semibold">SentinelFlow</span>
          </div>
          <div>
            <p className="text-[11px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
              /// Analyst console
            </p>
            <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Access the operations dashboard.
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <Label htmlFor="email" className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
                Email
              </Label>
              <Input
                id="email"
                data-testid="login-email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1.5 font-mono"
                required
              />
            </div>
            <div>
              <Label htmlFor="password" className="text-xs font-mono uppercase tracking-widest text-muted-foreground">
                Password
              </Label>
              <Input
                id="password"
                data-testid="login-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1.5 font-mono"
                required
              />
            </div>
          </div>

          {error && (
            <div
              data-testid="login-error"
              className="text-xs px-3 py-2 rounded-sm severity-critical font-mono"
            >
              {error}
            </div>
          )}

          <Button
            type="submit"
            data-testid="login-submit"
            disabled={loading}
            className="w-full"
          >
            {loading ? "Authenticating…" : "Sign in →"}
          </Button>

          <div className="text-[11px] font-mono text-muted-foreground border border-border/60 rounded-sm p-3 leading-relaxed">
            <div className="uppercase tracking-widest mb-1">Demo credentials</div>
            <div>admin@sentinelflow.io / Admin@12345</div>
            <div>analyst@sentinelflow.io / Analyst@123</div>
          </div>
        </form>
      </div>
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="border border-border/60 rounded-sm p-3">
      <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">
        {label}
      </div>
      <div className="text-lg font-semibold mt-1">{value}</div>
    </div>
  );
}
