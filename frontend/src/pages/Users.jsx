import { useEffect, useState } from "react";
import api from "@/lib/api";
import { PageHeader } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";

export default function Users() {
  const [users, setUsers] = useState([]);
  const [form, setForm] = useState({ email: "", password: "", name: "", role: "analyst" });
  const [creating, setCreating] = useState(false);

  const load = async () => {
    const { data } = await api.get("/users");
    setUsers(data);
  };
  useEffect(() => { load(); }, []);

  const create = async (e) => {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post("/users", form);
      toast.success("User created");
      setForm({ email: "", password: "", name: "", role: "analyst" });
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed");
    } finally {
      setCreating(false);
    }
  };

  const del = async (id) => {
    if (!confirm("Delete this user?")) return;
    try {
      await api.delete(`/users/${id}`);
      toast.success("Deleted");
      await load();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Failed");
    }
  };

  return (
    <div className="pb-16">
      <PageHeader
        title="Users & Roles"
        subtitle="Admins manage accounts. Analysts triage alerts and search logs."
      />
      <div className="px-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
        <form onSubmit={create} className="border border-border/60 rounded-md bg-card/40 p-6" data-testid="new-user-form">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground mb-1">
            /// New user
          </div>
          <h2 className="text-base font-semibold mb-4">Invite team member</h2>
          <div className="space-y-3">
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Name</Label>
              <Input data-testid="user-name-input" value={form.name}
                     onChange={(e) => setForm({ ...form, name: e.target.value })}
                     className="mt-1.5" required />
            </div>
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Email</Label>
              <Input data-testid="user-email-input" type="email" value={form.email}
                     onChange={(e) => setForm({ ...form, email: e.target.value })}
                     className="mt-1.5 font-mono" required />
            </div>
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Temp password</Label>
              <Input data-testid="user-password-input" type="text" value={form.password}
                     onChange={(e) => setForm({ ...form, password: e.target.value })}
                     className="mt-1.5 font-mono" required minLength={6} />
            </div>
            <div>
              <Label className="text-xs font-mono uppercase tracking-widest text-muted-foreground">Role</Label>
              <Select value={form.role} onValueChange={(v) => setForm({ ...form, role: v })}>
                <SelectTrigger className="mt-1.5 font-mono" data-testid="user-role-select">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-popover border border-border">
                  <SelectItem value="admin">admin</SelectItem>
                  <SelectItem value="analyst">analyst</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button type="submit" disabled={creating} data-testid="user-create-btn"
                    className="w-full font-mono text-xs uppercase tracking-widest">
              {creating ? "Creating…" : "Create user"}
            </Button>
          </div>
        </form>

        <div className="lg:col-span-2 border border-border/60 rounded-md bg-card/40 overflow-hidden">
          <table className="w-full text-xs" data-testid="users-table">
            <thead className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground border-b border-border/60 bg-black/20">
              <tr>
                <th className="text-left px-4 py-2.5">Name</th>
                <th className="text-left px-4 py-2.5">Email</th>
                <th className="text-left px-4 py-2.5">Role</th>
                <th className="text-left px-4 py-2.5">Created</th>
                <th className="text-right px-4 py-2.5">Actions</th>
              </tr>
            </thead>
            <tbody className="font-mono">
              {users.map((u) => (
                <tr key={u.id} className="border-b border-border/40" data-testid={`user-row-${u.id}`}>
                  <td className="px-4 py-3">{u.name}</td>
                  <td className="px-4 py-3">{u.email}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 text-[10px] uppercase tracking-widest rounded-sm border ${u.role === "admin" ? "bg-primary/10 text-primary border-primary/25" : "bg-cyan-500/10 text-cyan-400 border-cyan-500/25"}`}>
                      {u.role}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {u.created_at ? new Date(u.created_at).toLocaleDateString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button onClick={() => del(u.id)} data-testid={`user-delete-${u.id}`}
                            className="text-muted-foreground hover:text-red-400 p-1"
                            style={{ transition: "color 0.15s ease" }}>
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
