import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import "@/index.css";
import { AuthProvider } from "@/context/AuthContext";
import ProtectedRoute from "@/components/ProtectedRoute";
import Layout from "@/components/Layout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Alerts from "@/pages/Alerts";
import Explorer from "@/pages/Explorer";
import Ingest from "@/pages/Ingest";
import Rules from "@/pages/Rules";
import Sources from "@/pages/Sources";
import Incidents from "@/pages/Incidents";
import Reports from "@/pages/Reports";
import Notifications from "@/pages/Notifications";
import Users from "@/pages/Users";
import Audit from "@/pages/Audit";

function Shell({ children, requireAdmin }) {
  return (
    <ProtectedRoute requireAdmin={requireAdmin}>
      <Layout>{children}</Layout>
    </ProtectedRoute>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/dashboard" element={<Shell><Dashboard /></Shell>} />
          <Route path="/alerts" element={<Shell><Alerts /></Shell>} />
          <Route path="/explorer" element={<Shell><Explorer /></Shell>} />
          <Route path="/ingest" element={<Shell><Ingest /></Shell>} />
          <Route path="/rules" element={<Shell><Rules /></Shell>} />
          <Route path="/sources" element={<Shell><Sources /></Shell>} />
          <Route path="/incidents" element={<Shell><Incidents /></Shell>} />
          <Route path="/reports" element={<Shell><Reports /></Shell>} />
          <Route path="/notifications" element={<Shell><Notifications /></Shell>} />
          <Route path="/users" element={<Shell requireAdmin><Users /></Shell>} />
          <Route path="/audit" element={<Shell requireAdmin><Audit /></Shell>} />
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
