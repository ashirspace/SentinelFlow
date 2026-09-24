import axios from "axios";

// In browser production deployments (non-localhost), use same-origin relative /api
// to prevent Mixed Content (HTTPS -> HTTP) and cross-origin cookie issues.
const isBrowser = typeof window !== "undefined";
const isLocalhost = isBrowser && (window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1");

const rawBackend = process.env.REACT_APP_BACKEND_URL || "";
const BACKEND_URL = (isBrowser && !isLocalhost) ? "" : rawBackend;
export const API_BASE = BACKEND_URL ? `${BACKEND_URL.replace(/\/+$/, "")}/api` : "/api";

const api = axios.create({
  baseURL: API_BASE,
  withCredentials: true,
});

export function formatApiError(detail) {
  if (detail == null) return "Something went wrong.";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail))
    return detail
      .map((e) => (e && typeof e.msg === "string" ? e.msg : JSON.stringify(e)))
      .filter(Boolean)
      .join(" ");
  if (detail && typeof detail.msg === "string") return detail.msg;
  return String(detail);
}

export default api;
