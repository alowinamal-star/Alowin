import { Database, KeyRound, LogOut, ScrollText, Server, ShieldCheck, User } from "lucide-react";
import { api, formatDate, pretty } from "../api";
import { useAuth } from "../auth";
import { Badge, Card, EmptyState, ErrorNotice, KeyValue, LoadingBlock, SectionHeading } from "../components/ui";
import { useAsync } from "../hooks";

export default function Settings() {
  const { user, logout } = useAuth();
  const info = useAsync(() => api.systemInfo(), []);
  const audit = useAsync(() => api.audit(60), []);

  const system = info.data;
  const events = audit.data?.events || [];

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <SectionHeading icon={User} title="Your account" subtitle="Role-based access is enforced by the API, not the UI." />
          <div className="flex items-center gap-3">
            <span className="grid h-12 w-12 place-items-center rounded-2xl border border-cyan-400/25 bg-cyan-400/10 text-lg font-semibold text-cyan-200">
              {(user?.name || user?.email || "?").slice(0, 1).toUpperCase()}
            </span>
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-slate-100">{user?.name || "—"}</p>
              <p className="truncate text-[11.5px] text-slate-400">{user?.email}</p>
            </div>
            <Badge tone="info" className="ml-auto">{pretty(user?.role)}</Badge>
          </div>

          <div className="mt-3">
            <p className="eyebrow mb-2">Capabilities</p>
            <div className="flex flex-wrap gap-1.5">
              {(user?.capabilities || []).map((capability) => (
                <Badge key={capability} tone="purple">
                  <ShieldCheck size={10} className="mr-1" /> {capability}
                </Badge>
              ))}
            </div>
          </div>

          <div className="mt-3">
            <KeyValue
              rows={[
                { label: "User ID", value: user?.id },
                { label: "Created", value: formatDate(user?.created_at) },
              ]}
            />
          </div>

          <button type="button" className="btn btn-ghost mt-3 w-full" onClick={logout}>
            <LogOut size={13} /> Sign out
          </button>
        </Card>

        <Card className="p-4">
          <SectionHeading icon={Server} title="System" subtitle="Reported by the running backend." />
          {info.loading && !system ? (
            <LoadingBlock label="Loading system info…" />
          ) : info.error ? (
            <ErrorNotice error={info.error} onRetry={info.reload} />
          ) : (
            <>
              <KeyValue
                rows={[
                  { label: "Application", value: `${system?.app} v${system?.version}` },
                  { label: "Storage backend", value: pretty(system?.storage_backend) },
                  { label: "Detector", value: system?.detector?.model },
                  { label: "Model threshold", value: system?.detector?.threshold },
                  { label: "Max upload", value: `${Math.round((system?.limits?.max_upload_bytes || 0) / 1024 / 1024)} MB` },
                  { label: "Max text", value: `${(system?.limits?.max_text_chars || 0).toLocaleString()} chars` },
                  { label: "Scan rate limit", value: `${system?.limits?.scan_rate_per_minute || 0} / min` },
                  { label: "Runtime", value: `Python ${system?.runtime?.python}` },
                  { label: "LLM integration", value: system?.llm?.configured ? `configured (${system?.llm?.model})` : "not configured — deterministic fallback" },
                ]}
              />
              <div className="mt-3 grid grid-cols-3 gap-2">
                {Object.entries(system?.counts || {}).map(([key, value]) => (
                  <div key={key} className="rounded-lg border border-white/10 bg-white/[0.03] p-2 text-center">
                    <p className="text-[15px] font-semibold tabular-nums text-slate-100">{value}</p>
                    <p className="text-[10px] uppercase tracking-wider text-slate-500">{key}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </Card>
      </div>

      <Card className="p-4">
        <SectionHeading
          icon={ScrollText}
          title="Audit log"
          subtitle="Security-relevant actions recorded server-side with actor and timestamp."
          actions={
            <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={audit.reload}>
              Refresh
            </button>
          }
        />
        {audit.loading && !events.length ? (
          <LoadingBlock label="Loading audit events…" />
        ) : audit.error ? (
          <ErrorNotice error={audit.error} onRetry={audit.reload} />
        ) : events.length ? (
          <div className="max-h-[420px] overflow-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Detail</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event) => (
                  <tr key={event.id} className="!cursor-default">
                    <td className="whitespace-nowrap text-[11px] text-slate-500">{formatDate(event.created_at)}</td>
                    <td className="whitespace-nowrap text-[11.5px] text-slate-300">{event.actor || event.user || "system"}</td>
                    <td><Badge tone="neutral">{event.action}</Badge></td>
                    <td className="max-w-[420px] text-[11.5px] text-slate-400">
                      <p className="truncate">{event.message || event.detail || event.summary}</p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={ScrollText} title="No audit events" message="Scanning content and validating actions creates audit records." />
        )}
      </Card>

      <Card className="p-4">
        <SectionHeading icon={Database} title="Configuration" subtitle="Environment-driven settings — no secrets are exposed to the browser." />
        <ul className="space-y-1.5 text-[11.5px] leading-relaxed text-slate-400">
          <li>• <span className="mono text-slate-300">MONGODB_URI</span> — optional; the app falls back to an embedded persistent store when unset.</li>
          <li>• <span className="mono text-slate-300">JWT_SECRET</span> — signs access tokens; set a long random value in production.</li>
          <li>• <span className="mono text-slate-300">LLM_BASE_URL</span> / <span className="mono text-slate-300">LLM_API_KEY</span> — optional OpenAI-compatible endpoint for the AI processing step.</li>
          <li>• <span className="mono text-slate-300">PROMPTSHIELD_ENV</span> — set to <span className="mono">production</span> to require secure cookies and disable demo seeding.</li>
        </ul>
        <p className="mt-2 text-[10.5px] text-slate-500">
          <KeyRound size={10} className="mr-1 inline" />
          Credentials are read from the server environment only; the frontend never receives API keys.
        </p>
      </Card>
    </div>
  );
}
