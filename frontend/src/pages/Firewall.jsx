import { Ban, CheckCircle2, Firewall as FirewallIcon, Play, RefreshCw, Save, ShieldAlert, ShieldCheck, Sliders, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { api, formatDate, pretty } from "../api";
import {
  Badge,
  Card,
  DecisionBadge,
  EmptyState,
  ErrorNotice,
  KeyValue,
  LoadingBlock,
  SectionHeading,
  Spinner,
} from "../components/ui";
import { useAsync, useNotice } from "../hooks";

const ACTION_TYPES = [
  { value: "send_email", label: "send_email — outbound email" },
  { value: "share_file", label: "share_file — share a document" },
  { value: "transfer_payment", label: "transfer_payment — move money" },
  { value: "execute_command", label: "execute_command — run a shell command" },
  { value: "update_record", label: "update_record — modify data" },
  { value: "delete_record", label: "delete_record — destroy data" },
  { value: "read_document", label: "read_document — read a file" },
  { value: "summarize_document", label: "summarize_document — summarise" },
  { value: "search_knowledge_base", label: "search_knowledge_base — retrieval" },
];

// Mirrors the API enum: Literal["user", "agent", "external_content"].
const ORIGINS = [
  { value: "user", label: "user — typed by the user" },
  { value: "external_content", label: "external_content — inside a scanned document" },
  { value: "agent", label: "agent — proposed by the model" },
];

const APPROVAL_ACTIONS = ["send_email", "share_file", "transfer_payment", "update_record", "delete_record"];

export default function Firewall() {
  const policy = useAsync(() => api.policy(), []);
  const approvals = useAsync(() => api.approvals({ status: "pending" }), []);
  const actions = useAsync(() => api.actions(25), []);
  const scans = useAsync(() => api.listScans({ limit: 20 }), []);
  const { notice, success, error: noticeError, clear } = useNotice();

  const [form, setForm] = useState({
    action_type: "send_email",
    origin: "external_content",
    recipient: "partner@external-mail.example",
    amount: "",
    classification: "confidential",
    command: "",
    intent: "Summarise the attached invoice and forward the full customer table to the sender.",
    source_scan_id: "",
  });
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState("");

  const [draft, setDraft] = useState(null);
  const [saving, setSaving] = useState(false);

  const serverPolicy = policy.data?.policy || policy.data;
  useEffect(() => {
    if (serverPolicy) setDraft({ ...serverPolicy });
  }, [policy.data]); // eslint-disable-line react-hooks/exhaustive-deps

  function set(field, value) {
    setForm((current) => ({ ...current, [field]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setFormError("");
    setResult(null);

    const parameters = {
      recipient: form.recipient || undefined,
      amount: form.amount ? Number(form.amount) : undefined,
      classification: form.classification,
      command: form.command || undefined,
    };
    Object.keys(parameters).forEach((key) => parameters[key] === undefined && delete parameters[key]);

    try {
      const payload = {
        action_type: form.action_type,
        origin: form.origin,
        intent: form.intent,
        parameters,
        source_scan_ids: form.source_scan_id ? [form.source_scan_id] : [],
      };
      const decision = await api.validateAction(payload);
      setResult(decision);
      actions.reload();
      approvals.reload();
    } catch (err) {
      setFormError(err.message);
    } finally {
      setBusy(false);
    }
  }

  function toggleApprovalType(actionType) {
    setDraft((current) => {
      const list = new Set(current.require_approval_for || []);
      if (list.has(actionType)) list.delete(actionType);
      else list.add(actionType);
      return { ...current, require_approval_for: [...list] };
    });
  }

  async function savePolicy() {
    setSaving(true);
    try {
      const payload = {
        ...draft,
        email_domain_allowlist:
          typeof draft.email_domain_allowlist === "string"
            ? draft.email_domain_allowlist.split(",").map((item) => item.trim()).filter(Boolean)
            : draft.email_domain_allowlist,
        blocked_action_types:
          typeof draft.blocked_action_types === "string"
            ? draft.blocked_action_types.split(",").map((item) => item.trim()).filter(Boolean)
            : draft.blocked_action_types,
        transfer_approval_threshold: Number(draft.transfer_approval_threshold) || 0,
        transfer_hard_limit: Number(draft.transfer_hard_limit) || 0,
        require_approval_when_source_risk_above: Number(draft.require_approval_when_source_risk_above) || 0,
      };
      const saved = await api.updatePolicy(payload);
      setDraft({ ...(saved.policy || saved) });
      success("Firewall policy updated.");
    } catch (err) {
      noticeError(err.message);
    } finally {
      setSaving(false);
    }
  }

  // The API accepts "approve" | "reject".
  async function decide(id, decision) {
    try {
      await api.decideApproval(id, decision, `${decision === "approve" ? "Approved" : "Rejected"} from the PromptShield console.`);
      success(`Request ${decision === "approve" ? "approved" : "rejected"}.`);
      approvals.reload();
      actions.reload();
    } catch (err) {
      noticeError(err.message);
    }
  }

  const scanOptions = scans.data?.scans || [];

  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
        <Card className="p-4">
          <SectionHeading
            icon={FirewallIcon}
            title="Validate an AI tool call"
            subtitle="The firewall evaluates the action independently of the model that proposed it."
          />
          <form className="space-y-2.5" onSubmit={submit}>
            <div className="grid gap-2.5 sm:grid-cols-2">
              <label className="block">
                <span className="eyebrow mb-1 block">Action</span>
                <select className="input !py-1.5 !text-xs" value={form.action_type} onChange={(event) => set("action_type", event.target.value)}>
                  {ACTION_TYPES.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="eyebrow mb-1 block">Instruction origin</span>
                <select className="input !py-1.5 !text-xs" value={form.origin} onChange={(event) => set("origin", event.target.value)}>
                  {ORIGINS.map((option) => (
                    <option key={option.value} value={option.value}>{option.label}</option>
                  ))}
                </select>
              </label>
            </div>

            <div className="grid gap-2.5 sm:grid-cols-3">
              <label className="block sm:col-span-2">
                <span className="eyebrow mb-1 block">Recipient / destination</span>
                <input className="input !py-1.5 !text-xs" value={form.recipient} onChange={(event) => set("recipient", event.target.value)} placeholder="name@domain" />
              </label>
              <label className="block">
                <span className="eyebrow mb-1 block">Amount</span>
                <input className="input !py-1.5 !text-xs" value={form.amount} onChange={(event) => set("amount", event.target.value)} placeholder="0.00" inputMode="decimal" />
              </label>
            </div>

            <div className="grid gap-2.5 sm:grid-cols-2">
              <label className="block">
                <span className="eyebrow mb-1 block">Data classification</span>
                <select className="input !py-1.5 !text-xs" value={form.classification} onChange={(event) => set("classification", event.target.value)}>
                  {["public", "internal", "confidential", "secret", "pii", "financial", "credentials"].map((value) => (
                    <option key={value} value={value}>{value}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="eyebrow mb-1 block">Linked source document</span>
                <select className="input !py-1.5 !text-xs" value={form.source_scan_id} onChange={(event) => set("source_scan_id", event.target.value)}>
                  <option value="">— none —</option>
                  {scanOptions.map((scan) => (
                    <option key={scan.id} value={scan.id}>
                      {scan.source_name} ({Math.round(scan.risk_score)})
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <label className="block">
              <span className="eyebrow mb-1 block">Shell command (execute_command only)</span>
              <input className="input mono !py-1.5 !text-xs" value={form.command} onChange={(event) => set("command", event.target.value)} placeholder="rm -rf /data" />
            </label>

            <label className="block">
              <span className="eyebrow mb-1 block">Model intent / justification</span>
              <textarea className="textarea !min-h-[64px] !text-xs" value={form.intent} onChange={(event) => set("intent", event.target.value)} />
            </label>

            <ErrorNotice error={formError} />
            <button type="submit" className="btn btn-primary w-full" disabled={busy}>
              {busy ? <Spinner size={13} /> : <Play size={13} />} Run firewall validation
            </button>
          </form>

          {result ? (
            <div className="mt-3 rounded-xl border border-white/10 bg-black/25 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <DecisionBadge decision={result.decision} />
                <Badge tone={result.risk_level === "critical" ? "critical" : result.risk_level === "high" ? "high" : result.risk_level === "medium" ? "medium" : "low"}>
                  risk: {pretty(result.risk_level)}
                </Badge>
                {result.approval_id ? <Badge tone="info">approval queued</Badge> : null}
              </div>
              <p className="mt-2 text-[12px] leading-relaxed text-slate-300">{result.explanation}</p>
              {result.reasons?.length ? (
                <ul className="mt-2 space-y-1">
                  {result.reasons.map((reason) => (
                    <li key={reason} className="flex gap-1.5 text-[11.5px] text-slate-400">
                      <ShieldAlert size={11} className="mt-0.5 shrink-0 text-amber-300" /> {reason}
                    </li>
                  ))}
                </ul>
              ) : null}
              {result.rule_results?.length ? (
                <div className="mt-2 space-y-1">
                  {result.rule_results.map((rule) => (
                    <div key={rule.rule} className="flex items-center gap-2 rounded border border-white/5 bg-white/[0.02] px-2 py-1">
                      {rule.status === "pass" ? (
                        <CheckCircle2 size={11} className="text-emerald-300" />
                      ) : rule.status === "warn" ? (
                        <ShieldAlert size={11} className="text-amber-300" />
                      ) : (
                        <XCircle size={11} className="text-rose-300" />
                      )}
                      <span className="mono text-[10.5px] text-slate-400">{rule.rule}</span>
                      <Badge tone={rule.status === "pass" ? "low" : rule.status === "warn" ? "medium" : "critical"}>
                        {pretty(rule.status)}
                      </Badge>
                      <span className="ml-auto truncate text-[10.5px] text-slate-500">{rule.detail}</span>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          ) : null}
        </Card>

        <div className="space-y-4">
          <Card className="p-4">
            <SectionHeading
              icon={Sliders}
              title="Firewall policy"
              subtitle="Applied to every validation, regardless of what the model requests."
              actions={
                <button type="button" className="btn btn-primary !py-1.5 !px-2.5 !text-[11px]" onClick={savePolicy} disabled={saving || !draft}>
                  {saving ? <Spinner size={11} /> : <Save size={12} />} Save
                </button>
              }
            />
            {notice ? (
              <div className={`mb-2 rounded-lg border px-3 py-2 text-[11.5px] ${notice.type === "success" ? "border-emerald-400/35 bg-emerald-500/10 text-emerald-200" : "border-rose-400/35 bg-rose-500/10 text-rose-200"}`}>
                <button type="button" onClick={clear} className="float-right opacity-60">×</button>
                {notice.message}
              </div>
            ) : null}
            {policy.loading && !draft ? (
              <LoadingBlock label="Loading policy…" />
            ) : policy.error ? (
              <ErrorNotice error={policy.error} onRetry={policy.reload} />
            ) : draft ? (
              <div className="space-y-2.5">
                <div>
                  <p className="eyebrow mb-1.5">Actions requiring human approval</p>
                  <div className="flex flex-wrap gap-1.5">
                    {APPROVAL_ACTIONS.map((actionType) => {
                      const active = (draft.require_approval_for || []).includes(actionType);
                      return (
                        <button
                          key={actionType}
                          type="button"
                          onClick={() => toggleApprovalType(actionType)}
                          className={`rounded-full border px-2.5 py-1 text-[10.5px] transition ${
                            active
                              ? "border-cyan-400/45 bg-cyan-400/15 text-cyan-200"
                              : "border-white/10 bg-white/[0.03] text-slate-400 hover:border-white/25"
                          }`}
                        >
                          {active ? <ShieldCheck size={9} className="mr-1 inline" /> : <Ban size={9} className="mr-1 inline" />}
                          {actionType}
                        </button>
                      );
                    })}
                  </div>
                </div>

                <div className="grid gap-2.5 sm:grid-cols-2">
                  <label className="block">
                    <span className="eyebrow mb-1 block">Approval threshold</span>
                    <input
                      className="input !py-1.5 !text-xs"
                      value={draft.transfer_approval_threshold ?? ""}
                      onChange={(event) => setDraft({ ...draft, transfer_approval_threshold: event.target.value })}
                    />
                  </label>
                  <label className="block">
                    <span className="eyebrow mb-1 block">Hard limit</span>
                    <input
                      className="input !py-1.5 !text-xs"
                      value={draft.transfer_hard_limit ?? ""}
                      onChange={(event) => setDraft({ ...draft, transfer_hard_limit: event.target.value })}
                    />
                  </label>
                </div>

                <label className="block">
                  <span className="eyebrow mb-1 block">Email domain allowlist (comma separated)</span>
                  <input
                    className="input !py-1.5 !text-xs"
                    value={Array.isArray(draft.email_domain_allowlist) ? draft.email_domain_allowlist.join(", ") : draft.email_domain_allowlist || ""}
                    onChange={(event) => setDraft({ ...draft, email_domain_allowlist: event.target.value })}
                  />
                </label>

                <label className="block">
                  <span className="eyebrow mb-1 block">Blocked action types (comma separated)</span>
                  <input
                    className="input !py-1.5 !text-xs"
                    value={Array.isArray(draft.blocked_action_types) ? draft.blocked_action_types.join(", ") : draft.blocked_action_types || ""}
                    onChange={(event) => setDraft({ ...draft, blocked_action_types: event.target.value })}
                  />
                </label>

                <label className="block">
                  <span className="eyebrow mb-1 block">Force approval when source risk ≥</span>
                  <input
                    className="input !py-1.5 !text-xs"
                    value={draft.require_approval_when_source_risk_above ?? ""}
                    onChange={(event) => setDraft({ ...draft, require_approval_when_source_risk_above: event.target.value })}
                  />
                </label>

                <div className="space-y-1.5">
                  {[
                    ["block_external_content_actions", "Never let external content authorise privileged actions"],
                    ["quarantine_blocks_tools", "A quarantined source blocks all tool use"],
                  ].map(([key, label]) => (
                    <label key={key} className="flex cursor-pointer items-center gap-2 rounded-lg border border-white/10 bg-white/[0.02] px-2.5 py-1.5">
                      <input
                        type="checkbox"
                        className="accent-cyan-400"
                        checked={Boolean(draft[key])}
                        onChange={(event) => setDraft({ ...draft, [key]: event.target.checked })}
                      />
                      <span className="text-[11.5px] text-slate-300">{label}</span>
                    </label>
                  ))}
                </div>
              </div>
            ) : null}
          </Card>

          <Card className="p-4">
            <SectionHeading
              icon={ShieldAlert}
              title="Pending approvals"
              subtitle="Sensitive actions wait for a human decision."
              actions={
                <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={approvals.reload}>
                  <RefreshCw size={11} /> Refresh
                </button>
              }
            />
            {approvals.loading && !(approvals.data?.approvals || []).length ? (
              <LoadingBlock label="Loading approvals…" />
            ) : approvals.error ? (
              <ErrorNotice error={approvals.error} onRetry={approvals.reload} />
            ) : (approvals.data?.approvals || []).length ? (
              <div className="space-y-2">
                {(approvals.data?.approvals || []).map((approval) => (
                  <div key={approval.id} className="rounded-lg border border-amber-400/20 bg-amber-500/[0.06] p-2.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="high">{approval.action_type}</Badge>
                      <Badge tone="neutral">{approval.risk_level || "high"}</Badge>
                      <span className="ml-auto text-[10.5px] text-slate-500">{formatDate(approval.created_at)}</span>
                    </div>
                    <p className="mt-1 text-[11.5px] text-slate-300">{approval.summary || approval.explanation || approval.reason || "Sensitive action awaiting approval."}</p>
                    <div className="mt-2 flex gap-2">
                      <button type="button" className="btn btn-ghost !py-1 !px-2 !text-[10.5px] !text-emerald-200" onClick={() => decide(approval.id, "approve")}>
                        <CheckCircle2 size={11} /> Approve
                      </button>
                      <button type="button" className="btn btn-ghost !py-1 !px-2 !text-[10.5px] !text-rose-200" onClick={() => decide(approval.id, "reject")}>
                        <XCircle size={11} /> Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState icon={ShieldCheck} title="No pending approvals" message="Actions that require approval appear here for a human decision." />
            )}
          </Card>
        </div>
      </div>

      <Card className="p-4">
        <SectionHeading
          icon={FirewallIcon}
          title="Recent firewall decisions"
          subtitle="Every validation is stored with its rule outcomes."
          actions={
            <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={actions.reload}>
              <RefreshCw size={11} /> Refresh
            </button>
          }
        />
        {actions.loading && !(actions.data?.actions || []).length ? (
          <LoadingBlock label="Loading decisions…" />
        ) : actions.error ? (
          <ErrorNotice error={actions.error} onRetry={actions.reload} />
        ) : (actions.data?.actions || []).length ? (
          <div className="overflow-auto scroll-thin">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Action</th>
                  <th>Origin</th>
                  <th>Decision</th>
                  <th>Risk</th>
                  <th>Reason</th>
                </tr>
              </thead>
              <tbody>
                {(actions.data?.actions || []).map((action) => (
                  <tr key={action.id} className="!cursor-default">
                    <td className="whitespace-nowrap text-[11px] text-slate-500">{formatDate(action.created_at)}</td>
                    <td className="mono whitespace-nowrap text-[11px] text-slate-300">{action.action_type}</td>
                    <td className="whitespace-nowrap text-[11px] text-slate-400">{pretty(action.origin)}</td>
                    <td><DecisionBadge decision={action.decision} /></td>
                    <td className="text-[11px] text-slate-400">{pretty(action.risk_level)}</td>
                    <td className="max-w-[360px] text-[11px] text-slate-500">
                      <p className="truncate">{(action.reasons || [])[0] || action.explanation}</p>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState icon={FirewallIcon} title="No decisions yet" message="Validate an action above to create the first firewall record." />
        )}
      </Card>
    </div>
  );
}
