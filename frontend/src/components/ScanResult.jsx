import { BrainCircuit, ChevronDown, ShieldAlert, ShieldCheck, Terminal, Zap } from "lucide-react";
import { useState } from "react";
import { Badge, Card, CopyButton, DecisionBadge, EvidenceList, KeyValue, Meter, RiskBadge, RiskGauge, SectionHeading, Spinner } from "./ui";
import { formatDate, pretty } from "../api";

/**
 * Renders one analysis result exactly as returned by the API:
 * score, decision, evidence spans, model context and the untrusted envelope.
 */
export default function ScanResult({ result, onAiProcess, onSimulate, busy, aiResult, simulation }) {
  const [showSanitized, setShowSanitized] = useState(false);
  const [showEnvelope, setShowEnvelope] = useState(false);
  if (!result) return null;

  const scores = result.scores || {};
  const model = result.model || {};
  const categories = result.threat_categories || [];
  const languages = result.languages_detected || [];
  const blocked = ["block", "quarantine"].includes(result.decision);

  return (
    <div className="space-y-4 animate-fade-up">
      <Card className="p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="info">{pretty(result.source_type)}</Badge>
              <RiskBadge band={result.risk_band} />
              <DecisionBadge decision={result.decision} label={result.decision_label} />
            </div>
            <p className="mt-2 truncate text-[14px] font-semibold text-slate-100">{result.source_name}</p>
            <p className="text-[11px] text-slate-500">
              {formatDate(result.created_at)} · scan <span className="mono">{result.id}</span>
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn btn-ghost !text-xs" onClick={onAiProcess} disabled={busy || blocked}>
              {busy ? <Spinner size={13} /> : <BrainCircuit size={13} />} Pass to AI as untrusted
            </button>
            <button type="button" className="btn btn-ghost !text-xs" onClick={onSimulate} disabled={busy}>
              {busy ? <Spinner size={13} /> : <Zap size={13} />} Simulate AI tool call
            </button>
          </div>
        </div>

        <div className="mt-4 grid gap-4 lg:grid-cols-[auto_1fr]">
          <div className="flex items-center justify-center gap-5">
            <RiskGauge score={result.risk_score} band={result.risk_band} />
            <div className="space-y-3">
              <div>
                <p className="eyebrow">Decision</p>
                <p className="text-sm font-semibold text-slate-100">{result.decision_label || pretty(result.decision)}</p>
              </div>
              <div className="w-40 space-y-2">
                <Meter label="Rule engine" value={Math.round((scores.rule_component || 0) * 100)} tone="cyan" />
                <Meter label="ML classifier" value={Math.round((scores.model_component || 0) * 100)} tone="purple" />
              </div>
            </div>
          </div>

          <div className="space-y-3">
            <p className="text-[12.5px] leading-relaxed text-slate-300">{result.summary}</p>
            <KeyValue
              rows={[
                { label: "Categories", value: categories.length ? categories.map(pretty).join(", ") : "none detected" },
                { label: "Languages", value: languages.length ? languages.map((l) => String(l).toUpperCase()).join(", ") : "en" },
                { label: "Model", value: model.available === false ? "rules only (model unavailable)" : "hybrid rules + classifier" },
                { label: "Recommended", value: result.recommended_action || "—" },
              ]}
            />
          </div>
        </div>

        {model.document_context || model.educational_framing ? (
          <div className="mt-3 flex flex-wrap gap-2 text-[11px]">
            {model.document_context ? <Badge tone="neutral">context: {pretty(model.document_context)}</Badge> : null}
            {model.educational_framing ? <Badge tone="purple">educational framing detected</Badge> : null}
            {model.quoted_only ? <Badge tone="info">quoted / attributed only</Badge> : null}
          </div>
        ) : null}

        <div className="mt-4 rounded-xl border border-amber-400/25 bg-amber-400/[0.06] p-3 text-[11.5px] leading-relaxed text-amber-200/90">
          <span className="font-semibold">Score meaning:</span> 0–29 low · 30–59 medium · 60–79 high · 80–100 critical. This is an
          application-specific risk heuristic, not a universal security standard.
        </div>
      </Card>

      <Card className="p-4">
        <SectionHeading icon={ShieldAlert} title="Detection evidence" subtitle="Each span is the exact text that triggered a rule, with the reason it matters." />
        <EvidenceList evidence={result.evidence} />
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="p-4">
          <SectionHeading
            icon={ShieldCheck}
            title="Sanitized content"
            subtitle="What would reach the model if this content is allowed."
            actions={<button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={() => setShowSanitized((v) => !v)}>
              <ChevronDown size={12} className={showSanitized ? "rotate-180" : ""} /> {showSanitized ? "Hide" : "Show"}
            </button>}
          />
          {showSanitized ? (
            <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-black/35 p-3 text-[11.5px] leading-relaxed text-slate-300 scroll-thin">
              {result.sanitized_content || "(empty)"}
            </pre>
          ) : (
            <p className="text-xs text-slate-500">Hidden or injected instruction spans are neutralised before the model sees the text.</p>
          )}
        </Card>

        <Card className="p-4">
          <SectionHeading
            icon={Terminal}
            title="Untrusted envelope"
            subtitle="Structural separation between trusted instructions and external data."
            actions={<>
              <CopyButton value={typeof result.untrusted_envelope === "string" ? result.untrusted_envelope : JSON.stringify(result.untrusted_envelope, null, 2)} />
              <button type="button" className="btn btn-ghost !py-1.5 !px-2.5 !text-[11px]" onClick={() => setShowEnvelope((v) => !v)}>
                <ChevronDown size={12} className={showEnvelope ? "rotate-180" : ""} /> {showEnvelope ? "Hide" : "Show"}
              </button>
            </>}
          />
          {showEnvelope ? (
            <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-black/35 p-3 text-[11px] leading-relaxed text-slate-300 scroll-thin">
              {typeof result.untrusted_envelope === "string" ? result.untrusted_envelope : JSON.stringify(result.untrusted_envelope, null, 2)}
            </pre>
          ) : (
            <p className="text-xs text-slate-500">The payload handed to the model, wrapped with an explicit “data, not instructions” boundary.</p>
          )}
        </Card>
      </div>

      {aiResult ? (
        <Card className="p-4">
          <SectionHeading icon={BrainCircuit} title="AI processing stage" subtitle="Content was passed as untrusted data only." />
          <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/10 bg-black/35 p-3 text-[11px] text-slate-300 scroll-thin">
            {JSON.stringify(aiResult, null, 2)}
          </pre>
        </Card>
      ) : null}

      {simulation ? (
        <Card className="p-4">
          <SectionHeading icon={Zap} title="Firewall verdict on the simulated tool call" subtitle="Derived from what the AI would attempt if it obeyed the document." />
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <Badge tone="purple">{pretty(simulation.requested_action?.action_type)}</Badge>
            <Badge tone={simulation.firewall?.decision === "block" ? "critical" : simulation.firewall?.decision === "allow" ? "low" : "high"}>
              {pretty(simulation.firewall?.decision)}
            </Badge>
            <span className="text-[11px] text-slate-500">risk: {simulation.firewall?.risk_level}</span>
          </div>
          <p className="mb-2 text-[12px] text-slate-300">{simulation.firewall?.reason || simulation.firewall?.summary}</p>
          <ul className="space-y-1.5">
            {(simulation.firewall?.rules || []).map((rule, index) => (
              <li key={index} className="flex items-start gap-2 text-[11.5px] text-slate-400">
                <span className={`mt-1 h-1.5 w-1.5 shrink-0 rounded-full ${rule.passed ? "bg-emerald-400" : "bg-rose-400"}`} />
                <span>
                  <span className="mono text-[10.5px] text-slate-500">{rule.rule_id || rule.id || `rule-${index + 1}`}</span>{" "}
                  {rule.message || rule.description || pretty(rule.name || "")}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}
