import { Link2, ShieldQuestion, Sparkles } from "lucide-react";
import { useState } from "react";
import { api } from "../api";
import ScanResult from "../components/ScanResult";
import { Card, ErrorNotice, SectionHeading, Spinner } from "../components/ui";

export default function UrlScanner() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [aiResult, setAiResult] = useState(null);
  const [simulation, setSimulation] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event) {
    event.preventDefault();
    setError("");
    setBusy(true);
    setAiResult(null);
    setSimulation(null);
    try {
      setResult(await api.scanUrl({ url: url.trim() }));
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  async function runAi() {
    setBusy(true);
    try {
      setAiResult(await api.aiProcess(result.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function runSimulation() {
    setBusy(true);
    try {
      setSimulation(await api.simulateAiCall(result.id));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(0,420px)_minmax(0,1fr)]">
      <div className="space-y-4">
        <Card className="p-4">
          <SectionHeading icon={Link2} title="Fetch a web page" subtitle="Only http/https public addresses are fetched." />
          <ErrorNotice error={error} className="mb-3" />
          <form onSubmit={submit} className="space-y-3">
            <div>
              <label className="label" htmlFor="url">
                Page URL
              </label>
              <input
                id="url"
                className="input mono !text-[12.5px]"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com/article"
                inputMode="url"
                required
              />
            </div>
            <button type="submit" className="btn btn-primary w-full" disabled={busy || url.trim().length < 8}>
              {busy ? <Spinner size={14} /> : <Sparkles size={14} />} Fetch and analyse
            </button>
          </form>
        </Card>

        <Card className="p-4">
          <SectionHeading icon={ShieldQuestion} title="SSRF protection" subtitle="Why some URLs are rejected." />
          <ul className="space-y-2 text-[11.5px] leading-relaxed text-slate-400">
            <li>• Private, loopback, link-local and cloud-metadata addresses are refused before any request.</li>
            <li>• Only <span className="mono text-slate-300">http</span> and <span className="mono text-slate-300">https</span> schemes are allowed.</li>
            <li>• Redirects are re-validated so a public host cannot bounce you to an internal one.</li>
            <li>• Response size and time are bounded; scripts are never executed.</li>
          </ul>
        </Card>
      </div>

      <div>
        {result ? (
          <ScanResult result={result} busy={busy} aiResult={aiResult} simulation={simulation} onAiProcess={runAi} onSimulate={runSimulation} />
        ) : (
          <Card className="grid min-h-[420px] place-items-center p-8 text-center">
            <div>
              <span className="mx-auto mb-3 grid h-12 w-12 place-items-center rounded-2xl border border-cyan-400/25 bg-cyan-400/10 text-cyan-300">
                <Link2 size={20} />
              </span>
              <p className="text-sm font-medium text-slate-200">No page analysed yet</p>
              <p className="mx-auto mt-1 max-w-sm text-xs leading-relaxed text-slate-500">
                Enter a public URL. Visible text, comments, hidden nodes and metadata are extracted, then scored for
                embedded instructions.
              </p>
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
