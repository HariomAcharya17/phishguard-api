"use client";

import { useState } from "react";
import { CheckResult, RISK, SEVERITY, SourceCheck } from "@/lib/types";

type Row = { name: string; value: string; tone: "good" | "bad" | "warn" | "muted" };

function statusText(c: SourceCheck | undefined): string | null {
  switch (c?.status) {
    case "not_configured": return "Not configured";
    case "rate_limited": return "Skipped (rate limit)";
    case "timeout": return "Timed out";
    case "error": case "auth_error": return "Unavailable";
    case "skipped": return "Skipped";
    default: return null;
  }
}

function formatAge(days: number): string {
  if (days < 1) return "today";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} ago`;
  if (days < 730) return `${Math.round(days / 30)} months ago`;
  return `${Math.floor(days / 365)} years ago`;
}

function sourceRows(r: CheckResult): Row[] {
  const rows: Row[] = [];
  const vt = r.checks.virustotal;
  const vtSkip = statusText(vt);
  if (vtSkip) rows.push({ name: "VirusTotal", value: vtSkip, tone: "muted" });
  else if (vt?.status === "unknown") rows.push({ name: "VirusTotal", value: "Not in database yet", tone: "muted" });
  else {
    const mal = Number(vt?.malicious ?? 0), eng = Number(vt?.engines ?? 0);
    const scope = vt?.scope === "domain" ? " (domain)" : "";
    rows.push({ name: "VirusTotal", value: mal ? `${mal} of ${eng} engines flag it${scope}` : `Clean, 0 of ${eng} engines${scope}`, tone: mal >= 3 ? "bad" : mal ? "warn" : "good" });
  }

  const op = r.checks.openphish;
  const opSkip = statusText(op);
  rows.push(opSkip
    ? { name: "OpenPhish feed", value: opSkip, tone: "muted" }
    : op?.listed
      ? { name: "OpenPhish feed", value: op.listed === "url" ? "Link is listed" : "Host is listed", tone: "bad" }
      : { name: "OpenPhish feed", value: "Not listed", tone: "good" });

  const who = r.checks.whois;
  const whoSkip = statusText(who);
  if (whoSkip) rows.push({ name: "Domain age", value: whoSkip, tone: "muted" });
  else if (who?.status === "redacted" || who?.status === "unparsed") rows.push({ name: "Domain age", value: "Hidden by registrar", tone: "muted" });
  else if (who?.status === "not_applicable") rows.push({ name: "Domain age", value: "Not applicable (IP address)", tone: "muted" });
  else if (typeof r.domain_age_days === "number") {
    const d = r.domain_age_days;
    const value = d < 730 || !r.domain_created ? `Registered ${formatAge(d)}` : `Since ${r.domain_created.slice(0, 4)} (${Math.floor(d / 365)} years)`;
    rows.push({ name: "Domain age", value, tone: d < 30 ? "bad" : d < 180 ? "warn" : "good" });
  }

  const dns = r.checks.dns;
  const dnsSkip = statusText(dns);
  if (dnsSkip) rows.push({ name: "Connection", value: dnsSkip, tone: "muted" });
  else if (dns?.resolves === false) rows.push({ name: "Connection", value: "Domain does not resolve", tone: "warn" });
  else if (dns?.public === false) rows.push({ name: "Connection", value: "Private network address", tone: "warn" });
  else if (dns?.fetch_error) rows.push({ name: "Connection", value: "Site did not respond", tone: "muted" });
  else rows.push({ name: "Connection", value: dns?.final_https ? "Uses HTTPS" : "No HTTPS", tone: dns?.final_https ? "good" : "warn" });

  if (r.ml_score !== null) {
    const pct = Math.round(r.ml_score * 100);
    rows.push({ name: "Hostname model", value: r.well_known_domain ? "Not used (well-known site)" : `${pct}% phishing-like`, tone: r.well_known_domain ? "muted" : pct >= 75 ? "bad" : pct >= 60 ? "warn" : "good" });
  }
  // Sources that aren't set up on this deployment are left out entirely.
  return rows.filter((row) => row.value !== "Not configured");
}

const TONE: Record<Row["tone"], string> = {
  good: "text-risk-safe",
  bad: "text-risk-critical",
  warn: "text-risk-medium",
  muted: "text-slate-500",
};

export default function ResultCard({ result: r }: { result: CheckResult }) {
  const [copied, setCopied] = useState(false);
  const risk = RISK[r.risk_level] ?? RISK.safe;
  const score = Math.round((r.risk_score ?? 0) * 100);
  const rows = sourceRows(r);
  const redirected = r.final_url && r.final_url !== r.url;

  return (
    <article className="animate-fade-up overflow-hidden rounded-xl border border-slate-200 bg-white shadow-lg shadow-slate-900/5">
      {/* Verdict */}
      <div className={`flex flex-col gap-5 p-5 sm:flex-row sm:items-center sm:justify-between sm:p-6 ${risk.bg}`}>
        <div className="min-w-0">
          <div className={`inline-flex items-center gap-2 rounded-full bg-white px-2.5 py-1 text-xs font-semibold ring-1 ${risk.ring} ${risk.text}`}>
            <span className={`size-2 rounded-full ${risk.bar}`} aria-hidden />
            {risk.label}
          </div>
          <h2 className="mt-3 text-xl font-semibold tracking-tight sm:text-2xl">{r.verdict}</h2>
          <p className="mt-1 truncate font-mono text-sm text-slate-600" title={r.url}>{r.host}</p>
          {redirected && (
            <p className="mt-1 truncate text-sm text-slate-600" title={r.final_url ?? ""}>
              Redirects to <span className="font-mono">{r.final_url}</span>
            </p>
          )}
        </div>
        <div className="shrink-0 sm:text-right">
          <div className="flex items-baseline gap-1 sm:justify-end">
            <span className={`text-4xl font-semibold tabular-nums ${risk.text}`}>{score}</span>
            <span className="text-sm text-slate-500">/ 100 risk</span>
          </div>
          <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-white sm:w-44" aria-hidden>
            <div className={`h-full rounded-full ${risk.bar}`} style={{ width: `${Math.max(score, 2)}%` }} />
          </div>
        </div>
      </div>

      <div className="grid gap-px bg-slate-200 lg:grid-cols-[1.4fr_1fr]">
        {/* Findings */}
        <section className="bg-white p-5 sm:p-6">
          <h3 className="text-sm font-semibold">What we found</h3>
          {r.signals.length === 0 ? (
            <p className="mt-3 text-sm text-slate-600">No warning signs in the address, the domain records or the reputation feeds.</p>
          ) : (
            <ul className="mt-3 divide-y divide-slate-100">
              {r.signals.map((s) => {
                const sev = SEVERITY[s.severity] ?? SEVERITY.low;
                return (
                  <li key={s.id} className="flex gap-3 py-3 first:pt-1">
                    <span className={`mt-1.5 size-2 shrink-0 rounded-full ${sev.dot}`} aria-hidden />
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-baseline gap-x-2">
                        <span className="text-sm font-medium">{s.title}</span>
                        <span className={`text-xs ${sev.text}`}>{s.confirmed ? "Confirmed" : sev.label}</span>
                      </div>
                      <p className="mt-0.5 text-sm leading-relaxed text-slate-600 break-words">{s.detail}</p>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </section>

        {/* Sources */}
        <section className="bg-white p-5 sm:p-6">
          <h3 className="text-sm font-semibold">Checks</h3>
          <dl className="mt-3 space-y-2.5 text-sm">
            {rows.map((row) => (
              <div key={row.name} className="flex items-baseline justify-between gap-4">
                <dt className="shrink-0 text-slate-500">{row.name}</dt>
                <dd className={`text-right ${TONE[row.tone]}`}>{row.value}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>

      {/* Advice */}
      <div className="border-t border-slate-200 bg-slate-50 px-5 py-4 sm:px-6">
        <p className="text-sm leading-relaxed text-slate-700">
          <span className="font-medium text-ink">What to do: </span>
          {r.recommendation}
        </p>
      </div>

      <details className="group border-t border-slate-200 px-5 py-3 text-sm sm:px-6">
        <summary className="flex cursor-pointer list-none items-center justify-between text-slate-500 hover:text-ink">
          <span>Raw API response · analyzed in {(r.analysis_ms / 1000).toFixed(1)}s</span>
          <span className="text-xs group-open:hidden">Show</span>
          <span className="hidden text-xs group-open:inline">Hide</span>
        </summary>
        <div className="relative mt-3">
          <button
            type="button"
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(r, null, 2)).then(() => {
                setCopied(true);
                setTimeout(() => setCopied(false), 1500);
              });
            }}
            className="absolute right-2 top-2 rounded-md bg-white/10 px-2 py-1 text-xs text-slate-300 hover:bg-white/20"
          >
            {copied ? "Copied" : "Copy"}
          </button>
          <pre className="max-h-96 overflow-auto rounded-lg bg-ink p-4 font-mono text-xs leading-relaxed text-slate-200">
            {JSON.stringify(r, null, 2)}
          </pre>
        </div>
      </details>
    </article>
  );
}
