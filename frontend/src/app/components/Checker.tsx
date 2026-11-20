"use client";

import { useEffect, useRef, useState } from "react";
import type { CheckResult } from "@/lib/types";
import ResultCard from "./ResultCard";

const EXAMPLES = [
  { label: "github.com", url: "https://github.com" },
  { label: "paypal-login-verify.xyz", url: "http://paypal-login-verify.xyz/account/update" },
  { label: "apple.com-id-verify.support", url: "https://apple.com-id-verify.support/signin" },
];

const STEPS = ["Checking reputation feeds", "Inspecting the address", "Looking up the domain", "Following redirects"];

export default function Checker() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!loading) return;
    const t = setInterval(() => setStep((s) => Math.min(s + 1, STEPS.length - 1)), 700);
    return () => clearInterval(t);
  }, [loading]);

  // Support shareable links: /?url=https://example.com runs the check on load.
  useEffect(() => {
    const shared = new URLSearchParams(window.location.search).get("url");
    if (shared) void check(shared);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function check(target: string) {
    const value = target.trim();
    if (!value || loading) return;
    setUrl(value);
    setStep(0);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: value }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        throw new Error(data?.detail || (res.status === 429 ? "Too many checks. Wait a minute and try again." : "The check failed. Try again."));
      }
      setResult(data as CheckResult);
      const share = new URL(window.location.href);
      share.searchParams.set("url", value);
      window.history.replaceState(null, "", share);
      requestAnimationFrame(() => resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (e) {
      setError(e instanceof Error && e.message !== "Failed to fetch" ? e.message : "Couldn't reach the server. Check your connection and try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      <section className="relative overflow-hidden bg-ink pb-24 pt-32 sm:pb-28 sm:pt-40">
        <div className="hero-grid pointer-events-none absolute inset-0" aria-hidden />
        <div className="relative mx-auto max-w-3xl px-4 text-center sm:px-6">
          <h1 className="text-4xl font-semibold tracking-tight text-white text-balance sm:text-5xl">
            Check a link before you open it
          </h1>
          <p className="mx-auto mt-4 max-w-2xl text-base leading-relaxed text-slate-300 text-pretty sm:text-lg">
            Paste a link from an email, SMS or chat. PhishGuard checks it against VirusTotal, Google Safe Browsing and
            OpenPhish, inspects the address for impersonation tricks, and looks up how old the domain is.
          </p>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              check(url);
            }}
            className="mx-auto mt-10 flex max-w-2xl flex-col gap-2 rounded-xl bg-white p-2 shadow-2xl shadow-black/30 sm:flex-row"
          >
            <label htmlFor="url" className="sr-only">Link to check</label>
            <input
              id="url"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="off"
              spellCheck={false}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/login"
              className="min-w-0 flex-1 rounded-lg px-3 py-3 font-mono text-[15px] text-ink outline-none placeholder:font-sans placeholder:text-slate-400"
            />
            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="inline-flex items-center justify-center gap-2 rounded-lg bg-brand px-5 py-3 text-sm font-medium text-white transition-colors hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading && <span className="size-4 animate-spin rounded-full border-2 border-white/40 border-t-white" aria-hidden />}
              {loading ? "Checking…" : "Check link"}
            </button>
          </form>

          <div className="mt-4 flex flex-wrap items-center justify-center gap-2 text-sm">
            <span className="text-slate-400">Try:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex.url}
                type="button"
                onClick={() => check(ex.url)}
                disabled={loading}
                className="rounded-full border border-white/15 px-3 py-1 font-mono text-[13px] text-slate-300 transition-colors hover:border-white/30 hover:text-white disabled:opacity-50"
              >
                {ex.label}
              </button>
            ))}
          </div>

          <p className="mt-6 text-xs text-slate-500">
            The link is never opened in your browser. Our server makes one request to see where it leads.
          </p>
          <p className="mt-10 text-xs uppercase tracking-wider text-slate-500">Checked against</p>
          <p className="mt-2 text-sm text-slate-300">VirusTotal · Google Safe Browsing · OpenPhish · WHOIS records</p>
        </div>
      </section>

      <div
        ref={resultRef}
        className={`relative z-10 mx-auto max-w-4xl scroll-mt-6 px-4 sm:px-6 ${loading || error || result ? "-mt-12 mb-20" : ""}`}
        aria-live="polite"
      >
        {loading && (
          <div className="animate-fade-up rounded-xl border border-slate-200 bg-white p-6 shadow-lg shadow-slate-900/5">
            <ul className="space-y-3 text-sm">
              {STEPS.map((s, i) => (
                <li key={s} className={`flex items-center gap-3 ${i > step ? "text-slate-400" : "text-ink"}`}>
                  {i < step ? (
                    <svg viewBox="0 0 16 16" className="size-4 text-risk-safe" aria-hidden><path d="m3.5 8.5 3 3 6-7" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" /></svg>
                  ) : i === step ? (
                    <span className="size-4 animate-spin rounded-full border-2 border-slate-200 border-t-brand" aria-hidden />
                  ) : (
                    <span className="size-4 rounded-full border-2 border-slate-200" aria-hidden />
                  )}
                  {s}
                </li>
              ))}
            </ul>
          </div>
        )}

        {error && !loading && (
          <div role="alert" className="animate-fade-up rounded-xl border border-red-200 bg-red-50 px-5 py-4 text-sm text-red-800 shadow-lg shadow-slate-900/5">
            {error}
          </div>
        )}

        {result && !loading && <ResultCard result={result} />}
      </div>
    </>
  );
}
