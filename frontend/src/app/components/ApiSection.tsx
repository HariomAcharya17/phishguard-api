"use client";

import { useState, useSyncExternalStore } from "react";

type Lang = "curl" | "javascript" | "python";

function snippets(origin: string): Record<Lang, string> {
  return {
    curl: `curl -X POST ${origin}/api/check-url \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: pg_your_key" \\
  -d '{"url": "http://paypa1.com/login"}'`,
    javascript: `const res = await fetch("${origin}/api/check-url", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": process.env.PHISHGUARD_KEY,
  },
  body: JSON.stringify({ url: "http://paypa1.com/login" }),
});
const { risk_level, risk_score, signals } = await res.json();`,
    python: `import requests

r = requests.post(
    "${origin}/api/check-url",
    headers={"X-API-Key": PHISHGUARD_KEY},
    json={"url": "http://paypa1.com/login"},
    timeout=15,
)
result = r.json()
print(result["risk_level"], result["risk_score"])`,
  };
}

const RESPONSE = `{
  "risk_level": "critical",
  "risk_score": 0.84,
  "is_safe": false,
  "verdict": "Phishing or malicious. Do not open.",
  "signals": [
    {
      "id": "lookalike_domain",
      "severity": "critical",
      "title": "Look-alike of \\"paypal\\"",
      "detail": "\\"paypa1\\" uses look-alike characters. ..."
    }
  ],
  "domain_age_days": 12,
  "final_url": "http://paypa1.com/webscr?cmd=_login",
  "checks": { "virustotal": { ... }, "whois": { ... } }
}`;

const FIELDS: [string, string][] = [
  ["risk_level", "safe, low, medium, high or critical"],
  ["risk_score", "0 to 1. Confirmed listings are at least 0.95"],
  ["signals", "Every finding, strongest first, with a human-readable title and detail"],
  ["checks", "Status of each source, e.g. VirusTotal engine counts or why a source was skipped"],
  ["final_url", "Where the link ends up after redirects"],
  ["domain_age_days", "Days since registration, or null if unknown"],
];

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={() => navigator.clipboard.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); })}
      className="rounded-md px-2 py-1 text-xs text-slate-400 hover:bg-white/10 hover:text-white"
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

function KeyForm() {
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [message, setMessage] = useState("");
  const [key, setKey] = useState("");

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setState("loading");
    try {
      const res = await fetch("/api/auth/signup", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json().catch(() => null);
      if (!res.ok) throw new Error(data?.detail || "Couldn't create a key. Try again.");
      setKey(data.api_key);
      setState("done");
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Couldn't create a key. Try again.");
      setState("error");
    }
  }

  if (state === "done") {
    return (
      <div className="rounded-xl border border-green-200 bg-green-50 p-5">
        <p className="text-sm font-medium text-green-900">Your API key</p>
        <div className="mt-2 flex items-center gap-2 rounded-lg bg-white p-2 ring-1 ring-green-200">
          <code className="min-w-0 flex-1 truncate px-1 font-mono text-sm">{key}</code>
          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(key)}
            className="rounded-md bg-ink px-3 py-1.5 text-xs font-medium text-white hover:bg-slate-800"
          >
            Copy
          </button>
        </div>
        <p className="mt-2 text-xs text-green-900/80">Save it now. For security, it won&apos;t be shown again.</p>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="rounded-xl border border-slate-200 p-5">
      <label htmlFor="email" className="text-sm font-medium">Get a free API key</label>
      <p className="mt-1 text-sm text-slate-600">100 checks a day. No credit card.</p>
      <div className="mt-4 flex flex-col gap-2 sm:flex-row">
        <input
          id="email"
          type="email"
          required
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="you@company.com"
          className="min-w-0 flex-1 rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-brand focus:ring-2 focus:ring-brand/20"
        />
        <button
          type="submit"
          disabled={state === "loading"}
          className="rounded-lg bg-ink px-4 py-2 text-sm font-medium text-white hover:bg-slate-800 disabled:opacity-60"
        >
          {state === "loading" ? "Creating…" : "Create key"}
        </button>
      </div>
      {state === "error" && <p role="alert" className="mt-2 text-sm text-red-700">{message}</p>}
    </form>
  );
}

export default function ApiSection() {
  const [lang, setLang] = useState<Lang>("curl");
  // Real origin on the client, a placeholder during server rendering.
  const origin = useSyncExternalStore(
    () => () => {},
    () => window.location.origin,
    () => "https://your-deployment.vercel.app",
  );
  const code = snippets(origin)[lang];

  return (
    <section id="api" className="scroll-mt-8 border-t border-slate-200 bg-slate-50/60 py-20 sm:py-24">
      <div className="mx-auto grid max-w-6xl gap-12 px-4 sm:px-6 lg:grid-cols-[1fr_1.2fr]">
        <div>
          <p className="text-sm font-medium text-brand">API</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Add link checks to your product</h2>
          <p className="mt-4 leading-relaxed text-slate-600">
            One endpoint returns the verdict, the score and every finding with an explanation you can show to users.
            Use it in a mail filter, a chat bot or a support tool.
          </p>
          <div className="mt-8">
            <KeyForm />
          </div>
          <p className="mt-4 text-sm text-slate-600">
            No key? You can make up to 10 checks a minute without one. Full reference at{" "}
            <a href="/api/docs" className="font-medium text-brand hover:underline">/api/docs</a>.
          </p>
        </div>

        <div className="min-w-0 space-y-6">
          <div className="overflow-hidden rounded-xl bg-ink shadow-xl shadow-slate-900/10">
            <div className="flex items-center justify-between border-b border-white/10 px-3">
              <div className="flex" role="tablist" aria-label="Code language">
                {(["curl", "javascript", "python"] as Lang[]).map((l) => (
                  <button
                    key={l}
                    role="tab"
                    aria-selected={lang === l}
                    onClick={() => setLang(l)}
                    className={`border-b-2 px-3 py-3 text-xs font-medium ${lang === l ? "border-white text-white" : "border-transparent text-slate-400 hover:text-slate-200"}`}
                  >
                    {l === "curl" ? "cURL" : l === "javascript" ? "JavaScript" : "Python"}
                  </button>
                ))}
              </div>
              <CopyButton text={code} />
            </div>
            <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed text-slate-200"><code>{code}</code></pre>
          </div>

          <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
            <div className="border-b border-slate-200 px-4 py-2.5 text-xs font-medium text-slate-500">Response (abridged)</div>
            <pre className="overflow-x-auto p-4 font-mono text-[12.5px] leading-relaxed text-slate-700"><code>{RESPONSE}</code></pre>
          </div>

          <dl className="divide-y divide-slate-200 rounded-xl border border-slate-200 bg-white text-sm">
            {FIELDS.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[9rem_1fr] gap-4 px-4 py-2.5">
                <dt className="font-mono text-[13px]">{k}</dt>
                <dd className="text-slate-600">{v}</dd>
              </div>
            ))}
          </dl>
        </div>
      </div>
    </section>
  );
}
