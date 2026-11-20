const LAYERS = [
  {
    n: "01",
    title: "Reputation feeds",
    body: "The link and its domain are looked up in VirusTotal (90+ security vendors), Google Safe Browsing and the OpenPhish feed of active phishing pages. A confirmed listing always produces a Dangerous verdict.",
  },
  {
    n: "02",
    title: "Address analysis",
    body: "Rules catch the tricks phishing links rely on: brand names on someone else's domain, look-alike spellings (paypa1, g00gle), letters from other alphabets, brand names hidden in subdomains, text before an @, raw or disguised IP addresses, free hosting and tunnels, and risky downloads.",
  },
  {
    n: "03",
    title: "Domain records",
    body: "We check when the domain was registered (most phishing domains are days old), whether it resolves, whether the final page uses HTTPS, and where the link really ends up after redirects and shorteners.",
  },
  {
    n: "04",
    title: "Hostname model",
    body: "A gradient-boosted tree model scores the shape of the hostname: length, character mix, randomness and domain ending. It was trained on 219,000 hostnames from the PhiUSIIL dataset and reaches a ROC AUC of 0.88 on domains it never saw.",
  },
];

export default function HowItWorks() {
  return (
    <section id="how" className="scroll-mt-8 border-t border-slate-200 py-20 sm:py-24">
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-2xl">
          <p className="text-sm font-medium text-brand">How it works</p>
          <h2 className="mt-2 text-3xl font-semibold tracking-tight sm:text-4xl">Four independent checks, one verdict</h2>
          <p className="mt-4 leading-relaxed text-slate-600">
            Blocklists miss phishing pages that are only hours old. The address and domain records rarely lie, so
            PhishGuard combines both. Each finding adds evidence, and every warning is explained in plain language.
          </p>
        </div>

        <ol className="mt-12 grid gap-px overflow-hidden rounded-xl border border-slate-200 bg-slate-200 sm:grid-cols-2">
          {LAYERS.map((l) => (
            <li key={l.n} className="bg-white p-6 sm:p-8">
              <span className="font-mono text-sm text-slate-400">{l.n}</span>
              <h3 className="mt-3 text-lg font-semibold">{l.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-600">{l.body}</p>
            </li>
          ))}
        </ol>

        <div className="mt-10 grid gap-6 rounded-xl bg-slate-50 p-6 sm:grid-cols-3 sm:p-8">
          <div>
            <div className="text-sm font-semibold">How the score works</div>
            <p className="mt-1.5 text-sm leading-relaxed text-slate-600">
              Each finding has a weight. Independent findings reinforce each other, so two medium warnings outweigh one,
              but many weak hints can&apos;t add up to a false alarm on their own.
            </p>
          </div>
          <div>
            <div className="text-sm font-semibold">Well-known sites</div>
            <p className="mt-1.5 text-sm leading-relaxed text-slate-600">
              A bank&apos;s own login page says &ldquo;login&rdquo;. On established domains, address rules count far less,
              while reputation feeds still apply in full.
            </p>
          </div>
          <div>
            <div className="text-sm font-semibold">Limits</div>
            <p className="mt-1.5 text-sm leading-relaxed text-slate-600">
              A hacked but otherwise normal website can host a phishing page with a clean-looking address. Treat
              &ldquo;Safe&rdquo; as &ldquo;no warning signs found&rdquo;, not as a guarantee.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
}
