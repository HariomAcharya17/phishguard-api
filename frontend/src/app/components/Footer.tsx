import { Logo, REPO_URL } from "./Nav";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200">
      <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 py-10 sm:flex-row sm:justify-between sm:px-6">
        <div className="max-w-sm">
          <Logo className="text-ink" />
          <p className="mt-3 text-sm leading-relaxed text-slate-600">
            A phishing link checker and API. Built by Hariom Acharya.
          </p>
        </div>
        <div className="grid grid-cols-2 gap-x-12 gap-y-2 text-sm">
          <span className="font-medium">Product</span>
          <span className="font-medium">Project</span>
          <a href="#how" className="text-slate-600 hover:text-ink">How it works</a>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="text-slate-600 hover:text-ink">Source code</a>
          <a href="#api" className="text-slate-600 hover:text-ink">API</a>
          <a href={`${REPO_URL}/issues`} target="_blank" rel="noreferrer" className="text-slate-600 hover:text-ink">Report a problem</a>
        </div>
      </div>
      <div className="border-t border-slate-200">
        <p className="mx-auto max-w-6xl px-4 py-4 text-xs leading-relaxed text-slate-500 sm:px-6">
          © {new Date().getFullYear()} Hariom Acharya. Model trained on the PhiUSIIL Phishing URL Dataset (Prasad &amp; Chandra, 2023, UCI).
          Results are guidance, not a guarantee.
        </p>
      </div>
    </footer>
  );
}
