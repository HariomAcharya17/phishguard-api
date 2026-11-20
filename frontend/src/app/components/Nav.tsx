export const REPO_URL = "https://github.com/HariomAcharya17/phishguard-api";

export function Logo({ className = "" }: { className?: string }) {
  return (
    <span className={`inline-flex items-center gap-2 font-semibold tracking-tight ${className}`}>
      <svg viewBox="0 0 32 32" className="size-7" aria-hidden>
        <rect width="32" height="32" rx="8" fill="#1d4ed8" />
        <path d="M16 6.5 8.5 9.5v6c0 4.6 3.1 8.6 7.5 10 4.4-1.4 7.5-5.4 7.5-10v-6L16 6.5Z" fill="none" stroke="#fff" strokeWidth="2" strokeLinejoin="round" />
        <path d="m12.5 16 2.5 2.5 4.5-5" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      PhishGuard
    </span>
  );
}

export default function Nav() {
  return (
    <header className="absolute inset-x-0 top-0 z-20">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <a href="#" className="text-white" aria-label="PhishGuard home">
          <Logo />
        </a>
        <nav className="flex items-center gap-1 text-sm">
          <a href="#how" className="hidden rounded-md px-3 py-2 text-slate-300 hover:text-white sm:block">How it works</a>
          <a href="#api" className="hidden rounded-md px-3 py-2 text-slate-300 hover:text-white sm:block">API</a>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className="rounded-md px-3 py-2 text-slate-300 hover:text-white">GitHub</a>
          <a href="#api" className="ml-1 rounded-md bg-white px-3 py-1.5 font-medium text-ink hover:bg-slate-100">Get an API key</a>
        </nav>
      </div>
    </header>
  );
}
