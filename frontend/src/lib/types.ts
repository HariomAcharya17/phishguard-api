export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Signal {
  id: string;
  layer: "reputation" | "url" | "domain" | "ml";
  title: string;
  detail: string;
  weight: number;
  severity: Severity;
  confirmed: boolean;
}

export interface SourceCheck {
  status?: string;
  [key: string]: unknown;
}

export interface CheckResult {
  url: string;
  input: string;
  host: string;
  registrable_domain: string | null;
  is_safe: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  verdict: string;
  recommendation: string;
  confirmed_malicious: boolean;
  signals: Signal[];
  threats_detected: string[];
  ml_score: number | null;
  domain_age_days: number | null;
  domain_created: string | null;
  final_url: string | null;
  well_known_domain: boolean;
  brands_detected: string[];
  checks: Record<string, SourceCheck>;
  breakdown: Record<"blacklist" | "pattern" | "domain" | "ml", { score: number; threats: string[]; description: string }>;
  analysis_ms: number;
}

export const RISK: Record<RiskLevel, { label: string; text: string; bg: string; ring: string; bar: string }> = {
  safe: { label: "Safe", text: "text-risk-safe", bg: "bg-green-50", ring: "ring-green-200", bar: "bg-risk-safe" },
  low: { label: "Low risk", text: "text-risk-low", bg: "bg-lime-50", ring: "ring-lime-200", bar: "bg-risk-low" },
  medium: { label: "Suspicious", text: "text-risk-medium", bg: "bg-amber-50", ring: "ring-amber-200", bar: "bg-risk-medium" },
  high: { label: "High risk", text: "text-risk-high", bg: "bg-orange-50", ring: "ring-orange-200", bar: "bg-risk-high" },
  critical: { label: "Dangerous", text: "text-risk-critical", bg: "bg-red-50", ring: "ring-red-200", bar: "bg-risk-critical" },
};

export const SEVERITY: Record<Severity, { label: string; dot: string; text: string }> = {
  critical: { label: "Critical", dot: "bg-risk-critical", text: "text-risk-critical" },
  high: { label: "High", dot: "bg-risk-high", text: "text-risk-high" },
  medium: { label: "Medium", dot: "bg-risk-medium", text: "text-risk-medium" },
  low: { label: "Low", dot: "bg-slate-400", text: "text-slate-500" },
  info: { label: "Info", dot: "bg-slate-300", text: "text-slate-500" },
};
