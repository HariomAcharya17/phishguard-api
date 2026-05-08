export type RiskLevel = "safe" | "low" | "medium" | "high" | "critical";

export interface CheckResult {
  url: string;
  is_phishing: boolean;
  risk_score: number;
  risk_level: RiskLevel;
  threats_detected: string[];
  recommendation: string;
  breakdown: {
    blacklist_score: number;
    pattern_score: number;
    domain_score: number;
    ml_score: number;
  };
  domain_age_days?: number;
  ml_confidence?: number;
  ml_score?: number;
}

export const RISK = {
  safe:     { label: "SAFE",        color: "#22d3a5", glow: "rgba(34,211,165,0.25)",  icon: "✓"  },
  low:      { label: "LOW RISK",    color: "#a3e635", glow: "rgba(163,230,53,0.2)",   icon: "!"  },
  medium:   { label: "MEDIUM RISK", color: "#fbbf24", glow: "rgba(251,191,36,0.25)",  icon: "!!" },
  high:     { label: "HIGH RISK",   color: "#f97316", glow: "rgba(249,115,22,0.25)",  icon: "⚠"  },
  critical: { label: "CRITICAL",    color: "#ff4455", glow: "rgba(255,68,85,0.3)",    icon: "☠"  },
} as const;