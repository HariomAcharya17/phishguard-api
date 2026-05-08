"use client";

import { useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckResult, RISK, RiskLevel } from "@/lib/types";

const PHASES = [
  "Initializing scan pipeline...",
  "Querying threat intelligence...",
  "Analyzing domain signatures...",
  "Running classifier inference...",
  "Aggregating risk vectors...",
];

function AnalysisLayer({ label, score, color, delay = 0, icon, desc }: {
  label: string; score: number; color: string; delay?: number; icon: React.ReactNode; desc: string;
}) {
  const status = score > 0.7 ? "CRITICAL" : score > 0.3 ? "SUSPICIOUS" : "CLEAN";
  const statusColor = score > 0.7 ? "#ef4444" : score > 0.3 ? "#f59e0b" : "#10b981";

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.5, delay }}
      style={{
        padding: "20px",
        background: "rgba(0,0,0,0.012)",
        border: "1px solid rgba(0,0,0,0.05)",
        borderRadius: 16,
        display: "flex",
        flexDirection: "column",
        gap: 14,
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div style={{ display: "flex", gap: 12 }}>
          <div style={{ 
            width: 36, height: 36, borderRadius: 10, 
            background: `${color}10`, color: color,
            display: "flex", alignItems: "center", justifyContent: "center"
          }}>
            {icon}
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            <span className="mono" style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text)", letterSpacing: "0.02em" }}>
              {label}
            </span>
            <p style={{ fontSize: "0.62rem", color: "rgba(15,14,23,0.4)", lineHeight: 1.4, maxWidth: "180px" }}>
              {desc}
            </p>
          </div>
        </div>
        <div style={{
          fontSize: "0.55rem", fontWeight: 900,
          padding: "3px 8px", borderRadius: 6,
          background: `${statusColor}15`, color: statusColor,
          border: `1px solid ${statusColor}30`,
          letterSpacing: "0.08em",
        }}>
          {status}
        </div>
      </div>

      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ flex: 1, height: 5, background: "rgba(0,0,0,0.06)", borderRadius: 99, overflow: "hidden" }}>
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${score * 100}%` }}
            transition={{ duration: 1.2, delay: delay + 0.2, ease: [0.22, 1, 0.36, 1] as any }}
            style={{
              height: "100%", background: color,
              boxShadow: score > 0.3 ? `0 0 12px ${color}40` : "none",
            }}
          />
        </div>
        <span className="mono" style={{ fontSize: "0.8rem", fontWeight: 600, color: "var(--text)", minWidth: "30px", textAlign: "right" }}>
          {(score * 100).toFixed(0)}%
        </span>
      </div>
    </motion.div>
  );
}

function RiskMeter({ score, color }: { score: number; color: string }) {
  const pct = score * 100;
  const r = 52;
  const circ = 2 * Math.PI * r;
  return (
    <div style={{ position: "relative", width: 120, height: 120, flexShrink: 0 }}>
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r={r} fill="none" stroke="rgba(0,0,0,0.06)" strokeWidth="6" />
        <motion.circle
          cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={`${circ}`}
          initial={{ strokeDashoffset: circ }}
          animate={{ strokeDashoffset: circ - (circ * pct / 100) }}
          transition={{ duration: 1.2, ease: [0.22, 1, 0.36, 1] as any }}
          style={{ transform: "rotate(-90deg)", transformOrigin: "60px 60px", filter: `drop-shadow(0 0 6px ${color}60)` }}
        />
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center" }}>
        <div className="mono" style={{ fontSize: "1.8rem", fontWeight: 500, color, lineHeight: 1 }}>
          {pct.toFixed(0)}
        </div>
        <div style={{ fontSize: "0.6rem", color: "rgba(15,14,23,0.3)", marginTop: 4, letterSpacing: "0.12em", textTransform: "uppercase", fontFamily: "'Inter', sans-serif" }}>
          Risk
        </div>
      </div>
    </div>
  );
}

function MetricCell({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div style={{
      padding: "16px 20px",
      background: "rgba(0,0,0,0.02)",
      border: "1px solid rgba(0,0,0,0.06)",
      borderRadius: 12,
    }}>
      <div style={{ fontSize: "0.62rem", color: "rgba(15,14,23,0.35)", letterSpacing: "0.14em", textTransform: "uppercase", fontFamily: "'Inter', sans-serif", marginBottom: 8 }}>
        {label}
      </div>
      <div className="mono" style={{ fontSize: "1rem", fontWeight: 500, color: accent || "rgba(15,14,23,0.8)" }}>
        {value}
      </div>
    </div>
  );
}

export default function URLChecker() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [phaseIdx, setPhaseIdx] = useState(0);
  const [result, setResult] = useState<CheckResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [focused, setFocused] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  async function handleCheck() {
    let trimmed = url.trim();
    if (!trimmed || loading) return;
    if (!trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      trimmed = "http://" + trimmed;
    }
    setLoading(true);
    setResult(null);
    setError(null);
    setPhaseIdx(0);
    let idx = 0;
    intervalRef.current = setInterval(() => {
      idx = Math.min(idx + 1, PHASES.length - 1);
      setPhaseIdx(idx);
    }, 900);
    try {
      const res = await fetch("/api/check-url", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });
      clearInterval(intervalRef.current!);
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err?.error || `Server responded with ${res.status}`);
      }
      const data: CheckResult = await res.json();
      setResult(data);
    } catch (e: unknown) {
      clearInterval(intervalRef.current!);
      setError(e instanceof Error ? e.message : "Unknown error occurred");
    } finally {
      setLoading(false);
    }
  }

  const cfg = result ? RISK[result.risk_level as RiskLevel] ?? RISK.safe : null;

  return (
    <section id="checker" style={{ maxWidth: 780, margin: "0 auto", padding: "0 20px 120px" }}>
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] as any }}
        style={{ textAlign: "center", marginBottom: 44 }}
      >
        <div className="mono" style={{ fontSize: "0.65rem", letterSpacing: "0.25em", textTransform: "uppercase", color: "#4f46e5", marginBottom: 16 }}>
          // threat scanner
        </div>
        <h2 style={{ fontSize: "clamp(2rem, 5vw, 3.2rem)", fontWeight: 900, letterSpacing: "-2px", color: "var(--text)" }}>
          Analyze Any URL
        </h2>
        <p style={{ color: "rgba(15,14,23,0.45)", marginTop: 12, fontSize: "0.9rem", fontFamily: "'Inter', sans-serif" }}>
          Multi-layer threat detection in under a second.
        </p>
      </motion.div>

      {/* Input */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6 }}
        style={{
          background: "#ffffff",
          border: focused ? "1.5px solid rgba(79,70,229,0.5)" : "1.5px solid rgba(0,0,0,0.10)",
          borderRadius: 18,
          padding: "6px 6px 6px 20px",
          display: "flex",
          alignItems: "center",
          gap: 12,
          transition: "border-color 0.2s, box-shadow 0.2s",
          boxShadow: focused ? "0 0 0 3px rgba(79,70,229,0.08), 0 2px 12px rgba(0,0,0,0.06)" : "0 2px 12px rgba(0,0,0,0.05)",
        }}
      >
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" style={{ flexShrink: 0, opacity: 0.3 }}>
          <path d="M6.5 2a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9ZM1 6.5a5.5 5.5 0 1 1 9.9 3.293l3.154 3.153a.5.5 0 0 1-.707.708L10.19 10.5A5.5 5.5 0 0 1 1 6.5Z" fill="currentColor"/>
        </svg>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleCheck()}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder="Paste a suspicious URL to analyze..."
          style={{
            flex: 1, border: "none", outline: "none",
            background: "transparent",
            fontSize: "0.92rem", color: "rgba(15,14,23,0.8)",
            padding: "13px 0",
            fontFamily: "'DM Mono', monospace",
          }}
        />
        <motion.button
          onClick={handleCheck}
          disabled={loading || !url.trim()}
          className="glow-btn"
          whileTap={{ scale: 0.96 }}
          style={{
            opacity: !url.trim() ? 0.45 : 1,
            whiteSpace: "nowrap",
            display: "flex", alignItems: "center", gap: 8,
          }}
        >
          {loading ? (
            <>
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 0.7, repeat: Infinity, ease: "linear" }}
                style={{ width: 13, height: 13, border: "1.5px solid rgba(255,255,255,0.35)", borderTopColor: "white", borderRadius: "50%" }}
              />
              Scanning
            </>
          ) : "Analyze"}
        </motion.button>
      </motion.div>

      {/* Loading phase */}
      <AnimatePresence>
        {loading && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{ 
              marginTop: 24, 
              padding: "20px", 
              borderRadius: 16, 
              background: "rgba(79,70,229,0.03)", 
              border: "1px solid rgba(79,70,229,0.1)",
              display: "flex",
              flexDirection: "column",
              gap: 12
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <span className="mono" style={{ fontSize: "0.7rem", color: "#4f46e5", fontWeight: 600, letterSpacing: "0.05em" }}>
                {PHASES[phaseIdx]}
              </span>
              <span className="mono" style={{ fontSize: "0.7rem", color: "rgba(15,14,23,0.3)" }}>
                {Math.round(((phaseIdx + 1) / PHASES.length) * 100)}%
              </span>
            </div>
            <div style={{ height: 4, background: "rgba(0,0,0,0.05)", borderRadius: 99, overflow: "hidden" }}>
              <motion.div 
                animate={{ width: `${((phaseIdx + 1) / PHASES.length) * 100}%` }}
                transition={{ duration: 0.8, ease: "circOut" }}
                style={{ height: "100%", background: "#4f46e5", boxShadow: "0 0 10px rgba(79,70,229,0.3)" }}
              />
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Error */}
      <AnimatePresence>
        {error && (
          <motion.div
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            style={{
              marginTop: 16, padding: "14px 18px",
              borderRadius: 12,
              background: "rgba(239,68,68,0.06)",
              border: "1px solid rgba(239,68,68,0.18)",
              color: "#dc2626", fontSize: "0.85rem",
              fontFamily: "'DM Mono', monospace",
            }}
          >
            ⚠ {error}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Result Card */}
      <AnimatePresence>
        {result && cfg && (
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] as any }}
            style={{
              marginTop: 24,
              background: "#ffffff",
              borderRadius: 22,
              overflow: "hidden",
              border: `1px solid rgba(0,0,0,0.07)`,
              boxShadow: `0 4px 40px ${cfg.color}14, 0 2px 12px rgba(0,0,0,0.06)`,
            }}
          >
            {/* Top strip - verdict */}
            <div style={{
              padding: "28px 32px",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              gap: 20,
              borderBottom: "1px solid rgba(0,0,0,0.06)",
              background: `linear-gradient(135deg, ${cfg.color}07, transparent)`,
            }}>
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                  <div style={{
                    width: 8, height: 8, borderRadius: "50%", background: cfg.color,
                    boxShadow: `0 0 8px ${cfg.color}80`,
                  }} />
                  <span className="mono" style={{ fontSize: "0.62rem", color: cfg.color, letterSpacing: "0.18em", textTransform: "uppercase" }}>
                    {result.risk_level}
                  </span>
                </div>
                <div style={{ fontSize: "1.9rem", fontWeight: 900, letterSpacing: "-1px", color: cfg.color }}>
                  {cfg.label}
                </div>
                <div style={{ marginTop: 6, color: "rgba(15,14,23,0.45)", fontSize: "0.85rem", fontFamily: "'Inter', sans-serif" }}>
                  {result.recommendation}
                </div>
              </div>
              <RiskMeter score={result.risk_score} color={cfg.color} />
            </div>

            {/* URL display */}
            <div style={{ padding: "20px 32px", borderBottom: "1px solid rgba(0,0,0,0.05)" }}>
              <div style={{ fontSize: "0.58rem", color: "rgba(15,14,23,0.28)", letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 8, fontFamily: "'Inter', sans-serif" }}>
                Analyzed Target
              </div>
              <div className="mono" style={{ fontSize: "0.82rem", color: "rgba(15,14,23,0.55)", wordBreak: "break-all", lineHeight: 1.5 }}>
                {result.url}
              </div>
            </div>

            {/* Metrics grid */}
            <div style={{ padding: "20px 32px", borderBottom: "1px solid rgba(0,0,0,0.05)" }}>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))", gap: 10 }}>
                <MetricCell label="ML Score" value={`${((result.ml_score ?? 0) * 100).toFixed(1)}%`} accent="#4f46e5" />
                <MetricCell label="Risk Score" value={`${(result.risk_score * 100).toFixed(1)}%`} accent={cfg.color} />
                <MetricCell
                  label="Domain Age"
                  value={result.domain_age_days != null ? `${result.domain_age_days}d` : "Unknown"}
                  accent={result.domain_age_days != null && result.domain_age_days < 90 ? "#f97316" : "rgba(15,14,23,0.6)"}
                />
                <MetricCell
                  label="Threats"
                  value={`${result.threats_detected?.length ?? 0} signals`}
                  accent={(result.threats_detected?.length ?? 0) > 0 ? "#ef4444" : "#10b981"}
                />
              </div>
            </div>

            {/* Detection breakdown */}
            {result.breakdown && (
              <div style={{ padding: "24px 32px", borderBottom: "1px solid rgba(0,0,0,0.05)" }}>
                <div style={{ fontSize: "0.6rem", color: "rgba(15,14,23,0.28)", letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 18, fontFamily: "'Inter', sans-serif" }}>
                   Detection Breakdown
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16 }}>
                  <AnalysisLayer 
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>} 
                    label="Threat Registry" 
                    desc="Cross-references global databases for known malicious signatures and reports."
                    score={result.breakdown.blacklist_score} 
                    color="#ef4444" 
                    delay={0} 
                  />
                  <AnalysisLayer 
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>} 
                    label="Heuristic Analysis" 
                    desc="Examines URL structure and character distribution for obfuscation patterns."
                    score={result.breakdown.pattern_score} 
                    color="#f59e0b" 
                    delay={0.1} 
                  />
                  <AnalysisLayer 
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>} 
                    label="Entity Reputation" 
                    desc="Evaluates domain age, SSL status, and historical registrar reliability."
                    score={result.breakdown.domain_score} 
                    color="#f97316" 
                    delay={0.2} 
                  />
                  <AnalysisLayer 
                    icon={<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2a10 10 0 1 0 10 10A10 10 0 0 0 12 2zm0 18a8 8 0 1 1 8-8 8 8 0 0 1-8 8z"/><path d="M12 6a6 6 0 1 0 6 6 6 6 0 0 0-6-6zm0 10a4 4 0 1 1 4-4 4 4 0 0 1-4 4z"/></svg>} 
                    label="Neural Intelligence" 
                    desc="Deep-learning classifier trained on millions of samples for zero-day detection."
                    score={result.breakdown.ml_score} 
                    color="#4f46e5" 
                    delay={0.3} 
                  />
                </div>
              </div>
            )}

            {/* Threat signals */}
            {result.threats_detected?.length > 0 && (
              <div style={{ padding: "20px 32px" }}>
                <div style={{ fontSize: "0.6rem", color: "rgba(15,14,23,0.28)", letterSpacing: "0.14em", textTransform: "uppercase", marginBottom: 14, fontFamily: "'Inter', sans-serif" }}>
                  Signals Detected
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                  {result.threats_detected.map((t) => (
                    <motion.div
                      key={t}
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      style={{
                        background: "rgba(239,68,68,0.06)",
                        border: "1px solid rgba(239,68,68,0.16)",
                        color: "#dc2626",
                        padding: "6px 14px",
                        borderRadius: 999,
                        fontSize: "0.72rem",
                        fontFamily: "'DM Mono', monospace",
                        letterSpacing: "0.03em",
                      }}
                    >
                      {t.replace(/_/g, " ")}
                    </motion.div>
                  ))}
                </div>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </section>
  );
}