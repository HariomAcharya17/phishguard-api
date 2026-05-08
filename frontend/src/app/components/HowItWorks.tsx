"use client";

import { motion } from "framer-motion";

const LAYERS = [
  {
    num: "01", title: "VirusTotal Blacklist",
    desc: "Cross-references 90+ antivirus engines and threat databases in real-time. Any engine flagging the URL immediately elevates the risk score.",
    color: "#ef4444", tag: "blacklist", weight: "35%",
    icon: (
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
        <path d="M10 2L3 5.5v5c0 3.87 2.97 7.5 7 8.5 4.03-1 7-4.63 7-8.5v-5L10 2Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round"/>
      </svg>
    ),
  },
  {
    num: "02", title: "Pattern Analysis",
    desc: "Regex heuristics detect brand impersonation, IP-as-hostname, typosquatting, excessive subdomains, and hex-encoded redirects.",
    color: "#f59e0b", tag: "pattern", weight: "20%",
    icon: (
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
        <circle cx="8" cy="8" r="5" stroke="currentColor" strokeWidth="1.5"/>
        <path d="m13 13 4 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    num: "03", title: "Domain Intelligence",
    desc: "WHOIS lookup checks registration age. Domains under 30 days, unknown registrars, and missing creation records are strong phishing signals.",
    color: "#f97316", tag: "domain", weight: "10%",
    icon: (
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
        <circle cx="10" cy="10" r="7" stroke="currentColor" strokeWidth="1.5"/>
        <path d="M10 3c-2 2.5-2 11.5 0 14M3 10h14" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
  {
    num: "04", title: "ML Model — Random Forest",
    desc: "Trained on 11,000+ labeled URLs with 30+ engineered features. 86.72% accuracy. Final arbitrator when other signals are inconclusive.",
    color: "#4f46e5", tag: "ml", weight: "35%",
    icon: (
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
        <rect x="3" y="3" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.5"/>
        <rect x="12" y="3" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.5"/>
        <rect x="7.5" y="12" width="5" height="5" rx="1" stroke="currentColor" strokeWidth="1.5"/>
        <path d="M5.5 8v2.5H10M14.5 8v2.5H10M10 10.5V12" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
      </svg>
    ),
  },
];

function ConnectorLine() {
  return (
    <div style={{ display: "flex", justifyContent: "center", height: 28 }}>
      <div style={{ width: 1, background: "linear-gradient(to bottom, rgba(79,70,229,0.2), rgba(79,70,229,0.04))" }} />
    </div>
  );
}

export default function HowItWorks() {
  return (
    <section style={{ maxWidth: 820, margin: "0 auto", padding: "0 20px 120px" }}>
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-60px" }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] as any }}
        style={{ textAlign: "center", marginBottom: 60 }}
      >
        <div className="mono" style={{ fontSize: "0.65rem", letterSpacing: "0.25em", textTransform: "uppercase", color: "#4f46e5", marginBottom: 16 }}>
          // architecture
        </div>
        <h2 style={{ fontSize: "clamp(1.8rem, 5vw, 3rem)", fontWeight: 900, letterSpacing: "-1.5px", color: "var(--text)" }}>
          4 Detection Layers
        </h2>
        <p style={{ color: "rgba(15,14,23,0.44)", marginTop: 12, fontSize: "0.9rem", maxWidth: 420, margin: "12px auto 0", fontFamily: "'Inter', sans-serif", lineHeight: 1.7 }}>
          Every URL passes through all layers simultaneously. Scores are weighted and aggregated into a final verdict.
        </p>
      </motion.div>

      {/* Input pill */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        style={{ display: "flex", justifyContent: "center" }}
      >
        <div className="mono" style={{
          padding: "9px 22px",
          background: "#ffffff",
          border: "1px solid rgba(0,0,0,0.09)",
          borderRadius: 100, fontSize: "0.72rem",
          color: "rgba(15,14,23,0.38)",
          display: "flex", alignItems: "center", gap: 8,
          boxShadow: "0 2px 8px rgba(0,0,0,0.05)",
        }}>
          <span style={{ opacity: 0.5 }}>⌘</span> Input URL
        </div>
      </motion.div>

      <ConnectorLine />

      {LAYERS.map((layer, i) => (
        <div key={layer.num}>
          <motion.div
            initial={{ opacity: 0, x: i % 2 === 0 ? -20 : 20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-40px" }}
            transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] as any }}
          >
            <motion.div
              whileHover={{ scale: 1.012, boxShadow: `0 8px 36px rgba(0,0,0,0.09), 0 0 0 1.5px ${layer.color}22` }}
              transition={{ duration: 0.2 }}
              style={{
                maxWidth: 600, margin: "0 auto",
                background: "#ffffff",
                border: `1px solid rgba(0,0,0,0.07)`,
                borderRadius: 18, padding: "20px 24px",
                display: "flex", alignItems: "flex-start", gap: 16,
                cursor: "default",
                boxShadow: "0 2px 12px rgba(0,0,0,0.05)",
              }}
            >
              <div className="mono" style={{ fontSize: "0.58rem", color: layer.color, opacity: 0.45, letterSpacing: "0.15em", paddingTop: 5, flexShrink: 0, width: 22 }}>
                {layer.num}
              </div>
              <div style={{
                width: 42, height: 42, borderRadius: 11,
                background: `${layer.color}10`,
                border: `1px solid ${layer.color}20`,
                display: "flex", alignItems: "center", justifyContent: "center",
                color: layer.color, flexShrink: 0,
              }}>
                {layer.icon}
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 800, fontSize: "0.95rem", marginBottom: 6, color: "var(--text)" }}>{layer.title}</div>
                <div style={{ fontSize: "0.82rem", color: "rgba(15,14,23,0.45)", lineHeight: 1.65, fontFamily: "'Inter', sans-serif" }}>{layer.desc}</div>
              </div>
              <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 5, flexShrink: 0 }}>
                <span className="mono" style={{
                  fontSize: "0.6rem", color: layer.color,
                  background: `${layer.color}0e`, border: `1px solid ${layer.color}20`,
                  padding: "2px 9px", borderRadius: 100,
                }}>
                  {layer.tag}
                </span>
                <span className="mono" style={{ fontSize: "0.6rem", color: "rgba(15,14,23,0.25)" }}>
                  {layer.weight}
                </span>
              </div>
            </motion.div>
          </motion.div>

          {i < LAYERS.length - 1 ? <ConnectorLine /> : (
            <>
              <ConnectorLine />
              <motion.div
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                style={{ display: "flex", justifyContent: "center" }}
              >
                <div style={{
                  padding: "13px 32px",
                  background: "#0f0e17",
                  border: "1px solid rgba(0,0,0,0.12)",
                  borderRadius: 100, fontWeight: 800,
                  color: "#ffffff", fontSize: "0.88rem",
                  letterSpacing: "-0.3px",
                  boxShadow: "0 4px 20px rgba(0,0,0,0.18)",
                }}>
                  Final Weighted Risk Score
                </div>
              </motion.div>
            </>
          )}
        </div>
      ))}
    </section>
  );
}