"use client";

import { motion } from "framer-motion";

const STORY = [
  {
    title: "The Problem",
    body: "Phishing attacks cause over $1.8B in losses annually. Blocklists alone can't keep up — attackers spin up new domains in seconds. I wanted to build a layered detector that doesn't rely solely on known-bad lists.",
    color: "#ef4444",
  },
  {
    title: "Architecture",
    body: "FastAPI backend with async-native design. All 4 detection layers run independently — blacklist, pattern, domain, ML — and their scores are weighted and aggregated. Each layer is isolated and independently testable.",
    color: "#f97316",
  },
  {
    title: "ML Training",
    body: "Trained a Random Forest on 11,000+ URLs from the UCI Phishing Websites dataset. Engineered 30+ features: URL length, subdomain depth, digit ratio, HTTPS presence, domain age, TLD rarity. Final model: 86.72% accuracy.",
    color: "#4f46e5",
  },
  {
    title: "Challenges",
    body: "VirusTotal rate limits required caching and graceful degradation. WHOIS lookups were unreliable across TLDs — added fallbacks. Balancing speed vs. thoroughness was the hardest tradeoff.",
    color: "#f59e0b",
  },
  {
    title: "What I Learned",
    body: "Ensemble detection is far more robust than any single signal. Feature engineering matters more than model selection for URL-structured data. Building for failure — timeouts, bad data, unavailable APIs — separates demos from real systems.",
    color: "#10b981",
  },
];

const STACK = [
  { name: "FastAPI",        role: "Backend API",    color: "#10b981" },
  { name: "scikit-learn",   role: "ML Model",       color: "#f97316" },
  { name: "Random Forest",  role: "Classifier",     color: "#4f46e5" },
  { name: "VirusTotal API", role: "Blacklist Layer", color: "#ef4444" },
  { name: "python-whois",   role: "Domain Intel",   color: "#f59e0b" },
  { name: "Next.js 14",     role: "Frontend",       color: "#0f0e17" },
  { name: "Framer Motion",  role: "Animations",     color: "#ec4899" },
  { name: "Vercel",         role: "Deployment",     color: "#64748b" },
];

export default function BuildStory() {
  return (
    <section style={{ maxWidth: 700, margin: "0 auto", padding: "0 20px 120px" }}>
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-60px" }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] as any }}
        style={{ textAlign: "center", marginBottom: 64 }}
      >
        <div className="mono" style={{ fontSize: "0.65rem", letterSpacing: "0.25em", textTransform: "uppercase", color: "#4f46e5", marginBottom: 16 }}>
          // case study
        </div>
        <h2 style={{ fontSize: "clamp(1.8rem, 5vw, 3rem)", fontWeight: 900, letterSpacing: "-1.5px", color: "var(--text)" }}>
          How I Built This
        </h2>
      </motion.div>

      {/* Timeline */}
      <div>
        {STORY.map((item, i) => (
          <motion.div
            key={item.title}
            initial={{ opacity: 0, x: -16 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true, margin: "-40px" }}
            transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] as any, delay: i * 0.04 }}
            style={{ display: "grid", gridTemplateColumns: "48px 1fr", gap: "0 18px" }}
          >
            {/* Spine */}
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div style={{
                width: 36, height: 36, borderRadius: "50%",
                background: `${item.color}0e`,
                border: `1px solid ${item.color}25`,
                display: "flex", alignItems: "center", justifyContent: "center",
                flexShrink: 0,
              }}>
                <div style={{ width: 7, height: 7, borderRadius: "50%", background: item.color, boxShadow: `0 0 8px ${item.color}80` }} />
              </div>
              {i < STORY.length - 1 && (
                <div style={{ flex: 1, width: 1, background: `linear-gradient(to bottom, ${item.color}18, rgba(79,70,229,0.05))`, marginTop: 6, minHeight: 28 }} />
              )}
            </div>

            {/* Content */}
            <div style={{ paddingBottom: 40 }}>
              <h3 style={{ fontWeight: 800, fontSize: "1rem", marginBottom: 10, marginTop: 6, color: "var(--text)" }}>
                {item.title}
              </h3>
              <p style={{ color: "rgba(15,14,23,0.44)", fontSize: "0.86rem", lineHeight: 1.8, fontFamily: "'Inter', sans-serif" }}>
                {item.body}
              </p>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Tech Stack */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6 }}
        style={{
          marginTop: 16, padding: "26px",
          background: "#ffffff",
          border: "1px solid rgba(0,0,0,0.07)",
          borderRadius: 18,
          boxShadow: "0 2px 16px rgba(0,0,0,0.05)",
        }}
      >
        <div className="mono" style={{ fontSize: "0.6rem", textTransform: "uppercase", letterSpacing: "0.15em", color: "rgba(15,14,23,0.28)", marginBottom: 20 }}>
          Tech Stack
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(145px, 1fr))", gap: 10 }}>
          {STACK.map((s) => (
            <motion.div
              key={s.name}
              whileHover={{
                scale: 1.04,
                boxShadow: `0 8px 28px rgba(0,0,0,0.10), 0 0 0 1.5px ${s.color}28`,
                y: -2,
              }}
              transition={{ duration: 0.18 }}
              style={{
                padding: "14px 16px",
                background: "rgba(0,0,0,0.02)",
                border: "1px solid rgba(0,0,0,0.07)",
                borderRadius: 12, cursor: "default",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                <span style={{
                  width: 9, height: 9, borderRadius: "50%",
                  background: s.color, display: "inline-block",
                  boxShadow: `0 0 7px ${s.color}90`,
                  flexShrink: 0,
                }} />
                <div style={{ fontWeight: 700, fontSize: "0.9rem", color: "var(--text)" }}>{s.name}</div>
              </div>
              <div style={{ fontSize: "0.72rem", color: "rgba(15,14,23,0.38)", fontFamily: "'Inter', sans-serif", paddingLeft: 17 }}>{s.role}</div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </section>
  );
}