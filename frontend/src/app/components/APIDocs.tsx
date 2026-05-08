"use client";

import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";

// ─── VS Code "One Dark Pro" inspired token colours ───────────────────────────
const C = {
  keyword:   "#c678dd",   // purple  – curl, -X, -H, -d, POST
  method:    "#61afef",   // blue    – command / function names
  string:    "#98c379",   // green   – quoted strings
  number:    "#d19a66",   // orange  – numbers, booleans
  key:       "#e06c75",   // red     – JSON keys
  punctuation:"#abb2bf",  // grey    – braces, brackets, commas, colons
  comment:   "#5c6370",   // dim grey
  plain:     "#abb2bf",   // default text
  url:       "#56b6c2",   // cyan    – URLs / paths
  bool:      "#d19a66",   // orange  – true / false
};

// ─── Typed token stream ───────────────────────────────────────────────────────
type Token = { text: string; color: string };
type Line  = Token[];

// ─── cURL token lines ─────────────────────────────────────────────────────────
const CURL_LINES: Line[] = [
  [
    { text: "curl",         color: C.keyword },
    { text: " -X ",        color: C.plain },
    { text: "POST",         color: C.method },
    { text: " http://127.0.0.1:8000/api/check-url", color: C.url },
    { text: " \\",         color: C.punctuation },
  ],
  [
    { text: "  -H ",        color: C.plain },
    { text: '"Content-Type: application/json"', color: C.string },
    { text: " \\",         color: C.punctuation },
  ],
  [
    { text: "  -d ",        color: C.plain },
    { text: "'",            color: C.string },
    { text: "{",            color: C.punctuation },
    { text: '"url"',        color: C.key },
    { text: ": ",           color: C.punctuation },
    { text: '"http://suspicious-site.xyz"', color: C.string },
    { text: "}",            color: C.punctuation },
    { text: "'",            color: C.string },
  ],
];

// ─── JSON response token lines ────────────────────────────────────────────────
const JSON_LINES: Line[] = [
  [{ text: "{", color: C.punctuation }],
  [{ text: '  "url"',            color: C.key },  { text: ": ", color: C.punctuation }, { text: '"http://suspicious-site.xyz"', color: C.string }, { text: ",", color: C.punctuation }],
  [{ text: '  "is_safe"',        color: C.key },  { text: ": ", color: C.punctuation }, { text: "false",  color: C.bool },   { text: ",", color: C.punctuation }],
  [{ text: '  "risk_score"',     color: C.key },  { text: ": ", color: C.punctuation }, { text: "0.87",   color: C.number }, { text: ",", color: C.punctuation }],
  [{ text: '  "risk_level"',     color: C.key },  { text: ": ", color: C.punctuation }, { text: '"critical"', color: C.string }, { text: ",", color: C.punctuation }],
  [{ text: '  "threats_detected"', color: C.key }, { text: ": [", color: C.punctuation }],
  [{ text: '    "virustotal_malicious"', color: C.string }, { text: ",", color: C.punctuation }],
  [{ text: '    "suspicious_tld"',       color: C.string }, { text: ",", color: C.punctuation }],
  [{ text: '    "very_young_domain"',    color: C.string }],
  [{ text: "  ],", color: C.punctuation }],
  [{ text: '  "recommendation"', color: C.key }, { text: ": ", color: C.punctuation }, { text: '"dangerous — phishing likely"', color: C.string }, { text: ",", color: C.punctuation }],
  [{ text: '  "breakdown"', color: C.key }, { text: ": {", color: C.punctuation }],
  [{ text: '    "blacklist_score"', color: C.key }, { text: ": ", color: C.punctuation }, { text: "0.90", color: C.number }, { text: ",", color: C.punctuation }],
  [{ text: '    "pattern_score"',  color: C.key }, { text: ": ", color: C.punctuation }, { text: "0.75", color: C.number }, { text: ",", color: C.punctuation }],
  [{ text: '    "domain_score"',   color: C.key }, { text: ": ", color: C.punctuation }, { text: "0.80", color: C.number }, { text: ",", color: C.punctuation }],
  [{ text: '    "ml_score"',       color: C.key }, { text: ": ", color: C.punctuation }, { text: "0.91", color: C.number }],
  [{ text: "  },", color: C.punctuation }],
  [{ text: '  "domain_age_days"', color: C.key }, { text: ": ", color: C.punctuation }, { text: "12", color: C.number }, { text: ",", color: C.punctuation }],
  [{ text: '  "ml_score"',        color: C.key }, { text: ": ", color: C.punctuation }, { text: "0.91", color: C.number }],
  [{ text: "}", color: C.punctuation }],
];

// ─── raw strings for clipboard copy ─────────────────────────────────────────
const CURL_RAW = `curl -X POST http://127.0.0.1:8000/api/check-url \\
  -H "Content-Type: application/json" \\
  -d '{"url": "http://suspicious-site.xyz"}'`;

const RESPONSE_RAW = `{
  "url": "http://suspicious-site.xyz",
  "is_safe": false,
  "risk_score": 0.87,
  "risk_level": "critical",
  "threats_detected": [
    "virustotal_malicious",
    "suspicious_tld",
    "very_young_domain"
  ],
  "recommendation": "dangerous — phishing likely",
  "breakdown": {
    "blacklist_score": 0.90,
    "pattern_score": 0.75,
    "domain_score": 0.80,
    "ml_score": 0.91
  },
  "domain_age_days": 12,
  "ml_score": 0.91
}`;

// ─── VS Code window dots ──────────────────────────────────────────────────────
function WindowDots() {
  return (
    <div style={{ display: "flex", gap: 6, alignItems: "center" }}>
      {[["#ff5f57","#febc2e","#28c840"]].flat().map((c, i) => (
        <div key={i} style={{ width: 12, height: 12, borderRadius: "50%", background: c }} />
      ))}
    </div>
  );
}

// ─── Highlighted Code Block ───────────────────────────────────────────────────
function VSCodeBlock({
  label, lines, rawCode, icon
}: {
  label: string; lines: Line[]; rawCode: string; icon?: string;
}) {
  const [copied, setCopied] = useState(false);
  function doCopy() {
    navigator.clipboard.writeText(rawCode).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ duration: 0.5 }}
      style={{
        background: "#1e1e2e",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 16,
        overflow: "hidden",
        marginBottom: 18,
        boxShadow: "0 8px 40px rgba(0,0,0,0.22), 0 2px 8px rgba(0,0,0,0.14)",
      }}
    >
      {/* Title bar */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "10px 16px",
        background: "#181825",
        borderBottom: "1px solid rgba(255,255,255,0.07)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <WindowDots />
          <span className="mono" style={{
            fontSize: "0.68rem", color: "rgba(205,214,244,0.45)",
            letterSpacing: "0.06em",
          }}>
            {icon && <span style={{ marginRight: 6 }}>{icon}</span>}
            {label}
          </span>
        </div>
        <motion.button
          onClick={doCopy}
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.94 }}
          style={{
            display: "flex", alignItems: "center", gap: 6,
            background: copied ? "rgba(166,227,161,0.12)" : "rgba(205,214,244,0.07)",
            border: copied ? "1px solid rgba(166,227,161,0.3)" : "1px solid rgba(205,214,244,0.12)",
            borderRadius: 8, padding: "5px 13px",
            color: copied ? "#a6e3a1" : "rgba(205,214,244,0.4)",
            fontSize: "0.68rem", fontFamily: "'DM Mono', monospace",
            cursor: "pointer", transition: "all 0.2s",
          }}
        >
          <AnimatePresence mode="wait">
            <motion.span
              key={copied ? "copied" : "copy"}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.14 }}
            >
              {copied ? "✓ Copied!" : "Copy"}
            </motion.span>
          </AnimatePresence>
        </motion.button>
      </div>

      {/* Code area */}
      <div style={{ display: "flex", overflowX: "auto" }}>
        {/* Line numbers gutter */}
        <div style={{
          padding: "18px 0",
          minWidth: 44,
          textAlign: "right",
          borderRight: "1px solid rgba(255,255,255,0.05)",
          background: "#1e1e2e",
          userSelect: "none",
        }}>
          {lines.map((_, i) => (
            <div key={i} style={{
              padding: "0 14px 0 8px",
              lineHeight: "1.85",
              fontSize: "0.72rem",
              fontFamily: "'DM Mono', monospace",
              color: "rgba(205,214,244,0.18)",
            }}>
              {i + 1}
            </div>
          ))}
        </div>

        {/* Token lines */}
        <div style={{ padding: "18px 20px", flex: 1 }}>
          {lines.map((line, i) => (
            <div key={i} style={{ lineHeight: "1.85", whiteSpace: "pre", minHeight: "1.85em" }}>
              {line.map((token, j) => (
                <span key={j} style={{
                  color: token.color,
                  fontFamily: "'DM Mono', monospace",
                  fontSize: "0.8rem",
                }}>
                  {token.text}
                </span>
              ))}
            </div>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ─── Response fields ──────────────────────────────────────────────────────────
const FIELDS = [
  { f: "is_safe",          t: "boolean",   d: "False if URL is classified as phishing" },
  { f: "risk_score",       t: "float 0–1", d: "Weighted aggregate across all 4 layers" },
  { f: "risk_level",       t: "string",    d: "safe / low / medium / high / critical" },
  { f: "threats_detected", t: "string[]",  d: "Threat signal identifiers found" },
  { f: "breakdown",        t: "object",    d: "Per-layer scores: blacklist, pattern, domain, ml" },
  { f: "domain_age_days",  t: "integer",   d: "Domain age in days, null if unknown" },
  { f: "ml_score",         t: "float 0–1", d: "ML classifier confidence (phishing probability)" },
  { f: "recommendation",   t: "string",    d: "Action guidance based on risk level" },
];

// ─── Main component ───────────────────────────────────────────────────────────
export default function APIDocs() {
  return (
    <section id="api" style={{ maxWidth: 700, margin: "0 auto", padding: "0 20px 120px" }}>
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-60px" }}
        transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
        style={{ textAlign: "center", marginBottom: 52 }}
      >
        <div className="mono" style={{ fontSize: "0.65rem", letterSpacing: "0.25em", textTransform: "uppercase", color: "#4f46e5", marginBottom: 16 }}>
          // api reference
        </div>
        <h2 style={{ fontSize: "clamp(1.8rem, 5vw, 3rem)", fontWeight: 900, letterSpacing: "-1.5px", color: "var(--text)" }}>
          Try the API Yourself
        </h2>
        <p style={{ color: "rgba(15,14,23,0.44)", marginTop: 12, fontSize: "0.9rem", fontFamily: "'Inter', sans-serif" }}>
          One endpoint. Send a URL, get a full threat analysis.
        </p>
      </motion.div>

      {/* Endpoint badge */}
      <motion.div
        initial={{ opacity: 0, x: -14 }}
        whileInView={{ opacity: 1, x: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.5 }}
        style={{
          display: "flex", alignItems: "center", gap: 12,
          padding: "12px 18px",
          background: "#1e1e2e",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 12, marginBottom: 20, flexWrap: "wrap",
          boxShadow: "0 4px 20px rgba(0,0,0,0.14)",
        }}
      >
        <span className="mono" style={{
          background: "#c678dd", color: "#1e1e2e",
          padding: "4px 13px", borderRadius: 7, fontSize: "0.72rem",
          fontWeight: 800, letterSpacing: "0.12em",
        }}>
          POST
        </span>
        <span className="mono" style={{ fontSize: "0.84rem", color: "#61afef" }}>
          /api/check-url
        </span>
        <span style={{ marginLeft: "auto", fontSize: "0.68rem", color: "rgba(205,214,244,0.3)", fontFamily: "'DM Mono', monospace" }}>
          Content-Type: application/json
        </span>
      </motion.div>

      {/* VS Code blocks */}
      <VSCodeBlock
        label="request.sh"
        icon="$"
        lines={CURL_LINES}
        rawCode={CURL_RAW}
      />
      <VSCodeBlock
        label="response.json"
        icon="{}"
        lines={JSON_LINES}
        rawCode={RESPONSE_RAW}
      />

      {/* Response fields table */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6 }}
        style={{ marginTop: 28 }}
      >
        <div className="mono" style={{
          fontSize: "0.6rem", textTransform: "uppercase",
          letterSpacing: "0.18em", color: "rgba(15,14,23,0.28)",
          marginBottom: 14,
        }}>
          Response Fields
        </div>
        <div style={{
          background: "#1e1e2e",
          border: "1px solid rgba(255,255,255,0.07)",
          borderRadius: 16, overflow: "hidden",
          boxShadow: "0 4px 20px rgba(0,0,0,0.14)",
        }}>
          {FIELDS.map((row, i) => (
            <motion.div
              key={row.f}
              initial={{ opacity: 0 }}
              whileInView={{ opacity: 1 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.04 }}
              whileHover={{ background: "rgba(205,214,244,0.04)" }}
              style={{
                display: "grid",
                gridTemplateColumns: "170px 90px 1fr",
                padding: "12px 20px",
                borderTop: i > 0 ? "1px solid rgba(255,255,255,0.05)" : "none",
                alignItems: "center", gap: 10,
                transition: "background 0.15s",
              }}
            >
              <span className="mono" style={{ fontSize: "0.76rem", color: C.key }}>{row.f}</span>
              <span className="mono" style={{ fontSize: "0.66rem", color: C.comment }}>{row.t}</span>
              <span style={{ fontSize: "0.8rem", color: "rgba(205,214,244,0.65)", fontFamily: "'Inter', sans-serif" }}>{row.d}</span>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </section>
  );
}