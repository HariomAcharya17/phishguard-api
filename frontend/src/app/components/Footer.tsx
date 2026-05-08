"use client";

import { motion, useMotionValue, useSpring, useTransform } from "framer-motion";
import { useRef } from "react";

const LINKS = [
  { label: "GitHub",    href: "https://github.com/" },
  { label: "Portfolio", href: "#" },
  { label: "Contact",   href: "mailto:hariom@example.com" },
];

const STACK = [
  { name: "FastAPI",       color: "#10b981" },
  { name: "scikit-learn",  color: "#f97316" },
  { name: "Next.js 14",    color: "#0f0e17" },
  { name: "Framer Motion", color: "#ec4899" },
  { name: "Vercel",        color: "#64748b" },
  { name: "VirusTotal",    color: "#4f46e5" },
];

function WaterName() {
  const ref = useRef<HTMLDivElement>(null);
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const smoothX = useSpring(mouseX, { stiffness: 80, damping: 10 });
  const smoothY = useSpring(mouseY, { stiffness: 80, damping: 10 });
  const rotateX = useTransform(smoothY, [-40, 40], [8, -8]);
  const rotateY = useTransform(smoothX, [-80, 80], [-8, 8]);
  const skewX   = useTransform(smoothX, [-80, 80], [-2.5, 2.5]);
  const scaleY  = useTransform(smoothY, [-40, 40], [0.97, 1.03]);

  function onMove(e: React.MouseEvent<HTMLDivElement>) {
    const rect = ref.current?.getBoundingClientRect();
    if (!rect) return;
    mouseX.set(e.clientX - rect.left - rect.width / 2);
    mouseY.set(e.clientY - rect.top - rect.height / 2);
  }
  function onLeave() { mouseX.set(0); mouseY.set(0); }

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={onLeave}
      style={{ display: "inline-block", cursor: "default", perspective: 600 }}
    >
      <motion.span
        style={{
          display: "inline-block",
          rotateX, rotateY, skewX, scaleY,
          fontWeight: 900,
          fontSize: "2.8rem",
          letterSpacing: "-2px",
          lineHeight: 1,
          background: "linear-gradient(135deg, #0f0e17 0%, #1e1b4b 40%, #4f46e5 100%)",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent",
          backgroundClip: "text",
          fontFamily: "'Epilogue', sans-serif",
          transformStyle: "preserve-3d",
        }}
      >
        Hariom Acharya
      </motion.span>
    </motion.div>
  );
}

export default function Footer() {
  return (
    <footer style={{
      borderTop: "1px solid rgba(0,0,0,0.07)",
      padding: "80px 24px 56px",
      position: "relative",
      overflow: "hidden",
      background: "#f8f9fc",
    }}>
      {/* Soft indigo glow behind footer */}
      <div style={{
        position: "absolute", bottom: 0, left: "50%",
        transform: "translateX(-50%)",
        width: 600, height: 300,
        background: "radial-gradient(ellipse, rgba(79,70,229,0.07) 0%, transparent 70%)",
        pointerEvents: "none", filter: "blur(30px)",
      }} />

      <div style={{ maxWidth: 800, margin: "0 auto", position: "relative", zIndex: 1 }}>

        {/* Top: branding */}
        <div style={{ textAlign: "center", marginBottom: 48 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 10,
            marginBottom: 28,
          }}>
            <div style={{
              width: 36, height: 36, borderRadius: 9,
              background: "rgba(79,70,229,0.08)",
              border: "1px solid rgba(79,70,229,0.16)",
              display: "flex", alignItems: "center", justifyContent: "center",
            }}>
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 1.5L2 4.5v4c0 2.8 2.2 5.4 6 6.3 3.8-.9 6-3.5 6-6.3v-4L8 1.5Z"
                  stroke="#4f46e5" strokeWidth="1.2" strokeLinejoin="round"
                  fill="rgba(79,70,229,0.10)" />
                <path d="M5.5 8l2 1.5 3-3"
                  stroke="#4f46e5" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </div>
            <span style={{
              fontSize: "1.1rem", fontWeight: 800,
              letterSpacing: "-0.5px", color: "var(--text)",
            }}>
              PhishGuard API
            </span>
          </div>

          <div style={{
            fontSize: "0.72rem", color: "rgba(15,14,23,0.35)",
            letterSpacing: "0.12em", textTransform: "uppercase",
            fontFamily: "'Inter', sans-serif", marginBottom: 20,
          }}>
            Designed &amp; built by
          </div>

          <WaterName />

          <p style={{
            marginTop: 16, fontSize: "0.88rem",
            color: "rgba(15,14,23,0.42)",
            fontFamily: "'Inter', sans-serif",
            lineHeight: 1.7, maxWidth: 400, margin: "16px auto 0",
          }}>
            A full-stack security project combining ML, threat intelligence APIs,
            and modern web engineering.
          </p>
        </div>

        {/* Stack pills */}
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "center", gap: 10, marginBottom: 40 }}>
          {STACK.map((s) => (
            <motion.span
              key={s.name}
              whileHover={{ y: -2, boxShadow: `0 6px 20px rgba(0,0,0,0.10), 0 0 0 1.5px ${s.color}30` }}
              transition={{ duration: 0.18 }}
              style={{
                display: "inline-flex", alignItems: "center", gap: 7,
                fontFamily: "'Plus Jakarta Sans', sans-serif",
                fontSize: "0.82rem",
                fontWeight: 600,
                color: "rgba(15,14,23,0.72)",
                background: "#ffffff",
                border: "1.5px solid rgba(0,0,0,0.09)",
                padding: "8px 16px", borderRadius: 100,
                letterSpacing: "-0.01em",
                boxShadow: "0 2px 8px rgba(0,0,0,0.06)",
                cursor: "default",
              }}
            >
              <span style={{ width: 8, height: 8, borderRadius: "50%", background: s.color, display: "inline-block", flexShrink: 0, boxShadow: `0 0 6px ${s.color}80` }} />
              {s.name}
            </motion.span>
          ))}
        </div>

        {/* Bottom copyright */}
        <div style={{
          textAlign: "center",
          paddingTop: 24,
          borderTop: "1px solid rgba(0,0,0,0.06)",
        }}>
          <span className="mono" style={{ fontSize: "0.62rem", color: "rgba(15,14,23,0.18)", letterSpacing: "0.1em" }}>
            © 2026 PhishGuard · All rights reserved
          </span>
        </div>
      </div>
    </footer>
  );
}