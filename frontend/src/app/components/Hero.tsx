"use client";

import { motion, useMotionValue, useSpring, useTransform, Variants } from "framer-motion";
import { useEffect, useRef } from "react";

const container: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.11, delayChildren: 0.05 } },
};
const item: Variants = {
  hidden: { opacity: 0, y: 28 },
  show: { opacity: 1, y: 0, transition: { duration: 0.75, ease: [0.22, 1, 0.36, 1] } },
};

export default function Hero() {
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);
  const smoothX = useSpring(mouseX, { stiffness: 40, damping: 18 });
  const smoothY = useSpring(mouseY, { stiffness: 40, damping: 18 });
  const rotateX = useTransform(smoothY, [-400, 400], [3, -3]);
  const rotateY = useTransform(smoothX, [-400, 400], [-3, 3]);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      const rect = ref.current?.getBoundingClientRect();
      if (!rect) return;
      mouseX.set(e.clientX - rect.left - rect.width / 2);
      mouseY.set(e.clientY - rect.top - rect.height / 2);
    };
    window.addEventListener("mousemove", handler);
    return () => window.removeEventListener("mousemove", handler);
  }, [mouseX, mouseY]);

  return (
    <section
      ref={ref}
      style={{
        position: "relative",
        minHeight: "100vh",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        textAlign: "center",
        padding: "120px 24px 80px",
        overflow: "hidden",
      }}
    >
      {/* Subtle grid pattern */}
      <div style={{
        position: "absolute", inset: 0, zIndex: 0, opacity: 0.018,
        backgroundImage: `url("data:image/svg+xml,%3Csvg width='40' height='40' viewBox='0 0 40 40' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%230f0e17' fill-opacity='1'%3E%3Cpath d='M0 0h1v40H0zM40 0h-1v40h1zM0 0v1h40V0zM0 40v-1h40v1z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`,
        backgroundRepeat: "repeat",
        backgroundSize: "40px",
        pointerEvents: "none",
      }} />

      {/* Content */}
      <motion.div
        variants={container}
        initial="hidden"
        animate="show"
        style={{ position: "relative", zIndex: 1, maxWidth: 720 }}
      >
        {/* Live badge */}
        <motion.div variants={item} style={{ display: "flex", justifyContent: "center", marginBottom: 36 }}>
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 8,
            background: "rgba(79,70,229,0.06)",
            border: "1px solid rgba(79,70,229,0.15)",
            borderRadius: 100, padding: "8px 20px",
            backdropFilter: "blur(12px)",
          }}>
            <motion.div
              animate={{ opacity: [1, 0.2, 1] }}
              transition={{ duration: 1.6, repeat: Infinity }}
              style={{ width: 6, height: 6, borderRadius: "50%", background: "#10b981" }}
            />
            <span className="mono" style={{
              fontSize: "0.65rem", letterSpacing: "0.2em",
              textTransform: "uppercase", color: "rgba(79,70,229,0.65)",
            }}>
              4-Layer Security Pipeline · Live
            </span>
          </div>
        </motion.div>

        {/* Headline */}
        <motion.h1
          variants={item}
          style={{
            fontSize: "clamp(3.5rem, 10vw, 7.5rem)",
            fontWeight: 900,
            lineHeight: 0.92,
            letterSpacing: "-4px",
            marginBottom: 32,
          }}
        >
          <span style={{
            display: "block",
            background: "linear-gradient(135deg, #0f0e17 10%, #1e1b4b 60%, #4f46e5 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}>
            Phish
          </span>
          <span style={{
            display: "block",
            background: "linear-gradient(135deg, #4f46e5 0%, #7c3aed 50%, #a78bfa 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
          }}>
            Guard
          </span>
        </motion.h1>

        {/* Tagline */}
        <motion.p
          variants={item}
          style={{
            fontSize: "clamp(0.95rem, 2vw, 1.15rem)",
            color: "rgba(15,14,23,0.5)",
            lineHeight: 1.8,
            maxWidth: 480,
            margin: "0 auto 52px",
            fontFamily: "'Inter', sans-serif",
            fontWeight: 400,
          }}
        >
          Detect phishing URLs instantly — powered by VirusTotal,
          pattern heuristics, domain intelligence &amp; a trained
          Random Forest classifier.
        </motion.p>

        {/* Stats row */}
        <motion.div
          variants={item}
          style={{
            display: "flex", gap: "clamp(28px, 6vw, 72px)",
            justifyContent: "center", flexWrap: "wrap",
            marginBottom: 56,
          }}
        >
          {[
            { val: "86.72%", label: "ML Accuracy", color: "#4f46e5" },
            { val: "4", label: "Detection Layers", color: "#f97316" },
            { val: "< 1s", label: "Response Time", color: "#10b981" },
          ].map((s) => (
            <motion.div
              key={s.label}
              whileHover={{ y: -4 }}
              style={{ textAlign: "center" }}
            >
              <div className="mono" style={{
                fontSize: "clamp(1.8rem, 4vw, 2.6rem)",
                fontWeight: 500,
                color: s.color,
                letterSpacing: "-1px",
              }}>
                {s.val}
              </div>
              <div style={{
                fontSize: "0.68rem", textTransform: "uppercase",
                letterSpacing: "0.16em", color: "rgba(15,14,23,0.35)",
                marginTop: 6, fontFamily: "'Inter', sans-serif",
              }}>
                {s.label}
              </div>
            </motion.div>
          ))}
        </motion.div>

        {/* CTA */}
        <motion.div variants={item} style={{ display: "flex", gap: 14, justifyContent: "center", flexWrap: "wrap" }}>
          <motion.a
            href="#checker"
            className="glow-btn"
            whileTap={{ scale: 0.96 }}
            style={{
              display: "inline-flex", alignItems: "center", gap: 10,
              textDecoration: "none",
              fontFamily: "'Plus Jakarta Sans', sans-serif",
            }}
          >
            Check a URL
            <svg width="15" height="15" viewBox="0 0 15 15" fill="none">
              <path d="M2 7.5h11M9 3.5l4 4-4 4" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </motion.a>
          <motion.a
            href="#api"
            className="ghost-btn"
            whileTap={{ scale: 0.96 }}
            style={{
              display: "inline-flex", alignItems: "center", gap: 8,
              textDecoration: "none",
              fontFamily: "'Plus Jakarta Sans', sans-serif",
            }}
          >
            View API Docs
          </motion.a>
        </motion.div>
      </motion.div>

      {/* Scroll indicator */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 2, duration: 0.6 }}
        style={{
          position: "absolute", bottom: 32,
          display: "flex", flexDirection: "column",
          alignItems: "center", gap: 8,
        }}
      >
        <span className="mono" style={{ fontSize: "0.55rem", letterSpacing: "0.22em", textTransform: "uppercase", color: "rgba(15,14,23,0.2)" }}>scroll</span>
        <motion.div
          animate={{ scaleY: [1, 0.3, 1], opacity: [0.3, 0.8, 0.3] }}
          transition={{ duration: 2.2, repeat: Infinity, ease: "easeInOut" }}
          style={{ width: 1, height: 32, background: "linear-gradient(to bottom, rgba(79,70,229,0.4), transparent)" }}
        />
      </motion.div>
    </section>
  );
}