import Hero from "./components/Hero";
import URLChecker from "./components/URLChecker";
import HowItWorks from "./components/HowItWorks";
import BuildStory from "./components/BuildStory";
import APIDocs from "./components/APIDocs";
import Footer from "./components/Footer";
import SplashCursor from "./components/SplashCursor";


export default function Home() {
  return (
    <main style={{ position: "relative", zIndex: 1, overflowX: "hidden" }}>
      <SplashCursor />
      <div className="blob-mid" />   {/* ← third teal blob */}
      <Hero />
      <div className="section-divider" style={{ margin: "0 auto 80px" }} />
      <URLChecker />
      <div className="section-divider" style={{ margin: "0 auto 80px" }} />
      <HowItWorks />
      <div className="section-divider" style={{ margin: "0 auto 80px" }} />
      <BuildStory />
      <div className="section-divider" style={{ margin: "0 auto 80px" }} />
      <APIDocs />
      <Footer />
    </main>
  );
}