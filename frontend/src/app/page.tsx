import Nav from "./components/Nav";
import Checker from "./components/Checker";
import HowItWorks from "./components/HowItWorks";
import ApiSection from "./components/ApiSection";
import Footer from "./components/Footer";

export default function Home() {
  return (
    <>
      <Nav />
      <main>
        <Checker />
        <HowItWorks />
        <ApiSection />
      </main>
      <Footer />
    </>
  );
}
