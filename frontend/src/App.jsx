import { useState } from "react";
import Navbar from "./components/Navbar";
import FileUpload from "./components/FileUpload";
import Results from "./components/Results";

const App = () => {
  const [analysisResult, setAnalysisResult] = useState(null);

  const handleFileUpload = (result) => {
    setAnalysisResult(result);
  };

  return (
    <div className="relative min-h-screen text-white bg-gradient-to-br from-[#000000] to-[#002101] overflow-hidden">
      {/* We can place a hero glow image here if you have it, absolutely positioned behind content */}
      {/* <img
        src="/assets/hero-glow.jpeg"
        alt="Glow"
        className="absolute inset-0 w-full h-full object-cover opacity-20 pointer-events-none"
      /> */}

      <div className="relative z-10">
        <Navbar />

        {/* Hero Section */}
        <div className="container mx-auto px-4 sm:px-8 pt-20 sm:pt-28 pb-16 flex flex-col items-center">
          <p className="text-green-400 text-sm sm:text-base uppercase tracking-wide font-semibold mb-3">
            Introducing PDFreak AI
          </p>

          <h1
            className="text-4xl sm:text-5xl font-semibold text-center text-transparent bg-clip-text 
                       bg-gradient-to-b from-[#3F524C] to-[#929D9A] leading-tight"
          >
            Smarter Scanning. Safer PDFs.
          </h1>

          <p className="text-gray-300 text-center mt-4 max-w-3xl leading-relaxed">
            PDFreak AI blends cutting-edge AI and threat intel to detect
            malicious PDFs with precision. Scan, analyze, and understand hidden
            threats — instantly.
          </p>
        </div>

        {/* Upload Section */}
        <div className="container mx-auto px-4 sm:px-8 pb-16 flex flex-col items-center">
          <FileUpload onFileUpload={handleFileUpload} />

          <p className="text-gray-400 text-xs sm:text-sm mt-4 max-w-md text-center leading-snug">
            By uploading a file, you agree to share anonymous scan results with
            the PDFreak AI community. We don’t store files permanently and
            follow strict privacy standards.
            <span className="block">
              Please review our{" "}
              <a href="#" className="underline hover:text-green-400">
                Terms of Service
              </a>{" "}
              and{" "}
              <a href="#" className="underline hover:text-green-400">
                Privacy Policy
              </a>
              .
            </span>
          </p>

          {/* If you want a link to the Results page or an external resource, add it here. */}
        </div>

        {/* Render Results (if any) */}
        <Results analysisResult={analysisResult} />
      </div>
    </div>
  );
};

export default App;
