import {
  AiOutlineCheckCircle,
  AiOutlineExclamationCircle,
} from "react-icons/ai";
import { FiAlertTriangle } from "react-icons/fi";

const Results = ({ analysisResult }) => {
  if (!analysisResult) {
    return (
      <p className="text-gray-400 text-center mt-6">
        No results yet. Upload a PDF to analyze.
      </p>
    );
  }

  const {
    filename,
    prediction,
    confidence,
    features = {},
    ai_analysis,
    timestamp,
  } = analysisResult;

  // Determine if malicious or benign
  const isMalicious = prediction.toLowerCase() === "malicious";
  const confidencePercent = (confidence * 100).toFixed(2);

  // Convert file size to KB or MB for display
  const fileSizeKB = features.file_size
    ? (features.file_size / 1024).toFixed(2)
    : null;

  // Color-coded status for Malicious vs. Benign
  const verdictColor = isMalicious ? "text-red-500" : "text-green-500";
  const verdictIcon = isMalicious ? (
    <AiOutlineExclamationCircle size={36} className="text-red-500" />
  ) : (
    <AiOutlineCheckCircle size={36} className="text-green-500" />
  );

  // Suspicious markers to highlight
  // We'll show them only if they're flagged in the features
  const suspiciousIndicators = [];
  if (features.has_shellcode) {
    suspiciousIndicators.push({
      label: "Shellcode Detected",
      value: `Patterns: ${features.num_shellcode_patterns || 1}`,
    });
  }
  if (features.num_urls > 0) {
    suspiciousIndicators.push({
      label: "URLs Found",
      value: features.num_urls,
    });
  }
  if (features.suspicious_streams > 0) {
    suspiciousIndicators.push({
      label: "Suspicious Streams",
      value: features.suspicious_streams,
    });
  }
  // Add more if needed (e.g., has_javascript_marker, has_openaction_marker, etc.)

  return (
    <div className="mt-6 w-full max-w-6xl mx-auto px-4 sm:px-8 text-white space-y-6">
      {/* Verdict & Confidence */}
      <div className="bg-[#101B16] border border-[#1f2a24] rounded-md p-6 flex flex-col sm:flex-row items-center sm:items-start justify-between">
        <div className="flex items-center space-x-3">
          {verdictIcon}
          <div>
            <h2 className={`text-2xl font-bold ${verdictColor}`}>
              {prediction} <span className="text-gray-200">PDF</span>
            </h2>
            <p className="text-gray-400 text-sm">
              Confidence: {confidencePercent}%
            </p>
          </div>
        </div>

        {/* Timestamp */}
        <p className="text-gray-400 text-xs sm:text-sm mt-4 sm:mt-0">
          Scanned at: {new Date(timestamp).toLocaleString()}
        </p>
      </div>

      {/* File Overview & Behavioral Indicators */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        {/* File Overview */}
        <div className="bg-[#101B16] border border-[#1f2a24] rounded-md p-4 col-span-1 space-y-2">
          <h3 className="text-green-400 font-semibold text-lg">
            File Overview
          </h3>
          <div className="text-gray-300 text-sm space-y-1">
            <p>
              <span className="font-semibold">Name:</span> {filename || "N/A"}
            </p>
            <p>
              <span className="font-semibold">Type:</span>{" "}
              {features.file_type || "Unknown"}
            </p>
            <p>
              <span className="font-semibold">Size:</span>{" "}
              {fileSizeKB ? `${fileSizeKB} KB` : "Unknown"}
            </p>
            <p>
              <span className="font-semibold">SHA-256:</span>{" "}
              <span className="break-all">
                {features.sha256 || "Not available"}
              </span>
            </p>
            <p>
              <span className="font-semibold">Entropy:</span>{" "}
              {features.file_entropy?.toFixed(2) ?? "N/A"}
            </p>
          </div>
        </div>

        {/* Behavioral Indicators */}
        <div className="bg-[#101B16] border border-[#1f2a24] rounded-md p-4 col-span-1 space-y-2">
          <h3 className="text-green-400 font-semibold text-lg">
            Behavioral Indicators
          </h3>
          <div className="text-gray-300 text-sm space-y-1">
            {suspiciousIndicators.length === 0 ? (
              <p className="text-green-500 flex items-center">
                <AiOutlineCheckCircle className="mr-1" /> No major red flags
              </p>
            ) : (
              suspiciousIndicators.map((indicator, idx) => (
                <p
                  key={idx}
                  className="text-red-400 flex items-center space-x-2"
                >
                  <FiAlertTriangle />
                  <span>{indicator.label}:</span>
                  <span>{indicator.value}</span>
                </p>
              ))
            )}
          </div>
        </div>

        {/* Quick Stats / Additional Info */}
        <div className="bg-[#101B16] border border-[#1f2a24] rounded-md p-4 col-span-1 space-y-2">
          <h3 className="text-green-400 font-semibold text-lg">Quick Stats</h3>
          <div className="text-gray-300 text-sm space-y-1">
            <p>
              <span className="font-semibold">Objects:</span>{" "}
              {features.object_count ?? "N/A"}
            </p>
            <p>
              <span className="font-semibold">Streams:</span>{" "}
              {features.num_streams ?? "N/A"}
            </p>
            <p>
              <span className="font-semibold">URLs:</span>{" "}
              {features.num_urls || 0}
            </p>
            <p>
              <span className="font-semibold">Encrypted Count:</span>{" "}
              {features.encrypted_count || 0}
            </p>
          </div>
        </div>
      </div>

      {/* AI Analysis Summary */}
      <div className="bg-[#101B16] border border-[#1f2a24] rounded-md p-4">
        <h3 className="text-green-400 font-semibold text-lg mb-2">
          AI Analysis Summary
        </h3>
        {ai_analysis ? (
          <p className="text-gray-300 whitespace-pre-line text-sm leading-relaxed">
            {ai_analysis}
          </p>
        ) : (
          <p className="text-gray-500 italic">No AI analysis available.</p>
        )}
      </div>
    </div>
  );
};

export default Results;
