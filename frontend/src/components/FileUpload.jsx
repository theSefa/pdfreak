import { useState, useEffect } from "react";

const FileUpload = ({ onFileUpload }) => {
  const [file, setFile] = useState(null);
  const [progress, setProgress] = useState(0);
  const [isUploading, setIsUploading] = useState(false);

  const handleFileChange = (event) => {
    setFile(event.target.files[0]);
    setProgress(0);
  };

  const handleUpload = async () => {
    if (!file) return;

    setIsUploading(true);
    setProgress(10);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const interval = setInterval(() => {
        setProgress((prev) => Math.min(prev + 5, 90));
      }, 300);

      const response = await fetch("http://127.0.0.1:8000/analyze-upload", {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        throw new Error("Upload failed");
      }

      const result = await response.json();
      clearInterval(interval);
      setProgress(100);
      setTimeout(() => {
        setIsUploading(false);
        onFileUpload(result);
      }, 500);
    } catch (error) {
      console.error("Upload error:", error);
      clearInterval(interval);
      setProgress(0);
      setIsUploading(false);
    }
  };

  useEffect(() => {
    console.log({ isUploading, progress });
  }, [isUploading, progress]);

  return (
    <div className="bg-[#101B16] border border-[#1f2a24] p-8 rounded-md shadow-lg w-full max-w-xl flex flex-col items-center text-white mt-12">
      {/* Drag-and-Drop Label */}
      <label
        htmlFor="fileInput"
        className="cursor-pointer flex flex-col items-center"
      >
        <div className="px-6 py-4 border border-dashed border-green-400 rounded-md hover:bg-[#16231C] transition text-center">
          <span className="text-green-400 text-lg">
            Drag &amp; drop a PDF file here
          </span>
        </div>
      </label>

      {/* Hidden File Input */}
      <input
        type="file"
        accept=".pdf,.zip"
        onChange={handleFileChange}
        className="hidden"
        id="fileInput"
      />

      {/* File Name Preview */}
      {file && <p className="mt-3 text-sm text-gray-400">{file.name}</p>}

      {/* Progress Bar */}
      {isUploading && (
        <div className="w-full bg-[#1e2a25] mt-4 rounded-md h-2 overflow-hidden">
          <div
            className="bg-green-400 h-full rounded-md transition-all duration-500 ease-in-out"
            style={{ width: `${progress}%` }}
          ></div>
        </div>
      )}

      {/* Upload Button */}
      <button
        onClick={handleUpload}
        disabled={isUploading || !file}
        className={`mt-6 w-full py-3 rounded-md text-sm font-semibold transition ${
          isUploading || !file
            ? "bg-gray-600 cursor-not-allowed text-gray-300"
            : "bg-green-500 hover:bg-green-600 text-white"
        }`}
      >
        {isUploading ? "Uploading..." : "Upload & Scan"}
      </button>
    </div>
  );
};

export default FileUpload;
