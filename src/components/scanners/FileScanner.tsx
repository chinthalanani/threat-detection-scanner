"use client";

import React, { useRef, useState } from "react";
import { UploadCloud, File as FileIcon, AlertCircle, CheckCircle2, Shield, Loader2, ArrowRight, Sparkles, Copy, Check } from "lucide-react";
import { getCustomApiHeaders, saveScanToHistory } from "@/lib/storage";
import { FileScanResult, ScanResult } from "@/types/threat";
import { ScanningProgress } from "@/components/common/ScanningProgress";

interface FileScannerProps {
  onScanComplete: (result: ScanResult) => void;
}

export function FileScanner({ onScanComplete }: FileScannerProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [clientHash, setClientHash] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Compute SHA-256 client-side using Web Crypto API
  const computeFileSha256 = async (file: File): Promise<string> => {
    const arrayBuffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  };

  const handleFileChange = async (file: File) => {
    setError(null);
    setSelectedFile(file);
    setStatusMessage("Calculating SHA-256 cryptographic digest in browser...");

    try {
      const hash = await computeFileSha256(file);
      setClientHash(hash);
      setStatusMessage(`SHA-256: ${hash}`);
    } catch (err) {
      console.error("Failed to compute client hash:", err);
      setError("Could not compute file hash locally.");
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileChange(e.dataTransfer.files[0]);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError("Please select a file to scan.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const customHeaders = getCustomApiHeaders();
      let hash = clientHash;
      if (!hash) {
        setStatusMessage("Hashing file payload...");
        hash = await computeFileSha256(selectedFile);
        setClientHash(hash);
      }

      // Step 1: Pre-check hash in VirusTotal first to avoid uploading known files
      setStatusMessage("Checking if file hash exists in threat intelligence database...");
      
      const hashRes = await fetch("/api/scan/hash", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...customHeaders,
        },
        body: JSON.stringify({ hash }),
      });

      if (hashRes.ok) {
        const hashData = await hashRes.json();
        // If file already has scan results or was detected
        if (hashData.verdict !== "unknown" && (hashData.totalEngines > 0 || hashData.isDemo)) {
          const fileResult: FileScanResult = {
            ...hashData,
            scanType: "file",
            fileName: selectedFile.name,
            fileSize: selectedFile.size,
          };
          saveScanToHistory(fileResult);
          onScanComplete(fileResult);
          setLoading(false);
          return;
        }
      }

      // Step 2: Upload file payload to VirusTotal
      setStatusMessage("Uploading file to VirusTotal multi-engine analysis cluster...");
      const formData = new FormData();
      formData.append("file", selectedFile);
      formData.append("hash", hash);

      const uploadRes = await fetch("/api/scan/file", {
        method: "POST",
        headers: {
          ...customHeaders,
        },
        body: formData,
      });

      const uploadData = await uploadRes.json();
      if (!uploadRes.ok) {
        throw new Error(uploadData.error || "File upload failed.");
      }

      // If demo mode or immediate result returned
      if (uploadData.verdict) {
        saveScanToHistory(uploadData);
        onScanComplete(uploadData as FileScanResult);
        setLoading(false);
        return;
      }

      // If analysis queued, poll for status
      if (uploadData.analysisId) {
        const analysisId = uploadData.analysisId;
        let attempts = 0;
        const maxAttempts = 15;

        while (attempts < maxAttempts) {
          attempts += 1;
          setStatusMessage(`Polling VirusTotal scan cluster (Attempt ${attempts}/${maxAttempts})...`);
          await new Promise((r) => setTimeout(r, 3000));

          const statusRes = await fetch(
            `/api/scan/file/status?id=${analysisId}&fileName=${encodeURIComponent(selectedFile.name)}`,
            {
              headers: { ...customHeaders },
            }
          );

          if (statusRes.ok) {
            const statusJson = await statusRes.json();
            if (statusJson.status === "completed" && statusJson.result) {
              saveScanToHistory(statusJson.result);
              onScanComplete(statusJson.result as FileScanResult);
              setLoading(false);
              return;
            }
          }
        }

        throw new Error("Analysis is taking longer than expected. Please check back later using the file hash.");
      }
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to scan file";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleTestEicar = () => {
    // Generate virtual EICAR test string
    const eicarText = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    const blob = new Blob([eicarText], { type: "text/plain" });
    const testFile = new File([blob], "eicar_test_sample.com", { type: "text/plain" });
    handleFileChange(testFile);
  };

  const copyHashToClipboard = () => {
    if (clientHash) {
      navigator.clipboard.writeText(clientHash);
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border relative overflow-hidden">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
            <UploadCloud className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">File Upload & Malware Scanner</h2>
            <p className="text-xs text-gray-400">
              Computes SHA-256 client-side first to avoid re-uploading known binaries, then queries 70+ antivirus engines.
            </p>
          </div>
        </div>

        {/* Drag & Drop Area */}
        <div
          onDragOver={(e) => e.preventDefault()}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className="border-2 border-dashed border-soc-border/80 hover:border-soc-accent/60 rounded-xl p-8 text-center cursor-pointer transition-all bg-soc-darker/50 hover:bg-soc-dark/50 group"
        >
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) => {
              if (e.target.files?.[0]) handleFileChange(e.target.files[0]);
            }}
          />

          <div className="flex flex-col items-center justify-center gap-3">
            <div className="w-14 h-14 rounded-full bg-soc-dark border border-soc-border flex items-center justify-center group-hover:scale-110 group-hover:border-soc-accent/40 transition-all">
              <UploadCloud className="w-7 h-7 text-soc-accent" />
            </div>

            <div>
              <p className="text-sm font-semibold text-white">
                Drag and drop your file here, or <span className="text-soc-accent underline">browse</span>
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Executable, PDF, Office document, ZIP, or script (Up to 32MB)
              </p>
            </div>
          </div>
        </div>

        {/* Selected File Details & SHA-256 Info */}
        {selectedFile && (
          <div className="mt-4 p-4 rounded-lg bg-soc-darker border border-soc-border flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border flex-shrink-0">
                <FileIcon className="w-5 h-5 text-soc-accent" />
              </div>
              <div className="min-w-0">
                <div className="text-sm font-mono font-bold text-white truncate">
                  {selectedFile.name}
                </div>
                <div className="text-xs text-gray-400 font-mono">
                  {(selectedFile.size / 1024).toFixed(1)} KB • {selectedFile.type || "application/octet-stream"}
                </div>
                {clientHash && (
                  <div className="flex items-center gap-1.5 mt-1 text-[11px] font-mono text-emerald-400">
                    <span className="text-gray-400">SHA256:</span>
                    <span className="truncate max-w-xs md:max-w-md select-all">{clientHash}</span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        copyHashToClipboard();
                      }}
                      className="p-1 hover:bg-soc-border/50 rounded text-gray-400 hover:text-white"
                      title="Copy SHA-256"
                    >
                      {copiedHash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    </button>
                  </div>
                )}
              </div>
            </div>

            <button
              onClick={handleScan}
              disabled={loading}
              className="px-6 py-2.5 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-semibold text-xs font-mono flex items-center justify-center gap-2 transition-all disabled:opacity-50 shadow-lg shadow-soc-accent/20 flex-shrink-0"
            >
              {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
              <span>{loading ? "Scanning File..." : "Analyze File"}</span>
            </button>
          </div>
        )}

        {/* Quick Demo Test File Button */}
        <div className="flex flex-wrap items-center gap-2 mt-4 pt-2 border-t border-soc-border/40">
          <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-amber-400" />
            Test Sample:
          </span>
          <button
            type="button"
            onClick={handleTestEicar}
            disabled={loading}
            className="text-xs font-mono px-2.5 py-1 rounded bg-soc-dark/70 hover:bg-soc-border/60 text-gray-300 border border-soc-border/60 transition-colors flex items-center gap-1"
          >
            <span>Load EICAR Antivirus Test File (harmless standard sample)</span>
            <ArrowRight className="w-3 h-3 text-gray-500" />
          </button>
        </div>

        {/* Error Alert */}
        {error && (
          <div className="mt-4 p-3.5 rounded-lg bg-red-950/40 border border-red-500/40 text-red-400 text-xs font-mono flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Live Scanning Stepper */}
      {loading && (
        <ScanningProgress
          scanType="file"
          target={selectedFile?.name || "Uploaded file"}
          customStatus={statusMessage || undefined}
        />
      )}
    </div>
  );
}
