"use client";

import React, { useMemo, useState } from "react";
import { Hash, Search, AlertCircle, Sparkles, ArrowRight, CheckCircle, ShieldAlert } from "lucide-react";
import { SAMPLE_TARGETS } from "@/lib/demo-data";
import { getCustomApiHeaders, saveScanToHistory } from "@/lib/storage";
import { detectHashType } from "@/lib/validators";
import { HashScanResult, ScanResult } from "@/types/threat";
import { ScanningProgress } from "@/components/common/ScanningProgress";

interface HashScannerProps {
  onScanComplete: (result: ScanResult) => void;
}

export function HashScanner({ onScanComplete }: HashScannerProps) {
  const [hashInput, setHashInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const detectedType = useMemo(() => {
    return detectHashType(hashInput);
  }, [hashInput]);

  const handleScan = async (targetHash?: string) => {
    const inputToScan = (targetHash || hashInput).trim();
    if (!inputToScan) {
      setError("Please enter a cryptographic hash (MD5, SHA-1, or SHA-256).");
      return;
    }

    const type = detectHashType(inputToScan);
    if (!type) {
      setError("Invalid hash format. Must be 32 (MD5), 40 (SHA-1), or 64 (SHA-256) hex characters.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const customHeaders = getCustomApiHeaders();
      const res = await fetch("/api/scan/hash", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...customHeaders,
        },
        body: JSON.stringify({ hash: inputToScan }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Scan failed with status ${res.status}`);
      }

      saveScanToHistory(data);
      onScanComplete(data as HashScanResult);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to query hash intelligence";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSampleClick = (sampleHash: string) => {
    setHashInput(sampleHash);
    handleScan(sampleHash);
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border relative overflow-hidden">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
            <Hash className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">File Hash Lookup</h2>
            <p className="text-xs text-gray-400">
              Query VirusTotal for known malware signatures, ransomware strains, trojans, and clean binaries using MD5, SHA-1, or SHA-256 hashes.
            </p>
          </div>
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-4"
        >
          <div className="relative flex flex-col sm:flex-row items-stretch gap-2">
            <div className="relative flex-1">
              <Hash className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Enter MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex)..."
                value={hashInput}
                onChange={(e) => {
                  setHashInput(e.target.value);
                  if (error) setError(null);
                }}
                disabled={loading}
                className="w-full pl-10 pr-24 py-3 text-sm font-mono rounded-lg bg-soc-darker border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent transition-colors disabled:opacity-50"
              />

              {/* Detected Type Badge */}
              {hashInput.trim() && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  {detectedType ? (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-soc-accent/15 text-soc-accent border border-soc-accent/30">
                      {detectedType}
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono text-gray-500 bg-soc-dark border border-soc-border">
                      {hashInput.trim().length} chars
                    </span>
                  )}
                </div>
              )}
            </div>

            <button
              type="submit"
              disabled={loading || !hashInput.trim()}
              className="px-6 py-3 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-semibold text-sm font-mono flex items-center justify-center gap-2 transition-all disabled:opacity-50 shadow-lg shadow-soc-accent/20 flex-shrink-0"
            >
              <Search className="w-4 h-4" />
              <span>{loading ? "Searching..." : "Lookup Hash"}</span>
            </button>
          </div>

          {/* Quick Demo Samples */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" />
              Quick Samples:
            </span>
            {SAMPLE_TARGETS.hash.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSampleClick(sample.value)}
                disabled={loading}
                className="text-xs font-mono px-2.5 py-1 rounded bg-soc-dark/70 hover:bg-soc-border/60 text-gray-300 border border-soc-border/60 transition-colors flex items-center gap-1 truncate max-w-xs"
                title={`${sample.label}: ${sample.value}`}
              >
                <span>{sample.label}</span>
                <ArrowRight className="w-3 h-3 text-gray-500" />
              </button>
            ))}
          </div>
        </form>

        {/* Error Alert */}
        {error && (
          <div className="mt-4 p-3.5 rounded-lg bg-red-950/40 border border-red-500/40 text-red-400 text-xs font-mono flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Live Scanning Stepper */}
      {loading && <ScanningProgress scanType="hash" target={hashInput} />}
    </div>
  );
}
