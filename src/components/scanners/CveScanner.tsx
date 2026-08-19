"use client";

import React, { useState } from "react";
import { ShieldAlert, Search, AlertCircle, Sparkles, Bug, Terminal } from "lucide-react";
import { ScanningProgress } from "@/components/common/ScanningProgress";
import { SAMPLE_TARGETS } from "@/lib/demo-data";
import { saveScanToHistory } from "@/lib/storage";
import { CveScanResult } from "@/types/threat";

interface CveScannerProps {
  onScanComplete: (result: CveScanResult) => void;
}

export function CveScanner({ onScanComplete }: CveScannerProps) {
  const [cveId, setCveId] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e?: React.FormEvent, customCve?: string) => {
    if (e) e.preventDefault();
    const targetCve = customCve || cveId;
    if (!targetCve.trim()) {
      setError("Please enter a CVE ID (e.g. CVE-2021-44228).");
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const res = await fetch("/api/scan/cve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cveId: targetCve }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "CVE lookup failed. Please check the CVE identifier.");
      }

      saveScanToHistory(data);
      onScanComplete(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred during CVE lookup.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectSample = (sample: string) => {
    setCveId(sample);
    handleSubmit(undefined, sample);
  };

  return (
    <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-soc-border/60 pb-4">
        <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-red-400">
          <Bug className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>CVE Vulnerability & Exploit Intelligence Scanner</span>
          </h2>
          <p className="text-xs text-gray-400 font-mono">
            Query CVSS v3.1 severity, FIRST EPSS exploit likelihood, CISA KEV status, and patches
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-xs font-mono text-gray-300 flex items-center gap-1.5">
            <span>Common Vulnerabilities and Exposures (CVE) ID</span>
            <span className="text-soc-accent">*</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              placeholder="e.g. CVE-2021-44228 or CVE-2024-38077"
              disabled={isScanning}
              className="w-full bg-soc-darker border border-soc-border focus:border-soc-accent focus:ring-1 focus:ring-soc-accent rounded-lg px-4 py-3 pl-11 text-sm font-mono text-white uppercase placeholder-gray-500 transition-colors outline-none"
            />
            <Bug className="w-4 h-4 text-gray-500 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        </div>

        {error && (
          <div className="flex items-center gap-2 text-xs font-mono text-red-400 bg-red-950/40 border border-red-800/40 p-3 rounded-lg">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-1">
          {/* Quick Demo Samples */}
          <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
            <span className="text-gray-500 text-[11px] flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" /> Samples:
            </span>
            {SAMPLE_TARGETS.cve.map((s, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(s.value)}
                disabled={isScanning}
                className="px-2 py-1 rounded bg-soc-dark hover:bg-soc-border/60 text-gray-300 text-[11px] border border-soc-border hover:border-soc-accent/40 transition-colors"
              >
                {s.label}
              </button>
            ))}
          </div>

          <button
            type="submit"
            disabled={isScanning}
            className="w-full sm:w-auto px-6 py-2.5 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-mono font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-lg shadow-soc-accent/20 disabled:opacity-50"
          >
            <Search className="w-4 h-4" />
            <span>{isScanning ? "Querying NVD & EPSS..." : "Lookup CVE"}</span>
          </button>
        </div>
      </form>

      {/* Radar Scanning Progress */}
      {isScanning && (
        <ScanningProgress
          scanType="cve"
          target={cveId}
          customStatus="Querying NVD v2.0 database, computing CVSS severity & FIRST EPSS probabilities..."
        />
      )}
    </div>
  );
}
