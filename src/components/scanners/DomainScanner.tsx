"use client";

import React, { useState } from "react";
import { Globe, Search, AlertCircle, Sparkles, Shield, Server } from "lucide-react";
import { ScanningProgress } from "@/components/common/ScanningProgress";
import { SAMPLE_TARGETS } from "@/lib/demo-data";
import { getStoredApiKeys, saveScanToHistory } from "@/lib/storage";
import { DomainScanResult } from "@/types/threat";

interface DomainScannerProps {
  onScanComplete: (result: DomainScanResult) => void;
}

export function DomainScanner({ onScanComplete }: DomainScannerProps) {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e?: React.FormEvent, customDomain?: string) => {
    if (e) e.preventDefault();
    const targetDomain = customDomain || domain;
    if (!targetDomain.trim()) {
      setError("Please enter a domain name to scan.");
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const keys = getStoredApiKeys();
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (keys.virusTotalKey) headers["x-virustotal-key"] = keys.virusTotalKey;

      const res = await fetch("/api/scan/domain", {
        method: "POST",
        headers,
        body: JSON.stringify({ domain: targetDomain }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Domain scan failed. Please verify domain name.");
      }

      saveScanToHistory(data);
      onScanComplete(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred during domain scan.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectSample = (sample: string) => {
    setDomain(sample);
    handleSubmit(undefined, sample);
  };

  return (
    <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-soc-border/60 pb-4">
        <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-emerald-400">
          <Globe className="w-5 h-5" />
        </div>
        <div>
          <h2 className="text-lg font-bold text-white flex items-center gap-2">
            <span>Domain & WHOIS / DNS Security Scanner</span>
          </h2>
          <p className="text-xs text-gray-400 font-mono">
            Check domain age, SSL/TLS certificate health, SPF/DMARC compliance, and DGA entropy
          </p>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-xs font-mono text-gray-300 flex items-center gap-1.5">
            <span>Domain Name</span>
            <span className="text-soc-accent">*</span>
          </label>

          <div className="relative">
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder="e.g. secure-login-portal.xyz or microsoft.com"
              disabled={isScanning}
              className="w-full bg-soc-darker border border-soc-border focus:border-soc-accent focus:ring-1 focus:ring-soc-accent rounded-lg px-4 py-3 pl-11 text-sm font-mono text-white placeholder-gray-500 transition-colors outline-none"
            />
            <Globe className="w-4 h-4 text-gray-500 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" />
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
            {SAMPLE_TARGETS.domain.map((s, idx) => (
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
            <span>{isScanning ? "Resolving DNS & WHOIS..." : "Scan Domain"}</span>
          </button>
        </div>
      </form>

      {/* Radar Scanning Progress */}
      {isScanning && (
        <ScanningProgress
          scanType="domain"
          target={domain}
          customStatus="Resolving DNS records, evaluating SSL certificate & checking DGA entropy..."
        />
      )}
    </div>
  );
}
