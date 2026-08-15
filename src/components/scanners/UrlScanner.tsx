"use client";

import React, { useState } from "react";
import { Globe, Search, AlertCircle, Sparkles, ArrowRight, ShieldCheck, ShieldAlert } from "lucide-react";
import { SAMPLE_TARGETS } from "@/lib/demo-data";
import { getCustomApiHeaders, saveScanToHistory } from "@/lib/storage";
import { ScanResult, UrlScanResult } from "@/types/threat";
import { ScanningProgress } from "@/components/common/ScanningProgress";

interface UrlScannerProps {
  onScanComplete: (result: ScanResult) => void;
}

export function UrlScanner({ onScanComplete }: UrlScannerProps) {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async (targetUrl?: string) => {
    const inputToScan = (targetUrl || url).trim();
    if (!inputToScan) {
      setError("Please enter a URL to analyze.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const customHeaders = getCustomApiHeaders();
      const res = await fetch("/api/scan/url", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...customHeaders,
        },
        body: JSON.stringify({ url: inputToScan }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.error || `Scan failed with status ${res.status}`);
      }

      saveScanToHistory(data);
      onScanComplete(data as UrlScanResult);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to complete URL analysis";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const handleSampleClick = (sampleUrl: string) => {
    setUrl(sampleUrl);
    handleScan(sampleUrl);
  };

  return (
    <div className="space-y-6">
      {/* Scanner Card */}
      <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border relative overflow-hidden">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
            <Globe className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">URL Threat Scanner</h2>
            <p className="text-xs text-gray-400">
              Detect phishing, credential harvesters, malicious redirects, and malware distribution sites via VirusTotal & Google Safe Browsing.
            </p>
          </div>
        </div>

        {/* Search Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleScan();
          }}
          className="space-y-4"
        >
          <div className="relative flex flex-col sm:flex-row items-stretch gap-2">
            <div className="relative flex-1">
              <Globe className="w-4 h-4 text-gray-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Enter URL to analyze (e.g., https://example.com, malicious-domain.ru)..."
                value={url}
                onChange={(e) => {
                  setUrl(e.target.value);
                  if (error) setError(null);
                }}
                disabled={loading}
                className="w-full pl-10 pr-4 py-3 text-sm font-mono rounded-lg bg-soc-darker border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent transition-colors disabled:opacity-50"
              />
            </div>

            <button
              type="submit"
              disabled={loading || !url.trim()}
              className="px-6 py-3 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-semibold text-sm font-mono flex items-center justify-center gap-2 transition-all disabled:opacity-50 shadow-lg shadow-soc-accent/20 flex-shrink-0"
            >
              <Search className="w-4 h-4" />
              <span>{loading ? "Scanning..." : "Analyze URL"}</span>
            </button>
          </div>

          {/* Quick Demo Samples */}
          <div className="flex flex-wrap items-center gap-2 pt-2">
            <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
              <Sparkles className="w-3 h-3 text-amber-400" />
              Quick Samples:
            </span>
            {SAMPLE_TARGETS.url.map((sample, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSampleClick(sample.value)}
                disabled={loading}
                className="text-xs font-mono px-2.5 py-1 rounded bg-soc-dark/70 hover:bg-soc-border/60 text-gray-300 border border-soc-border/60 transition-colors flex items-center gap-1 truncate max-w-xs"
                title={sample.value}
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
      {loading && <ScanningProgress scanType="url" target={url} />}
    </div>
  );
}
