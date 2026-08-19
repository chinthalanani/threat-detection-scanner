"use client";

import React, { useState } from "react";
import { Mail, Search, AlertCircle, Sparkles, FileText, AtSign, ShieldAlert } from "lucide-react";
import { ScanningProgress } from "@/components/common/ScanningProgress";
import { SAMPLE_TARGETS } from "@/lib/demo-data";
import { getStoredApiKeys, saveScanToHistory } from "@/lib/storage";
import { EmailScanResult } from "@/types/threat";

interface EmailScannerProps {
  onScanComplete: (result: EmailScanResult) => void;
}

export function EmailScanner({ onScanComplete }: EmailScannerProps) {
  const [mode, setMode] = useState<'address' | 'content'>('address');
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e?: React.FormEvent, customVal?: string) => {
    if (e) e.preventDefault();
    const targetVal = customVal || input;
    if (!targetVal.trim()) {
      setError(mode === 'address' ? "Please enter an email address." : "Please paste email content or headers.");
      return;
    }

    setError(null);
    setIsScanning(true);

    try {
      const keys = getStoredApiKeys();
      const headers: Record<string, string> = { "Content-Type": "application/json" };
      if (keys.virusTotalKey) headers["x-virustotal-key"] = keys.virusTotalKey;
      if (keys.abuseIpDbKey) headers["x-abuseipdb-key"] = keys.abuseIpDbKey;

      const res = await fetch("/api/scan/email", {
        method: "POST",
        headers,
        body: JSON.stringify({ input: targetVal, mode }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || "Email scan failed. Please check your network or try again.");
      }

      saveScanToHistory(data);
      onScanComplete(data);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred during email scan.");
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectSample = (sample: string) => {
    setInput(sample);
    setMode('address');
    handleSubmit(undefined, sample);
  };

  return (
    <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-soc-border/60 pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-blue-400">
            <Mail className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <span>Email & Phishing Threat Scanner</span>
            </h2>
            <p className="text-xs text-gray-400 font-mono">
              Detect disposable emails, brand typo-squatting, breach exposure, and phishing links
            </p>
          </div>
        </div>

        {/* Mode Selector */}
        <div className="flex items-center bg-soc-dark p-1 rounded-lg border border-soc-border self-start sm:self-auto text-xs font-mono">
          <button
            type="button"
            onClick={() => setMode('address')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
              mode === 'address'
                ? "bg-soc-accent text-soc-darkest font-bold shadow"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <AtSign className="w-3.5 h-3.5" />
            <span>Single Address</span>
          </button>

          <button
            type="button"
            onClick={() => setMode('content')}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md transition-all ${
              mode === 'content'
                ? "bg-soc-accent text-soc-darkest font-bold shadow"
                : "text-gray-400 hover:text-white"
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Raw Content / Phishing</span>
          </button>
        </div>
      </div>

      {/* Input Form */}
      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="space-y-2">
          <label className="text-xs font-mono text-gray-300 flex items-center gap-1.5">
            <span>{mode === 'address' ? "Target Email Address" : "Email Raw Headers or Body Content"}</span>
            <span className="text-soc-accent">*</span>
          </label>

          {mode === 'address' ? (
            <div className="relative">
              <input
                type="email"
                value={input}
                onChange={(e) => setInput(e.target.value)}
                placeholder="e.g. security-alert@paypa1-account.com or support@google.com"
                disabled={isScanning}
                className="w-full bg-soc-darker border border-soc-border focus:border-soc-accent focus:ring-1 focus:ring-soc-accent rounded-lg px-4 py-3 pl-11 text-sm font-mono text-white placeholder-gray-500 transition-colors outline-none"
              />
              <Mail className="w-4 h-4 text-gray-500 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" />
            </div>
          ) : (
            <div className="relative">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                rows={5}
                placeholder="Paste the suspicious email text, subject line, urgency warnings, or raw RFC headers here..."
                disabled={isScanning}
                className="w-full bg-soc-darker border border-soc-border focus:border-soc-accent focus:ring-1 focus:ring-soc-accent rounded-lg p-4 text-xs font-mono text-white placeholder-gray-500 transition-colors outline-none resize-none"
              />
            </div>
          )}
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
            {SAMPLE_TARGETS.email.map((s, idx) => (
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
            <span>{isScanning ? "Analyzing Email..." : "Scan Email"}</span>
          </button>
        </div>
      </form>

      {/* Radar Scanning Progress */}
      {isScanning && (
        <ScanningProgress
          scanType="email"
          target={input}
          customStatus="Screening email for phishing patterns, disposable domains & breach exposures..."
        />
      )}
    </div>
  );
}
