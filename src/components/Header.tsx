"use client";

import React, { useEffect, useState } from "react";
import { Shield, Key, History, Sparkles, CheckCircle2, AlertTriangle, Terminal, Layers } from "lucide-react";
import { getScanHistory, getStoredApiKeys } from "@/lib/storage";
import { ApiStatusResponse } from "@/types/threat";

interface HeaderProps {
  onOpenSettings: () => void;
  onOpenHistory: () => void;
  historyUpdatedKey?: number;
}

export function Header({ onOpenSettings, onOpenHistory, historyUpdatedKey }: HeaderProps) {
  const [historyCount, setHistoryCount] = useState(0);
  const [serverStatus, setServerStatus] = useState<ApiStatusResponse | null>(null);

  useEffect(() => {
    setHistoryCount(getScanHistory().length);
  }, [historyUpdatedKey]);

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const res = await fetch("/api/status");
        if (res.ok) {
          const data = await res.json();
          setServerStatus(data);
        }
      } catch (err) {
        console.error("Status fetch error:", err);
      }
    };
    fetchStatus();
  }, []);

  const localKeys = getStoredApiKeys();
  const isLive = Boolean(
    serverStatus?.virusTotalConfigured ||
    serverStatus?.abuseIpDbConfigured ||
    serverStatus?.googleSafeBrowsingConfigured ||
    localKeys.virusTotalKey ||
    localKeys.abuseIpDbKey ||
    localKeys.googleSafeBrowsingKey
  );

  return (
    <header className="border-b border-soc-border/80 bg-soc-darker/80 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand Logo */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-soc-accent to-emerald-600 flex items-center justify-center shadow-lg shadow-soc-accent/20 border border-soc-accent/40">
            <Shield className="w-5 h-5 text-soc-darkest" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base font-bold text-white tracking-tight flex items-center gap-1.5">
                <span>ThreatVigil</span>
                <span className="text-soc-accent text-xs font-mono font-normal px-1.5 py-0.2 rounded bg-soc-accent/10 border border-soc-accent/30">
                  v1.0 SOC
                </span>
              </h1>
            </div>
            <p className="text-[11px] text-gray-400 font-mono hidden sm:block">
              Multi-Source Threat Intelligence & Malware Detection
            </p>
          </div>
        </div>

        {/* Right Navigation & Status Controls */}
        <div className="flex items-center gap-2.5 sm:gap-3">
          {/* API Status Badge / Settings Button */}
          <button
            onClick={onOpenSettings}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono transition-all ${
              isLive
                ? "bg-emerald-950/40 border-emerald-500/40 text-emerald-400 hover:bg-emerald-950/60"
                : "bg-amber-950/40 border-amber-500/40 text-amber-300 hover:bg-amber-950/60"
            }`}
            title="Configure VirusTotal, AbuseIPDB, and Google Safe Browsing API keys"
          >
            {isLive ? (
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            ) : (
              <Sparkles className="w-3.5 h-3.5 text-amber-400" />
            )}
            <span className="hidden md:inline font-medium">
              {isLive ? "Live Threat Intel Active" : "Interactive Demo Mode"}
            </span>
            <Key className="w-3 h-3 ml-0.5 text-gray-400" />
          </button>

          {/* Scan History Button */}
          <button
            onClick={onOpenHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-dark hover:bg-soc-border/60 text-gray-300 border border-soc-border text-xs font-mono transition-colors"
            title="View scan history"
          >
            <History className="w-3.5 h-3.5 text-soc-accent" />
            <span className="hidden sm:inline">History</span>
            {historyCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-soc-accent text-soc-darkest">
                {historyCount}
              </span>
            )}
          </button>
        </div>
      </div>
    </header>
  );
}
