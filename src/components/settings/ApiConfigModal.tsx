"use client";

import React, { useEffect, useState } from "react";
import {
  X,
  Key,
  Shield,
  CheckCircle2,
  AlertCircle,
  ExternalLink,
  Save,
  Trash2,
  Info,
  Server,
  Sparkles,
} from "lucide-react";
import { clearStoredApiKeys, getStoredApiKeys, saveStoredApiKeys, StoredApiKeys } from "@/lib/storage";
import { ApiStatusResponse } from "@/types/threat";

interface ApiConfigModalProps {
  isOpen: boolean;
  onClose: () => void;
  onKeysUpdated: () => void;
}

export function ApiConfigModal({ isOpen, onClose, onKeysUpdated }: ApiConfigModalProps) {
  const [keys, setKeys] = useState<StoredApiKeys>({});
  const [serverStatus, setServerStatus] = useState<ApiStatusResponse | null>(null);
  const [savedSuccess, setSavedSuccess] = useState(false);
  const [testing, setTesting] = useState(false);

  useEffect(() => {
    if (isOpen) {
      setKeys(getStoredApiKeys());
      fetchServerStatus();
    }
  }, [isOpen]);

  const fetchServerStatus = async () => {
    try {
      const res = await fetch("/api/status");
      if (res.ok) {
        const data = await res.json();
        setServerStatus(data);
      }
    } catch (err) {
      console.error("Failed to fetch API status:", err);
    }
  };

  const handleSave = () => {
    saveStoredApiKeys(keys);
    setSavedSuccess(true);
    onKeysUpdated();
    setTimeout(() => {
      setSavedSuccess(false);
      onClose();
    }, 1200);
  };

  const handleClear = () => {
    clearStoredApiKeys();
    setKeys({});
    onKeysUpdated();
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-xl bg-soc-darker border border-soc-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Modal Header */}
        <div className="p-5 border-b border-soc-border bg-soc-dark/80 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
              <Key className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Threat Intelligence API Keys</h3>
              <p className="text-xs text-gray-400">Configure free-tier credentials for live threat scanning</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-soc-border/60 text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 font-mono text-xs">
          {/* Server status banner */}
          <div className="p-3.5 rounded-lg bg-soc-dark/70 border border-soc-border space-y-2">
            <div className="flex items-center gap-2 text-gray-300 font-bold">
              <Server className="w-3.5 h-3.5 text-blue-400" />
              <span>Server Environment Status (.env.local)</span>
            </div>
            
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-1">
              <div className="p-2 rounded bg-soc-darkest border border-soc-border/50 flex items-center justify-between">
                <span className="text-gray-400">VirusTotal:</span>
                {serverStatus?.virusTotalConfigured || keys.virusTotalKey ? (
                  <span className="text-emerald-400 flex items-center gap-1 font-bold">
                    <CheckCircle2 className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-amber-400">Demo Mode</span>
                )}
              </div>

              <div className="p-2 rounded bg-soc-darkest border border-soc-border/50 flex items-center justify-between">
                <span className="text-gray-400">AbuseIPDB:</span>
                {serverStatus?.abuseIpDbConfigured || keys.abuseIpDbKey ? (
                  <span className="text-emerald-400 flex items-center gap-1 font-bold">
                    <CheckCircle2 className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-amber-400">Demo Mode</span>
                )}
              </div>

              <div className="p-2 rounded bg-soc-darkest border border-soc-border/50 flex items-center justify-between">
                <span className="text-gray-400">Safe Browsing:</span>
                {serverStatus?.googleSafeBrowsingConfigured || keys.googleSafeBrowsingKey ? (
                  <span className="text-emerald-400 flex items-center gap-1 font-bold">
                    <CheckCircle2 className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-amber-400">Demo Mode</span>
                )}
              </div>
            </div>
          </div>

          <p className="text-gray-400 leading-relaxed">
            Keys entered below are stored strictly in your browser and sent securely to Next.js server proxies. You can also place them in your server-side <span className="text-soc-accent font-bold">.env.local</span> file.
          </p>

          {/* Key Form Fields */}
          <div className="space-y-4">
            {/* VirusTotal API Key */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-gray-300 font-bold flex items-center gap-1.5">
                  <span>VirusTotal API Key</span>
                  <span className="text-[10px] text-gray-500 font-normal">(URLs, IPs, Hashes, Files)</span>
                </label>
                <a
                  href="https://www.virustotal.com/gui/join-us"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-soc-accent hover:underline flex items-center gap-0.5 text-[10px]"
                >
                  <span>Get Free Key (500/day)</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <input
                type="password"
                placeholder={serverStatus?.virusTotalConfigured ? "• Server .env key active (leave blank to use server key) •" : "Enter 64-char VirusTotal API Key..."}
                value={keys.virusTotalKey || ""}
                onChange={(e) => setKeys({ ...keys, virusTotalKey: e.target.value })}
                className="w-full px-3.5 py-2.5 rounded-lg bg-soc-dark border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent"
              />
            </div>

            {/* AbuseIPDB Key */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-gray-300 font-bold flex items-center gap-1.5">
                  <span>AbuseIPDB API Key</span>
                  <span className="text-[10px] text-gray-500 font-normal">(IP Reputation & Abuse Scores)</span>
                </label>
                <a
                  href="https://www.abuseipdb.com/register"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-soc-accent hover:underline flex items-center gap-0.5 text-[10px]"
                >
                  <span>Get Free Key (1,000/day)</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <input
                type="password"
                placeholder={serverStatus?.abuseIpDbConfigured ? "• Server .env key active (leave blank to use server key) •" : "Enter AbuseIPDB API Key..."}
                value={keys.abuseIpDbKey || ""}
                onChange={(e) => setKeys({ ...keys, abuseIpDbKey: e.target.value })}
                className="w-full px-3.5 py-2.5 rounded-lg bg-soc-dark border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent"
              />
            </div>

            {/* Google Safe Browsing Key */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-gray-300 font-bold flex items-center gap-1.5">
                  <span>Google Safe Browsing API Key</span>
                  <span className="text-[10px] text-gray-500 font-normal">(Google Malware/Phishing Index)</span>
                </label>
                <a
                  href="https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-soc-accent hover:underline flex items-center gap-0.5 text-[10px]"
                >
                  <span>Get Free Google Key (10k/day)</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </a>
              </div>
              <input
                type="password"
                placeholder={serverStatus?.googleSafeBrowsingConfigured ? "• Server .env key active (leave blank to use server key) •" : "Enter Google Safe Browsing API Key..."}
                value={keys.googleSafeBrowsingKey || ""}
                onChange={(e) => setKeys({ ...keys, googleSafeBrowsingKey: e.target.value })}
                className="w-full px-3.5 py-2.5 rounded-lg bg-soc-dark border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent"
              />
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-soc-border bg-soc-dark/80 flex items-center justify-between">
          <button
            onClick={handleClear}
            className="px-3 py-2 rounded-lg text-gray-400 hover:text-red-400 hover:bg-red-500/10 transition-colors font-mono text-xs flex items-center gap-1.5"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Reset Local Keys</span>
          </button>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-soc-dark hover:bg-soc-border text-gray-300 font-mono text-xs transition-colors"
            >
              Cancel
            </button>
            <button
              onClick={handleSave}
              className="px-5 py-2 rounded-lg bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-mono font-bold text-xs flex items-center gap-1.5 transition-all shadow-lg shadow-soc-accent/20"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{savedSuccess ? "Saved!" : "Save Keys"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
