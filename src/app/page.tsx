"use client";

import React, { useState } from "react";
import Link from "next/link";
import confetti from "canvas-confetti";
import {
  Globe,
  Network,
  Hash,
  UploadCloud,
  QrCode,
  Shield,
  Zap,
  RotateCcw,
  Sparkles,
  Search,
  Info,
} from "lucide-react";
import { Header } from "@/components/Header";
import { UrlScanner } from "@/components/scanners/UrlScanner";
import { IpScanner } from "@/components/scanners/IpScanner";
import { HashScanner } from "@/components/scanners/HashScanner";
import { FileScanner } from "@/components/scanners/FileScanner";
import { QrScanner } from "@/components/scanners/QrScanner";
import { AboutSection } from "@/components/about/AboutSection";
import { VerdictBanner } from "@/components/results/VerdictBanner";
import { VendorMatrix } from "@/components/results/VendorMatrix";
import { ReportDetails } from "@/components/results/ReportDetails";
import { HistoryDrawer } from "@/components/history/HistoryDrawer";
import { ApiConfigModal } from "@/components/settings/ApiConfigModal";
import { ScanResult, ScanType } from "@/types/threat";

export default function ThreatDashboard() {
  const [activeTab, setActiveTab] = useState<ScanType>("url");
  const [currentResult, setCurrentResult] = useState<ScanResult | null>(null);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [historyKey, setHistoryKey] = useState(0);

  const handleScanComplete = (result: ScanResult) => {
    setCurrentResult(result);
    setHistoryKey((prev) => prev + 1);

    // If completely clean verdict, trigger confetti
    if (result.verdict === "clean" && result.threatScore === 0) {
      try {
        confetti({
          particleCount: 40,
          spread: 60,
          origin: { y: 0.8 },
          colors: ["#10b981", "#00e599", "#3b82f6"],
        });
      } catch {
        // ignore
      }
    }
  };

  const handleSelectFromHistory = (result: ScanResult) => {
    setCurrentResult(result);
    setActiveTab(result.scanType);
  };

  const handleResetScan = () => {
    setCurrentResult(null);
  };

  return (
    <div className="min-h-screen flex flex-col bg-soc-darkest text-gray-100 font-sans selection:bg-soc-accent selection:text-soc-darkest">
      {/* Header */}
      <Header
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        historyUpdatedKey={historyKey}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Hero Section */}
        <div className="text-center max-w-3xl mx-auto mb-8 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-soc-dark border border-soc-border text-xs font-mono text-soc-accent">
            <Zap className="w-3.5 h-3.5" />
            <span>Real-Time Multi-Source Threat Intelligence</span>
          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-white">
            Analyze Threats. Protect Systems.
          </h1>

          <p className="text-sm md:text-base text-gray-400 max-w-2xl mx-auto">
            Scan suspicious URLs, IP addresses, cryptographic file hashes, binary uploads, and QR codes across 70+ security vendors including VirusTotal, AbuseIPDB, and Google Safe Browsing.
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-start sm:justify-center overflow-x-auto pb-3 mb-6">
          <div className="inline-flex p-1.5 rounded-xl bg-soc-darker border border-soc-border text-xs sm:text-sm font-mono">
            <button
              onClick={() => {
                setActiveTab("url");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "url"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>URL Scanner</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("ip");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "ip"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Network className="w-4 h-4" />
              <span>IP Reputation</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("hash");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "hash"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Hash className="w-4 h-4" />
              <span>Hash Lookup</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("file");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "file"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <UploadCloud className="w-4 h-4" />
              <span>File Scanner</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("qr");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "qr"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <QrCode className="w-4 h-4" />
              <span>QR Scanner</span>
            </button>

            <button
              onClick={() => {
                setActiveTab("about");
                setCurrentResult(null);
              }}
              className={`flex items-center gap-2 px-4 py-2.5 rounded-lg transition-all ${
                activeTab === "about"
                  ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                  : "text-gray-400 hover:text-white"
              }`}
            >
              <Info className="w-4 h-4" />
              <span>About & Guide</span>
            </button>
          </div>
        </div>

        {/* Active Scanner Input Tab */}
        <div className="mb-8">
          {activeTab === "url" && <UrlScanner onScanComplete={handleScanComplete} />}
          {activeTab === "ip" && <IpScanner onScanComplete={handleScanComplete} />}
          {activeTab === "hash" && <HashScanner onScanComplete={handleScanComplete} />}
          {activeTab === "file" && <FileScanner onScanComplete={handleScanComplete} />}
          {activeTab === "qr" && <QrScanner onScanComplete={handleScanComplete} />}
          {activeTab === "about" && <AboutSection />}
        </div>

        {/* Scan Results Section */}
        {currentResult && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-soc-accent" />
                <h3 className="text-lg font-bold text-white">Investigation Results</h3>
              </div>

              <button
                onClick={handleResetScan}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-dark hover:bg-soc-border/60 text-xs font-mono text-gray-300 border border-soc-border transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>New Query</span>
              </button>
            </div>

            {/* Verdict Card */}
            <VerdictBanner result={currentResult} />

            {/* Security Vendor Matrix */}
            <VendorMatrix engines={currentResult.engines || []} />

            {/* In-depth Intelligence Report */}
            <ReportDetails result={currentResult} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-soc-border/60 bg-soc-darker/60 py-6 text-center text-xs font-mono text-gray-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-gray-400">
            <Shield className="w-4 h-4 text-soc-accent" />
            <span>ThreatVigil Security Intelligence</span>
            <span>•</span>
            <Link href="/about" className="hover:text-soc-accent underline transition-colors">
              How to Use / About
            </Link>
          </div>

          <div className="flex flex-wrap items-center gap-4 text-gray-400">
            <button
              onClick={() => setIsSettingsOpen(true)}
              className="hover:text-soc-accent underline transition-colors"
            >
              API Settings
            </button>
            <span>•</span>
            <div className="text-gray-300">
              Developed by <span className="text-soc-accent font-bold">Chinthala Nani</span>
            </div>
          </div>
        </div>
      </footer>

      {/* Modals & Drawers */}
      <HistoryDrawer
        isOpen={isHistoryOpen}
        onClose={() => setIsHistoryOpen(false)}
        onSelectScan={handleSelectFromHistory}
      />

      <ApiConfigModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onKeysUpdated={() => setHistoryKey((prev) => prev + 1)}
      />
    </div>
  );
}
