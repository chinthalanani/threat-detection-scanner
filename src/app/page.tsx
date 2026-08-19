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
  Mail,
  Server,
} from "lucide-react";
import { Header } from "@/components/Header";
import { UrlScanner } from "@/components/scanners/UrlScanner";
import { IpScanner } from "@/components/scanners/IpScanner";
import { HashScanner } from "@/components/scanners/HashScanner";
import { FileScanner } from "@/components/scanners/FileScanner";
import { QrScanner } from "@/components/scanners/QrScanner";
import { EmailScanner } from "@/components/scanners/EmailScanner";
import { DomainScanner } from "@/components/scanners/DomainScanner";
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
  const [isHistoryOpen, setIsHistoryOpen] = useState(false);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [historyKey, setHistoryKey] = useState(0);

  const handleScanComplete = (result: ScanResult) => {
    setCurrentResult(result);
    setHistoryKey((prev) => prev + 1);

    // Trigger celebration confetti if result is completely clean
    if (result.verdict === "clean") {
      confetti({
        particleCount: 50,
        spread: 60,
        origin: { y: 0.8 },
        colors: ["#10b981", "#34d399", "#059669"],
      });
    }
  };

  const handleSelectFromHistory = (result: ScanResult) => {
    setActiveTab(result.scanType);
    setCurrentResult(result);
    setIsHistoryOpen(false);
  };

  const handleNewScan = () => {
    setCurrentResult(null);
  };

  const tabs: { id: ScanType; label: string; icon: React.ReactNode }[] = [
    { id: "url", label: "URL Scanner", icon: <Globe className="w-3.5 h-3.5" /> },
    { id: "ip", label: "IP Reputation", icon: <Network className="w-3.5 h-3.5" /> },
    { id: "hash", label: "Hash Lookup", icon: <Hash className="w-3.5 h-3.5" /> },
    { id: "file", label: "File Scanner", icon: <UploadCloud className="w-3.5 h-3.5" /> },
    { id: "qr", label: "QR Scanner", icon: <QrCode className="w-3.5 h-3.5" /> },
    { id: "email", label: "Email / Phish", icon: <Mail className="w-3.5 h-3.5" /> },
    { id: "domain", label: "Domain & DNS", icon: <Server className="w-3.5 h-3.5" /> },
    { id: "about", label: "About & Guide", icon: <Info className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="min-h-screen bg-soc-darkest text-gray-100 flex flex-col font-sans selection:bg-soc-accent selection:text-soc-darkest">
      {/* Top SOC Navbar */}
      <Header
        onOpenSettings={() => setIsSettingsOpen(true)}
        onOpenHistory={() => setIsHistoryOpen(true)}
        historyUpdatedKey={historyKey}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full">
        {/* Hero Section */}
        <div className="text-center max-w-3xl mx-auto mb-8 space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-soc-dark border border-soc-border text-xs font-mono text-soc-accent">
            <Zap className="w-3.5 h-3.5" />
            <span>Real-Time Multi-Source Threat Intelligence Suite</span>
          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black tracking-tight text-white">
            Analyze Threats. Protect Systems.
          </h1>

          <p className="text-sm md:text-base text-gray-400 max-w-2xl mx-auto">
            Scan suspicious URLs, IP addresses, hashes, files, QR codes, phishing emails, and domains across 70+ security vendors.
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-start sm:justify-center overflow-x-auto pb-3 mb-6">
          <div className="inline-flex p-1.5 rounded-xl bg-soc-darker border border-soc-border text-xs font-mono gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setCurrentResult(null);
                }}
                className={`flex items-center gap-1.5 px-3 py-2 rounded-lg transition-all whitespace-nowrap ${
                  activeTab === tab.id
                    ? "bg-soc-accent text-soc-darkest font-bold shadow-lg shadow-soc-accent/20"
                    : "text-gray-400 hover:text-white hover:bg-soc-dark"
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Active Scanner Input Tab */}
        <div className="mb-8">
          {activeTab === "url" && <UrlScanner onScanComplete={handleScanComplete} />}
          {activeTab === "ip" && <IpScanner onScanComplete={handleScanComplete} />}
          {activeTab === "hash" && <HashScanner onScanComplete={handleScanComplete} />}
          {activeTab === "file" && <FileScanner onScanComplete={handleScanComplete} />}
          {activeTab === "qr" && <QrScanner onScanComplete={handleScanComplete} />}
          {activeTab === "email" && <EmailScanner onScanComplete={handleScanComplete} />}
          {activeTab === "domain" && <DomainScanner onScanComplete={handleScanComplete} />}
          {activeTab === "about" && <AboutSection />}
        </div>

        {/* Scan Results Section */}
        {currentResult && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4 duration-300">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-soc-accent animate-pulse" />
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
                  Investigation Results
                </h3>
              </div>

              <button
                onClick={handleNewScan}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-soc-dark hover:bg-soc-border/60 text-xs font-mono text-gray-300 border border-soc-border transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5" />
                <span>New Query</span>
              </button>
            </div>

            {/* Verdict Banner */}
            <VerdictBanner result={currentResult} />

            {/* Security Vendor Matrix (if engines available) */}
            {currentResult.engines && currentResult.engines.length > 0 && (
              <VendorMatrix engines={currentResult.engines} />
            )}

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
            <span>ThreatVigil Security Intelligence Suite</span>
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
