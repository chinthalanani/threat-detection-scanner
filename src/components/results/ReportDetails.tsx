"use client";

import React, { useState } from "react";
import { ScanResult } from "@/types/threat";
import {
  FileCode,
  Globe,
  Network,
  Shield,
  Layers,
  FileCheck2,
  Calendar,
  Tag,
  Copy,
  Check,
  Server,
  User,
  MapPin,
} from "lucide-react";

interface ReportDetailsProps {
  result: ScanResult;
}

export function ReportDetails({ result }: ReportDetailsProps) {
  const [activeTab, setActiveTab] = useState<"overview" | "categories" | "signatures" | "abuse" | "raw">("overview");
  const [jsonCopied, setJsonCopied] = useState(false);

  const copyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setJsonCopied(true);
    setTimeout(() => setJsonCopied(false), 2000);
  };

  return (
    <div className="soc-card rounded-xl border border-soc-border overflow-hidden my-6">
      {/* Tab Navigation */}
      <div className="flex border-b border-soc-border/70 bg-soc-darker/80 overflow-x-auto text-xs font-mono">
        <button
          onClick={() => setActiveTab("overview")}
          className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === "overview"
              ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Shield className="w-3.5 h-3.5" />
          <span>Intelligence Overview</span>
        </button>

        {result.scanType === "url" && result.categories && Object.keys(result.categories).length > 0 && (
          <button
            onClick={() => setActiveTab("categories")}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === "categories"
                ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Categories & Web Taxonomy</span>
          </button>
        )}

        {(result.scanType === "hash" || result.scanType === "file") && (
          <button
            onClick={() => setActiveTab("signatures")}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === "signatures"
                ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <FileCheck2 className="w-3.5 h-3.5" />
            <span>Hashes & File Signatures</span>
          </button>
        )}

        {result.scanType === "ip" && result.recentReports && result.recentReports.length > 0 && (
          <button
            onClick={() => setActiveTab("abuse")}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === "abuse"
                ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            <span>Abuse Activity Logs ({result.recentReports.length})</span>
          </button>
        )}

        <button
          onClick={() => setActiveTab("raw")}
          className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === "raw"
              ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <FileCode className="w-3.5 h-3.5" />
          <span>Raw JSON Intelligence</span>
        </button>
      </div>

      {/* Tab Contents */}
      <div className="p-5 md:p-6 bg-soc-dark/40 text-sm">
        {/* Overview Tab */}
        {activeTab === "overview" && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
              <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                <Shield className="w-3.5 h-3.5 text-soc-accent" />
                Target Identifier
              </div>
              <div className="font-mono text-xs md:text-sm font-semibold text-white break-all">
                {result.target}
              </div>
            </div>

            <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
              <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                <Calendar className="w-3.5 h-3.5 text-blue-400" />
                Scan Timestamp
              </div>
              <div className="font-mono text-xs md:text-sm text-gray-200">
                {new Date(result.timestamp).toUTCString()}
              </div>
            </div>

            {result.scanType === "url" && (
              <>
                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Globe className="w-3.5 h-3.5 text-emerald-400" />
                    HTTP Status
                  </div>
                  <div className="font-mono text-sm text-emerald-400 font-semibold">
                    {result.httpResponseCode || 200} OK
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60 md:col-span-2">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Globe className="w-3.5 h-3.5 text-indigo-400" />
                    Google Safe Browsing Verdict
                  </div>
                  <div className="font-mono text-xs md:text-sm text-gray-200">
                    {result.googleSafeBrowsing?.isMalicious ? (
                      <span className="text-red-400 font-bold">
                        Threat Flagged: {result.googleSafeBrowsing.matches.map((m) => m.threatType).join(", ")}
                      </span>
                    ) : (
                      <span className="text-emerald-400">Passed - No matches in Google Blacklist</span>
                    )}
                  </div>
                </div>
              </>
            )}

            {result.scanType === "ip" && (
              <>
                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <MapPin className="w-3.5 h-3.5 text-pink-400" />
                    Country / Geolocation
                  </div>
                  <div className="font-mono text-sm text-white font-medium">
                    {result.countryName} ({result.countryCode})
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    ISP & Hosting Provider
                  </div>
                  <div className="font-mono text-xs md:text-sm text-gray-200 truncate" title={result.isp}>
                    {result.isp || "Unknown ISP"}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Layers className="w-3.5 h-3.5 text-amber-400" />
                    Usage Type
                  </div>
                  <div className="font-mono text-xs md:text-sm text-gray-200">
                    {result.usageType || "Commercial"}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <User className="w-3.5 h-3.5 text-purple-400" />
                    Distinct Reporters
                  </div>
                  <div className="font-mono text-sm text-gray-200">
                    {result.numDistinctUsers} unique security analysts
                  </div>
                </div>
              </>
            )}

            {(result.scanType === "hash" || result.scanType === "file") && (
              <>
                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Tag className="w-3.5 h-3.5 text-red-400" />
                    Malware Classification
                  </div>
                  <div className="font-mono text-xs md:text-sm text-red-400 font-bold truncate">
                    {result.malwareFamily || "No specific malware family label"}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <FileCheck2 className="w-3.5 h-3.5 text-blue-400" />
                    File Type
                  </div>
                  <div className="font-mono text-xs md:text-sm text-gray-200">
                    {result.fileType || "Binary / Executable"}
                  </div>
                </div>

                {result.fileSize && (
                  <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                    <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                      <Layers className="w-3.5 h-3.5 text-emerald-400" />
                      Payload Size
                    </div>
                    <div className="font-mono text-sm text-gray-200">
                      {(result.fileSize / 1024).toFixed(2)} KB ({result.fileSize.toLocaleString()} bytes)
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}

        {/* Categories Tab for URL */}
        {activeTab === "categories" && result.scanType === "url" && result.categories && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {Object.entries(result.categories).map(([vendor, cat]) => (
              <div key={vendor} className="p-3 rounded-lg bg-soc-darker/60 border border-soc-border/50">
                <div className="text-xs text-gray-400 font-mono">{vendor}</div>
                <div className="text-xs md:text-sm font-semibold text-gray-200 mt-1">{cat}</div>
              </div>
            ))}
          </div>
        )}

        {/* Signatures Tab for Hash / File */}
        {activeTab === "signatures" && (result.scanType === "hash" || result.scanType === "file") && (
          <div className="space-y-3">
            {result.md5 && (
              <div className="p-3 rounded-lg bg-soc-darker/60 border border-soc-border/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <span className="text-xs text-gray-400 font-mono uppercase w-20">MD5:</span>
                <span className="text-xs font-mono text-emerald-400 select-all break-all">{result.md5}</span>
              </div>
            )}
            {result.sha1 && (
              <div className="p-3 rounded-lg bg-soc-darker/60 border border-soc-border/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <span className="text-xs text-gray-400 font-mono uppercase w-20">SHA-1:</span>
                <span className="text-xs font-mono text-cyan-400 select-all break-all">{result.sha1}</span>
              </div>
            )}
            {result.sha256 && (
              <div className="p-3 rounded-lg bg-soc-darker/60 border border-soc-border/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <span className="text-xs text-gray-400 font-mono uppercase w-20">SHA-256:</span>
                <span className="text-xs font-mono text-indigo-400 select-all break-all">{result.sha256}</span>
              </div>
            )}
            {result.ssdeep && (
              <div className="p-3 rounded-lg bg-soc-darker/60 border border-soc-border/50 flex flex-col md:flex-row md:items-center justify-between gap-2">
                <span className="text-xs text-gray-400 font-mono uppercase w-20">SSDEEP:</span>
                <span className="text-xs font-mono text-amber-400 select-all break-all">{result.ssdeep}</span>
              </div>
            )}
          </div>
        )}

        {/* Abuse Reports for IP */}
        {activeTab === "abuse" && result.scanType === "ip" && result.recentReports && (
          <div className="space-y-3">
            {result.recentReports.map((report, idx) => (
              <div key={idx} className="p-3.5 rounded-lg bg-soc-darker/70 border border-soc-border/60">
                <div className="flex items-center justify-between gap-2 text-xs font-mono text-gray-400 mb-1.5">
                  <span className="flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                    Reporter #{report.reporterId} ({report.reporterCountryCode})
                  </span>
                  <span>{new Date(report.reportedAt).toLocaleDateString()}</span>
                </div>
                <p className="text-xs text-gray-200 font-mono bg-soc-dark/60 p-2 rounded border border-soc-border/40">
                  {report.comment}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Raw JSON Tab */}
        {activeTab === "raw" && (
          <div className="relative">
            <div className="flex justify-end mb-2">
              <button
                onClick={copyJson}
                className="flex items-center gap-1 px-3 py-1.5 rounded bg-soc-dark hover:bg-soc-border/60 text-xs font-mono text-gray-300 border border-soc-border transition-colors"
              >
                {jsonCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{jsonCopied ? "JSON Copied" : "Copy Raw JSON"}</span>
              </button>
            </div>
            <pre className="p-4 rounded-lg bg-soc-darkest border border-soc-border/60 overflow-x-auto text-xs font-mono text-emerald-400 max-h-96 leading-relaxed">
              {JSON.stringify(result, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
