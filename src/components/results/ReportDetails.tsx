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
  Mail,
  Lock,
  ExternalLink,
  AlertTriangle,
  CheckCircle2,
  FileText,
} from "lucide-react";

interface ReportDetailsProps {
  result: ScanResult;
}

export function ReportDetails({ result }: ReportDetailsProps) {
  const [activeTab, setActiveTab] = useState<string>("overview");
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

        {result.scanType === "email" && (
          <button
            onClick={() => setActiveTab("email_details")}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === "email_details"
                ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <Mail className="w-3.5 h-3.5" />
            <span>Phishing & Breach Indicators</span>
          </button>
        )}

        {result.scanType === "domain" && (
          <button
            onClick={() => setActiveTab("domain_details")}
            className={`px-4 py-3 border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
              activeTab === "domain_details"
                ? "border-soc-accent text-soc-accent font-semibold bg-soc-dark/40"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>DNS & SSL Security</span>
          </button>
        )}

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

            {/* Email Overview */}
            {result.scanType === "email" && (
              <>
                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Mail className="w-3.5 h-3.5 text-purple-400" />
                    Domain / Provider
                  </div>
                  <div className="font-mono text-xs md:text-sm text-white font-medium">
                    {result.domain}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Shield className="w-3.5 h-3.5 text-emerald-400" />
                    Mail Server (MX)
                  </div>
                  <div className="font-mono text-xs md:text-sm text-gray-200">
                    {result.hasMxRecords ? "Valid MX Configured" : "No MX Records (Undeliverable)"}
                  </div>
                </div>

                {result.typosquattingTarget && (
                  <div className="p-4 rounded-lg bg-soc-darker/60 border border-red-500/30 md:col-span-2">
                    <div className="text-xs text-red-400 font-mono flex items-center gap-1.5 mb-1">
                      <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
                      Homoglyph / Typosquatting Target
                    </div>
                    <div className="font-mono text-xs md:text-sm text-white font-bold">
                      Impersonating: {result.typosquattingTarget}
                    </div>
                  </div>
                )}
              </>
            )}

            {/* Domain Overview */}
            {result.scanType === "domain" && (
              <>
                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Server className="w-3.5 h-3.5 text-cyan-400" />
                    Registrar Authority
                  </div>
                  <div className="font-mono text-xs md:text-sm text-white font-medium truncate">
                    {result.registrar || "Public Registrar"}
                  </div>
                </div>

                <div className="p-4 rounded-lg bg-soc-darker/60 border border-soc-border/60">
                  <div className="text-xs text-gray-400 font-mono flex items-center gap-1.5 mb-1">
                    <Lock className="w-3.5 h-3.5 text-emerald-400" />
                    SSL/TLS Certificate
                  </div>
                  <div className="font-mono text-xs md:text-sm text-emerald-400 font-medium">
                    {result.sslCertificate?.valid ? `Valid (${result.sslCertificate.daysRemaining}d left)` : "Invalid / Expired"}
                  </div>
                </div>
              </>
            )}

            {/* URL Overview */}
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

            {/* IP Overview */}
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
              </>
            )}

            {/* Hash & File Overview */}
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

        {/* Email Phishing & Breach Details Tab */}
        {activeTab === "email_details" && result.scanType === "email" && (
          <div className="space-y-4">
            {/* Phishing Indicators */}
            <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-2">
              <h4 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
                <span>Heuristic Phishing & Social Engineering Flags ({result.phishingIndicators.length})</span>
              </h4>
              {result.phishingIndicators.length > 0 ? (
                <ul className="space-y-1.5 text-xs font-mono text-gray-300">
                  {result.phishingIndicators.map((ind, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-soc-dark/60 p-2 rounded border border-soc-border/40">
                      <span className="text-red-400 font-bold">•</span>
                      <span>{ind}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>No deceptive phishing patterns or high-urgency wording detected.</span>
                </div>
              )}
            </div>

            {/* Extracted Links */}
            {result.extractedLinks && result.extractedLinks.length > 0 && (
              <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-2">
                <h4 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <Globe className="w-4 h-4 text-blue-400" />
                  <span>Extracted Embedded URLs ({result.extractedLinks.length})</span>
                </h4>
                <div className="space-y-1.5 text-xs font-mono">
                  {result.extractedLinks.map((link, idx) => (
                    <div key={idx} className="flex items-center justify-between gap-2 bg-soc-dark/60 p-2.5 rounded border border-soc-border/40">
                      <span className="text-gray-200 truncate">{link.url}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${link.isSuspicious ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"}`}>
                        {link.isSuspicious ? "Suspicious Link" : "Clean"}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Data Breach Telemetry */}
            <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-2">
              <h4 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                <Shield className="w-4 h-4 text-purple-400" />
                <span>Known Data Breach Exposures ({result.breachCount})</span>
              </h4>
              {result.breachesExposed.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {result.breachesExposed.map((b, idx) => (
                    <span key={idx} className="px-2.5 py-1 rounded bg-soc-dark border border-soc-border text-xs font-mono text-amber-300">
                      {b}
                    </span>
                  ))}
                </div>
              ) : (
                <div className="text-xs font-mono text-emerald-400 flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>No public credential breach exposures found for this account.</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Domain DNS & SSL Details Tab */}
        {activeTab === "domain_details" && result.scanType === "domain" && (
          <div className="space-y-4">
            {/* DNS Records */}
            <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-2">
              <h4 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                <Server className="w-4 h-4 text-cyan-400" />
                <span>Authoritative DNS Records ({result.dnsRecords.length})</span>
              </h4>
              <div className="space-y-1.5 font-mono text-xs">
                {result.dnsRecords.map((r, idx) => (
                  <div key={idx} className="flex items-center justify-between gap-2 bg-soc-dark/60 p-2.5 rounded border border-soc-border/40">
                    <span className="text-soc-accent font-bold w-12">{r.type}</span>
                    <span className="text-gray-200 truncate flex-1">{r.value}</span>
                    {r.ttl && <span className="text-gray-500 text-[10px]">TTL {r.ttl}s</span>}
                  </div>
                ))}
              </div>
            </div>

            {/* SSL Certificate Details */}
            {result.sslCertificate && (
              <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-2">
                <h4 className="text-xs font-mono font-bold text-white flex items-center gap-1.5">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  <span>SSL/TLS Encryption Certificate</span>
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                  <div className="bg-soc-dark p-2.5 rounded border border-soc-border">
                    <div className="text-gray-400 text-[10px]">Certificate Authority</div>
                    <div className="text-white font-medium truncate mt-0.5">{result.sslCertificate.issuer}</div>
                  </div>
                  <div className="bg-soc-dark p-2.5 rounded border border-soc-border">
                    <div className="text-gray-400 text-[10px]">Validity Remaining</div>
                    <div className="text-emerald-400 font-medium mt-0.5">{result.sslCertificate.daysRemaining} Days</div>
                  </div>
                  <div className="bg-soc-dark p-2.5 rounded border border-soc-border">
                    <div className="text-gray-400 text-[10px]">Self-Signed Status</div>
                    <div className="text-white font-medium mt-0.5">{result.sslCertificate.isSelfSigned ? "Yes (Untrusted)" : "No (Trusted CA)"}</div>
                  </div>
                </div>
              </div>
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
