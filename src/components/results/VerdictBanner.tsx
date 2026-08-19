"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  AlertTriangle,
  ExternalLink,
  Copy,
  Check,
  Share2,
  FileText,
  Clock,
  Sparkles,
} from "lucide-react";
import { ScanResult, Verdict } from "@/types/threat";

interface VerdictBannerProps {
  result: ScanResult;
  onNewScan?: () => void;
}

export function VerdictBanner({ result }: VerdictBannerProps) {
  const [copied, setCopied] = useState(false);

  const getVerdictDetails = (verdict: Verdict, score: number) => {
    switch (verdict) {
      case "malicious":
        return {
          title: "Malicious Threat Detected",
          description: "Multiple threat intelligence sources flagged this target as dangerous. Interaction is hazardous.",
          badgeClass: "bg-red-500/10 text-red-400 border-red-500/30",
          glowClass: "cyber-glow-malicious border-red-500/50 bg-red-950/20",
          icon: <ShieldAlert className="w-10 h-10 text-red-400 animate-pulse" />,
          accentColor: "#ef4444",
        };
      case "suspicious":
        return {
          title: "Suspicious Activity Flagged",
          description: "Low-confidence detections or abnormal behavioral indicators were identified. Exercise caution.",
          badgeClass: "bg-amber-500/10 text-amber-400 border-amber-500/30",
          glowClass: "cyber-glow-suspicious border-amber-500/50 bg-amber-950/20",
          icon: <AlertTriangle className="w-10 h-10 text-amber-400" />,
          accentColor: "#f59e0b",
        };
      case "clean":
        return {
          title: "Clean / No Threats Detected",
          description: "All evaluated security engines reported this target as safe and free from known malware or phishing.",
          badgeClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          glowClass: "cyber-glow-clean border-emerald-500/50 bg-emerald-950/20",
          icon: <ShieldCheck className="w-10 h-10 text-emerald-400" />,
          accentColor: "#10b981",
        };
      default:
        return {
          title: "Unrated / Unknown",
          description: "Insufficient intelligence data found in public databases for this target.",
          badgeClass: "bg-gray-500/10 text-gray-400 border-gray-500/30",
          glowClass: "border-gray-700 bg-gray-900/30",
          icon: <ShieldQuestion className="w-10 h-10 text-gray-400" />,
          accentColor: "#6b7280",
        };
    }
  };

  const details = getVerdictDetails(result.verdict, result.threatScore);

  const copyExecutiveSummary = () => {
    let summaryText = `[Threat Intelligence Report]\n`;
    summaryText += `Target: ${result.target}\n`;
    summaryText += `Type: ${result.scanType.toUpperCase()}\n`;
    summaryText += `Verdict: ${result.verdict.toUpperCase()} (Threat Score: ${result.threatScore}/100)\n`;
    
    if (result.scanType === "url" || result.scanType === "hash" || result.scanType === "file") {
      summaryText += `Detections: ${result.positives} / ${result.totalEngines} engines flagged malicious\n`;
    } else if (result.scanType === "ip") {
      summaryText += `Abuse Confidence: ${result.abuseConfidenceScore}% | Country: ${result.countryName} (${result.countryCode})\n`;
      summaryText += `ISP: ${result.isp} | Total Reports: ${result.totalReports}\n`;
    }
    
    summaryText += `Timestamp: ${new Date(result.timestamp).toUTCString()}\n`;
    summaryText += `Generated via CyberIntel Threat Scanner`;

    navigator.clipboard.writeText(summaryText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`p-6 md:p-8 rounded-xl border transition-all duration-300 ${details.glowClass} relative overflow-hidden my-6`}>
      {/* Demo watermark banner if demo */}
      {result.isDemo && (
        <div className="absolute top-0 right-0 bg-gradient-to-l from-amber-500/20 to-transparent px-4 py-1 flex items-center gap-1.5 text-xs text-amber-300 font-mono border-b border-l border-amber-500/30 rounded-bl-lg">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Interactive Demo Mode</span>
        </div>
      )}

      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
        {/* Left: Icon & Verdict */}
        <div className="flex items-start gap-4">
          <div className="p-3.5 rounded-xl bg-soc-dark/90 border border-soc-border shadow-inner">
            {details.icon}
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2 mb-1.5">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold uppercase tracking-wider border ${details.badgeClass}`}>
                {result.verdict}
              </span>
              <span className="text-xs text-gray-400 font-mono flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {new Date(result.timestamp).toLocaleTimeString()}
              </span>
            </div>

            <h2 className="text-xl md:text-2xl font-bold text-white tracking-tight">
              {details.title}
            </h2>
            
            <p className="text-xs md:text-sm text-gray-300 mt-1 max-w-xl">
              {details.description}
            </p>

            <div className="mt-3 flex items-center gap-2">
              <span className="text-xs text-gray-400 font-mono">Target:</span>
              <span className="text-xs md:text-sm font-mono font-medium text-white px-2 py-0.5 rounded bg-soc-dark border border-soc-border truncate max-w-xs md:max-w-md select-all">
                {result.target}
              </span>
            </div>
          </div>
        </div>

        {/* Right: Score Gauge & Key Numbers */}
        <div className="flex flex-wrap items-center gap-4 w-full lg:w-auto justify-start lg:justify-end border-t lg:border-t-0 pt-4 lg:pt-0 border-soc-border/50">
          {/* Threat Score Gauge */}
          <div className="flex items-center gap-3 bg-soc-dark/80 px-4 py-3 rounded-xl border border-soc-border">
            <div className="text-right">
              <div className="text-xs text-gray-400 font-mono">Risk Index</div>
              <div className="text-2xl font-black font-mono" style={{ color: details.accentColor }}>
                {result.threatScore}<span className="text-xs text-gray-400 font-normal">/100</span>
              </div>
            </div>
            
            {/* Circular score ring visualization */}
            <div className="w-12 h-12 relative flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-gray-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  strokeDasharray={`${result.threatScore}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke={details.accentColor}
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
            </div>
          </div>

          {/* Quick stats pills tailored to scan type */}
          {result.scanType === "cve" ? (
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="bg-soc-dark/80 border border-red-500/20 px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">CVSS v3.1</div>
                <div className="text-lg font-bold font-mono text-red-400">
                  {"cvssScore" in result ? result.cvssScore : 0} <span className="text-[10px] uppercase font-normal">{"severity" in result ? result.severity : ""}</span>
                </div>
              </div>
              <div className="bg-soc-dark/80 border border-amber-500/20 px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">EPSS Exploit Prob.</div>
                <div className="text-lg font-bold font-mono text-amber-400">
                  {"epssScore" in result ? `${(result.epssScore * 100).toFixed(1)}%` : "0%"}
                </div>
              </div>
            </div>
          ) : result.scanType === "email" ? (
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">Breaches Exposed</div>
                <div className="text-lg font-bold font-mono text-amber-400">{"breachCount" in result ? result.breachCount : 0}</div>
              </div>
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">Disposable Box</div>
                <div className="text-lg font-bold font-mono text-gray-200">{"isDisposable" in result && result.isDisposable ? "YES" : "NO"}</div>
              </div>
            </div>
          ) : result.scanType === "domain" ? (
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">Domain Age</div>
                <div className="text-lg font-bold font-mono text-emerald-400">{"domainAgeDays" in result && result.domainAgeDays ? `${result.domainAgeDays}d` : "Established"}</div>
              </div>
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-[11px] text-gray-400">DGA Entropy</div>
                <div className="text-lg font-bold font-mono text-amber-400">{"dgaEntropyScore" in result ? `${result.dgaEntropyScore}%` : "0%"}</div>
              </div>
            </div>
          ) : result.scanType === "ip" ? (
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-xs text-gray-400">Abuse Score</div>
                <div className="text-lg font-bold font-mono text-amber-400">{"abuseConfidenceScore" in result ? result.abuseConfidenceScore : 0}%</div>
              </div>
              <div className="bg-soc-dark/80 border border-soc-border px-3 py-2 rounded-lg">
                <div className="text-xs text-gray-400">Total Reports</div>
                <div className="text-lg font-bold font-mono text-gray-200">{"totalReports" in result ? result.totalReports : 0}</div>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-3 gap-2 text-center">
              <div className="bg-soc-dark/80 border border-red-500/20 px-3 py-2 rounded-lg">
                <div className="text-xs text-gray-400">Malicious</div>
                <div className="text-lg font-bold font-mono text-red-400">{"stats" in result ? result.stats?.malicious ?? 0 : 0}</div>
              </div>
              <div className="bg-soc-dark/80 border border-amber-500/20 px-3 py-2 rounded-lg">
                <div className="text-xs text-gray-400">Suspicious</div>
                <div className="text-lg font-bold font-mono text-amber-400">{"stats" in result ? result.stats?.suspicious ?? 0 : 0}</div>
              </div>
              <div className="bg-soc-dark/80 border border-emerald-500/20 px-3 py-2 rounded-lg">
                <div className="text-xs text-gray-400">Clean</div>
                <div className="text-lg font-bold font-mono text-emerald-400">{"stats" in result ? result.stats?.harmless ?? 0 : 0}</div>
              </div>
            </div>
          )}

          {/* Action buttons */}
          <div className="flex items-center gap-2">
            <button
              onClick={copyExecutiveSummary}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-soc-dark hover:bg-soc-border/60 text-xs font-mono text-gray-300 border border-soc-border transition-colors"
              title="Copy executive summary report to clipboard"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied" : "Copy Report"}</span>
            </button>

            {"virusTotalPermalink" in result && result.virusTotalPermalink && (
              <a
                href={result.virusTotalPermalink}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 px-3 py-2 rounded-lg bg-soc-dark hover:bg-soc-border/60 text-xs font-mono text-gray-300 border border-soc-border transition-colors"
                title="View full report on VirusTotal"
              >
                <span>VT Report</span>
                <ExternalLink className="w-3 h-3" />
              </a>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
