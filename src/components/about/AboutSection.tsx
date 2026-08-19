import React from "react";
import {
  Globe,
  Network,
  Hash,
  UploadCloud,
  QrCode,
  Shield,
  Key,
  CheckCircle2,
  Lock,
  Cpu,
  Zap,
  User,
  Code2,
  Terminal,
  Mail,
  Bug,
  Server,
} from "lucide-react";

export function AboutSection() {
  const steps = [
    {
      icon: <Globe className="w-5 h-5 text-blue-400" />,
      title: "1. URL Threat Scanner",
      badge: "VirusTotal + Google Safe Browsing",
      description:
        "Enter any website link, shortened URL, or domain. Analyzes 70+ antivirus engines and Google Safe Browsing to detect phishing, credential harvesters, malware distribution, and IP grabbers (iplogger, grabify).",
      tips: "Includes automated HTTP 301/302 redirect tracking to reveal hidden destination endpoints.",
    },
    {
      icon: <Network className="w-5 h-5 text-purple-400" />,
      title: "2. IP Reputation & Threat Lookup",
      badge: "AbuseIPDB + VirusTotal",
      description:
        "Submit any IPv4 or IPv6 address. Fetches Abuse Confidence Score (0-100%), ISP organization, country of origin, usage type (VPN / Tor / Datacenter), and recent community security incident reports.",
      tips: "Ideal for investigating suspicious server connections, SSH brute-force attackers, and botnet scanning nodes.",
    },
    {
      icon: <Hash className="w-5 h-5 text-emerald-400" />,
      title: "3. Cryptographic Hash Lookup",
      badge: "MD5 • SHA-1 • SHA-256",
      description:
        "Input any 32-char MD5, 40-char SHA-1, or 64-char SHA-256 hash. Identifies known malware families (WannaCry, Emotet, RedLine Stealer, Mirai), file metadata, and AV detection ratios without needing the raw file.",
      tips: "Instantly checks if a binary has already been flagged in global threat databases.",
    },
    {
      icon: <UploadCloud className="w-5 h-5 text-amber-400" />,
      title: "4. File Upload & Binary Scanner",
      badge: "Web Crypto SHA-256 + VirusTotal Multi-Engine",
      description:
        "Drag and drop any suspicious file (executables, PDFs, documents, archives, APKs up to 32MB). Computes SHA-256 in your browser in milliseconds, checks hash databases, and uploads for deep multi-engine analysis if unknown.",
      tips: "Features built-in double-extension detection (e.g. invoice.pdf.exe) and macro/script exploit warnings.",
    },
    {
      icon: <QrCode className="w-5 h-5 text-pink-400" />,
      title: "5. QR Code Threat Scanner",
      badge: "Client-Side jsQR + Live Webcam Reticle",
      description:
        "Upload a QR code image/screenshot or turn on your live camera. The embedded URL is decoded directly in your browser without sending raw camera feeds to the server, and automatically piped into the URL threat scanner.",
      tips: "Protects against Quishing (QR Phishing) and malicious tracking redirects.",
    },
    {
      icon: <Mail className="w-5 h-5 text-indigo-400" />,
      title: "6. Email & Phishing Scanner",
      badge: "Disposable Detection • Typo-squatting • Phishing NLP",
      description:
        "Look up an email address or paste raw email headers and body text. Detects 500+ disposable temporary mail providers, brand typo-squatting (e.g. paypa1.com), data breach exposures, SPF/DMARC spoofing, and extracts embedded phishing links.",
      tips: "Automatically detects high-urgency panic language and financial extortion patterns.",
    },
    {
      icon: <Server className="w-5 h-5 text-cyan-400" />,
      title: "7. Domain & WHOIS / DNS Security",
      badge: "DNS-over-HTTPS • SSL Health • DGA Entropy",
      description:
        "Inspect any domain name. Resolves authoritative DNS records (A, MX, NS, TXT), flags Newly Registered Domains (< 30 days) used in active campaigns, audits SSL/TLS certificate validity, and measures DGA algorithmic entropy.",
      tips: "Checks SPF, DMARC, and DKIM email authentication compliance.",
    },
    {
      icon: <Bug className="w-5 h-5 text-red-400" />,
      title: "8. CVE Vulnerability & Exploit Intelligence",
      badge: "NVD v2.0 • FIRST EPSS • CISA KEV Catalog",
      description:
        "Query Common Vulnerabilities and Exposures (e.g. CVE-2021-44228 Log4Shell). Retrieves CVSS v3.1 base score, attack vectors, real-world Exploit Prediction (EPSS) probabilities, CISA Known Exploited Vulnerability alerts, and mitigation advisories.",
      tips: "Essential for vulnerability management, prioritizing zero-days and active weaponized exploits.",
    },
  ];

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Overview Intro */}
      <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border space-y-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">About ThreatVigil Threat Intelligence Platform</h2>
            <p className="text-xs text-gray-400 font-mono">Real-time 8-in-1 cyber threat intelligence and vulnerability scanning suite</p>
          </div>
        </div>

        <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
          ThreatVigil is a unified cyber threat intelligence platform designed to help security analysts, developers, and everyday users detect phishing, malware, ransomware, abusive network nodes, credential leaks, and weaponized CVE exploits in real time.
        </p>

        {/* Feature Highlights Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
          <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-1">
            <div className="flex items-center gap-2 font-bold text-white text-xs">
              <Cpu className="w-4 h-4 text-soc-accent" />
              <span>Multi-Source Engine</span>
            </div>
            <p className="text-[11px] text-gray-400">
              Aggregates telemetry from 70+ antivirus vendors with Google Safe Browsing, AbuseIPDB, NVD, and EPSS.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-1">
            <div className="flex items-center gap-2 font-bold text-white text-xs">
              <Lock className="w-4 h-4 text-blue-400" />
              <span>Client-Side Privacy</span>
            </div>
            <p className="text-[11px] text-gray-400">
              SHA-256 hashing and QR decoding are executed in-browser using Web Crypto API and jsQR before network transmission.
            </p>
          </div>

          <div className="p-4 rounded-lg bg-soc-darker/70 border border-soc-border/60 space-y-1">
            <div className="flex items-center gap-2 font-bold text-white text-xs">
              <Zap className="w-4 h-4 text-amber-400" />
              <span>Zero-Setup Demo Mode</span>
            </div>
            <p className="text-[11px] text-gray-400">
              Works instantly with built-in cybersecurity test signatures, or with your own free API keys.
            </p>
          </div>
        </div>
      </div>

      {/* How to Use Step-by-Step */}
      <div className="space-y-4">
        <div className="flex items-center justify-between border-b border-soc-border/60 pb-2">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <span>How to Use the 8 Scanners</span>
          </h3>
          <span className="text-xs font-mono text-soc-accent px-2 py-0.5 rounded bg-soc-accent/10 border border-soc-accent/30">
            8 Modules
          </span>
        </div>

        <div className="space-y-3">
          {steps.map((step, idx) => (
            <div
              key={idx}
              className="soc-card p-5 rounded-xl border border-soc-border space-y-2 hover:border-soc-accent/40 transition-colors"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-soc-dark border border-soc-border">
                    {step.icon}
                  </div>
                  <h4 className="text-sm font-bold text-white">{step.title}</h4>
                </div>
                <span className="text-[10px] font-mono text-gray-400 bg-soc-dark px-2 py-0.5 rounded border border-soc-border self-start sm:self-auto">
                  {step.badge}
                </span>
              </div>

              <p className="text-xs text-gray-300 leading-relaxed pl-0 sm:pl-10">
                {step.description}
              </p>

              <div className="pl-0 sm:pl-10 flex items-start gap-2 text-[11px] font-mono text-soc-accent bg-soc-dark/40 p-2.5 rounded-lg border border-soc-border/40">
                <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>{step.tips}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Free API Keys Guide */}
      <div className="soc-card p-6 rounded-xl border border-soc-border space-y-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
            <Key className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">How to Get Free API Keys</h3>
            <p className="text-[11px] text-gray-400 font-mono">Unlock live threat intelligence feeds for free</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 text-xs font-mono pt-1">
          <div className="p-3 rounded-lg bg-soc-darker border border-soc-border space-y-1">
            <div className="font-bold text-white">VirusTotal API v3</div>
            <div className="text-emerald-400 text-[11px]">500 req/day free</div>
            <p className="text-gray-400 text-[10px]">virustotal.com → Profile → API Key</p>
          </div>

          <div className="p-3 rounded-lg bg-soc-darker border border-soc-border space-y-1">
            <div className="font-bold text-white">AbuseIPDB API v2</div>
            <div className="text-purple-400 text-[11px]">1,000 checks/day free</div>
            <p className="text-gray-400 text-[10px]">abuseipdb.com → Account → API Key</p>
          </div>

          <div className="p-3 rounded-lg bg-soc-darker border border-soc-border space-y-1">
            <div className="font-bold text-white">Google Safe Browsing</div>
            <div className="text-blue-400 text-[11px]">10,000 req/day free</div>
            <p className="text-gray-400 text-[10px]">Google Cloud Console → Enable API Key</p>
          </div>
        </div>

        <p className="text-[11px] text-gray-400">
          Enter keys anytime by clicking <span className="text-soc-accent font-bold">API Settings</span> in the top header, or save them in your server <code className="text-gray-300">.env.local</code>.
        </p>
      </div>

      {/* Developer Attribution Card */}
      <div className="relative rounded-2xl p-6 md:p-8 border border-soc-accent/40 bg-gradient-to-r from-soc-darker via-soc-dark to-soc-darker overflow-hidden text-center shadow-2xl shadow-soc-accent/10">
        <div className="absolute top-0 right-0 w-36 h-36 bg-soc-accent/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-0 w-36 h-36 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col items-center justify-center space-y-2.5">
          <div className="w-14 h-14 rounded-full bg-soc-dark border-2 border-soc-accent flex items-center justify-center shadow-lg shadow-soc-accent/30 mb-0.5">
            <User className="w-7 h-7 text-soc-accent" />
          </div>

          <div className="space-y-1">
            <div className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-mono font-medium bg-soc-accent/10 text-soc-accent border border-soc-accent/30">
              <Code2 className="w-3 h-3" />
              <span>Lead Creator & Architect</span>
            </div>
            <h3 className="text-xl sm:text-2xl font-black text-white tracking-tight">
              Developed by Chinthala Nani
            </h3>
          </div>

          <p className="text-xs text-gray-300 max-w-md font-mono">
            Designed and built with passion for cybersecurity, threat intelligence, and empowering users with accessible detection tools.
          </p>
        </div>
      </div>
    </div>
  );
}
