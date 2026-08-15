import React from "react";
import Link from "next/link";
import {
  Shield,
  Globe,
  Network,
  Hash,
  UploadCloud,
  QrCode,
  Key,
  ArrowLeft,
  CheckCircle2,
  Lock,
  Cpu,
  Zap,
  User,
  Heart,
  Code2,
  Terminal,
} from "lucide-react";

export const metadata = {
  title: "About | ThreatVigil Threat Intelligence Scanner",
  description: "Learn how to use ThreatVigil to scan URLs, IP addresses, file hashes, binary uploads, and QR codes. Developed by Chinthala Nani.",
};

export default function AboutPage() {
  const steps = [
    {
      icon: <Globe className="w-6 h-6 text-blue-400" />,
      title: "1. URL Threat Scanner",
      badge: "VirusTotal + Google Safe Browsing",
      description:
        "Enter any suspicious website URL, shortened link, or domain. ThreatVigil cross-checks 70+ antivirus engines and Google's Blacklist to detect phishing, credential harvesters, malware distribution endpoints, and deceptive IP grabbers like iplogger or grabify.",
      tips: "Supports automated HTTP 301/302 redirect tracking to reveal hidden destination URLs.",
    },
    {
      icon: <Network className="w-6 h-6 text-purple-400" />,
      title: "2. IP Reputation & Threat Lookup",
      badge: "AbuseIPDB + VirusTotal",
      description:
        "Input any IPv4 or IPv6 address. The scanner fetches the Abuse Confidence Score (0-100%), ISP organization, country of origin, ASN, usage type (VPN / Tor / Datacenter), and recent community security incident reports.",
      tips: "Ideal for investigating suspicious server connections, SSH brute-force attackers, and botnet scanning nodes.",
    },
    {
      icon: <Hash className="w-6 h-6 text-emerald-400" />,
      title: "3. Cryptographic Hash Lookup",
      badge: "MD5 • SHA-1 • SHA-256",
      description:
        "Paste any 32-character MD5, 40-character SHA-1, or 64-character SHA-256 hash. The platform identifies known malware families (such as WannaCry, Emotet, RedLine Stealer, Mirai), file metadata, and AV detection ratios without needing the raw file.",
      tips: "Instantly tells you if a binary has already been flagged by global threat databases.",
    },
    {
      icon: <UploadCloud className="w-6 h-6 text-amber-400" />,
      title: "4. File Upload & Binary Scanner",
      badge: "Web Crypto SHA-256 + VirusTotal Multi-Engine",
      description:
        "Drag and drop any suspicious file (executables, PDFs, documents, archives, APKs up to 32MB). The app computes the cryptographic SHA-256 digest inside your browser in milliseconds, checks if it's already cataloged, and uploads it for deep multi-engine analysis if unknown.",
      tips: "Features built-in double-extension detection (e.g. invoice.pdf.exe) and macro/script exploit warnings.",
    },
    {
      icon: <QrCode className="w-6 h-6 text-pink-400" />,
      title: "5. QR Code Threat Scanner",
      badge: "Client-Side jsQR + Live Webcam Reticle",
      description:
        "Upload a QR code image/screenshot or turn on your live camera. The embedded URL is decoded directly in your browser without sending raw camera feeds to the server, and automatically piped into the URL threat scanner.",
      tips: "Protects against Quishing (QR Phishing) and malicious tracking redirects.",
    },
  ];

  return (
    <div className="min-h-screen bg-soc-darkest text-gray-100 flex flex-col font-sans selection:bg-soc-accent selection:text-soc-darkest">
      {/* Top Header */}
      <header className="border-b border-soc-border/80 bg-soc-darker/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link
            href="/"
            className="flex items-center gap-2 text-xs font-mono text-gray-300 hover:text-soc-accent transition-colors px-3 py-1.5 rounded-lg bg-soc-dark border border-soc-border hover:border-soc-accent/40"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Threat Scanner</span>
          </Link>

          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-soc-accent to-emerald-600 flex items-center justify-center shadow-lg shadow-soc-accent/20">
              <Shield className="w-4 h-4 text-soc-darkest" />
            </div>
            <span className="font-bold text-white tracking-tight">ThreatVigil</span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-12">
        {/* Hero Section */}
        <div className="text-center space-y-4 max-w-3xl mx-auto">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-soc-dark border border-soc-border text-xs font-mono text-soc-accent">
            <Zap className="w-3.5 h-3.5" />
            <span>Threat Intelligence User Guide & Architecture</span>
          </div>

          <h1 className="text-3xl sm:text-4xl md:text-5xl font-black text-white tracking-tight">
            About ThreatVigil Scanner
          </h1>

          <p className="text-sm md:text-base text-gray-400 leading-relaxed">
            ThreatVigil is a unified cyber threat intelligence platform designed to help security analysts, developers, and everyday users detect phishing, malware, ransomware, abusive network nodes, and tracking links in real time.
          </p>
        </div>

        {/* Core Architecture Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="soc-card p-6 rounded-xl border border-soc-border space-y-2">
            <div className="w-10 h-10 rounded-lg bg-soc-dark border border-soc-border flex items-center justify-center text-soc-accent mb-3">
              <Cpu className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-base">Multi-Engine Aggregation</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Consolidates threat feeds from 70+ antivirus engines (Kaspersky, Sophos, BitDefender, Microsoft) with Google Safe Browsing and AbuseIPDB.
            </p>
          </div>

          <div className="soc-card p-6 rounded-xl border border-soc-border space-y-2">
            <div className="w-10 h-10 rounded-lg bg-soc-dark border border-soc-border flex items-center justify-center text-blue-400 mb-3">
              <Lock className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-base">Zero-Leak Client Privacy</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Cryptographic SHA-256 hashing and QR decoding happen directly in your browser via Web Crypto API and jsQR before touching network proxies.
            </p>
          </div>

          <div className="soc-card p-6 rounded-xl border border-soc-border space-y-2">
            <div className="w-10 h-10 rounded-lg bg-soc-dark border border-soc-border flex items-center justify-center text-amber-400 mb-3">
              <Zap className="w-5 h-5" />
            </div>
            <h3 className="font-bold text-white text-base">Dual Mode Operation</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Functions seamlessly with live threat API keys, or in an interactive realistic simulation mode with built-in test signatures.
            </p>
          </div>
        </div>

        {/* How to Use Section */}
        <div className="space-y-6">
          <div className="border-b border-soc-border/70 pb-3 flex items-center justify-between">
            <div>
              <h2 className="text-xl sm:text-2xl font-bold text-white">How to Use ThreatVigil</h2>
              <p className="text-xs text-gray-400 font-mono mt-0.5">Comprehensive walkthrough of each scanner module</p>
            </div>
            <span className="text-xs font-mono text-soc-accent px-2.5 py-1 rounded bg-soc-accent/10 border border-soc-accent/30">
              5 Core Scanners
            </span>
          </div>

          <div className="space-y-4">
            {steps.map((step, idx) => (
              <div
                key={idx}
                className="soc-card p-6 rounded-xl border border-soc-border space-y-3 hover:border-soc-accent/40 transition-colors"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border">
                      {step.icon}
                    </div>
                    <h3 className="text-base sm:text-lg font-bold text-white">{step.title}</h3>
                  </div>
                  <span className="text-xs font-mono text-gray-400 bg-soc-dark px-2.5 py-1 rounded border border-soc-border self-start sm:self-auto">
                    {step.badge}
                  </span>
                </div>

                <p className="text-xs sm:text-sm text-gray-300 leading-relaxed pl-0 sm:pl-12">
                  {step.description}
                </p>

                <div className="pl-0 sm:pl-12 flex items-start gap-2 text-xs font-mono text-soc-accent bg-soc-dark/40 p-3 rounded-lg border border-soc-border/40">
                  <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                  <span>{step.tips}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* API Key Configuration Guide */}
        <div className="soc-card p-6 sm:p-8 rounded-xl border border-soc-border space-y-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">How to Add Free API Keys</h3>
              <p className="text-xs text-gray-400">Unlock live multi-source security feeds without spending money</p>
            </div>
          </div>

          <p className="text-xs sm:text-sm text-gray-300 leading-relaxed">
            All integrated services provide generous 100% free developer tiers:
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div className="p-3.5 rounded-lg bg-soc-darker border border-soc-border space-y-1.5">
              <div className="font-bold text-white">VirusTotal API v3</div>
              <div className="text-emerald-400">500 requests/day free</div>
              <p className="text-gray-400 text-[11px]">Sign up at virustotal.com → Profile → API Key</p>
            </div>

            <div className="p-3.5 rounded-lg bg-soc-darker border border-soc-border space-y-1.5">
              <div className="font-bold text-white">AbuseIPDB API v2</div>
              <div className="text-purple-400">1,000 checks/day free</div>
              <p className="text-gray-400 text-[11px]">Register at abuseipdb.com → Account → API Key</p>
            </div>

            <div className="p-3.5 rounded-lg bg-soc-darker border border-soc-border space-y-1.5">
              <div className="font-bold text-white">Google Safe Browsing</div>
              <div className="text-blue-400">10,000 requests/day free</div>
              <p className="text-gray-400 text-[11px]">Enable in Google Cloud Console → Create API Key</p>
            </div>
          </div>

          <p className="text-xs text-gray-400">
            You can enter your keys anytime by clicking <span className="text-soc-accent font-bold">API Settings</span> in the top navigation bar, or save them in your server environment variables (<code className="text-gray-300">.env.local</code>).
          </p>
        </div>

        {/* Developer Attribution Card */}
        <div className="relative rounded-2xl p-8 border border-soc-accent/40 bg-gradient-to-r from-soc-darker via-soc-dark to-soc-darker overflow-hidden text-center shadow-2xl shadow-soc-accent/10">
          <div className="absolute top-0 right-0 w-40 h-40 bg-soc-accent/10 rounded-full blur-3xl pointer-events-none" />
          <div className="absolute bottom-0 left-0 w-40 h-40 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

          <div className="relative z-10 flex flex-col items-center justify-center space-y-3">
            <div className="w-16 h-16 rounded-full bg-soc-dark border-2 border-soc-accent flex items-center justify-center shadow-lg shadow-soc-accent/30 mb-1">
              <User className="w-8 h-8 text-soc-accent" />
            </div>

            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 px-3 py-0.5 rounded-full text-xs font-mono font-medium bg-soc-accent/10 text-soc-accent border border-soc-accent/30">
                <Code2 className="w-3.5 h-3.5" />
                <span>Lead Creator & Architect</span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-black text-white tracking-tight">
                Developed by Chinthala Nani
              </h2>
            </div>

            <p className="text-xs sm:text-sm text-gray-300 max-w-lg font-mono">
              Designed and built with passion for cybersecurity, open intelligence, and empowering developers & users with reliable threat detection tools.
            </p>

            <div className="pt-2">
              <Link
                href="/"
                className="inline-flex items-center gap-2 px-6 py-2.5 rounded-xl bg-soc-accent hover:bg-emerald-400 text-soc-darkest font-mono font-bold text-xs transition-all shadow-lg shadow-soc-accent/20"
              >
                <Shield className="w-4 h-4" />
                <span>Start Scanning Threats Now</span>
              </Link>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-soc-border/60 bg-soc-darker/80 py-6 text-center text-xs font-mono text-gray-400">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-gray-300">
            <Shield className="w-4 h-4 text-soc-accent" />
            <span>ThreatVigil Security Intelligence Platform</span>
          </div>

          <div className="flex items-center gap-1.5 text-gray-300">
            <span>Developed by</span>
            <span className="text-soc-accent font-bold">Chinthala Nani</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
