import React from "react";
import Link from "next/link";
import { Shield, ArrowLeft } from "lucide-react";
import { AboutSection } from "@/components/about/AboutSection";

export const metadata = {
  title: "About & User Guide | ThreatVigil Threat Intelligence Scanner",
  description: "Learn how to use ThreatVigil to scan URLs, IP addresses, file hashes, binary uploads, and QR codes. Developed by Chinthala Nani.",
};

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-soc-darkest text-gray-100 flex flex-col font-sans selection:bg-soc-accent selection:text-soc-darkest">
      {/* Header */}
      <header className="border-b border-soc-border/80 bg-soc-darker/80 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <Link
            href="/"
            className="flex items-center gap-2 text-xs font-mono text-gray-300 hover:text-soc-accent transition-colors px-3 py-1.5 rounded-lg bg-soc-dark border border-soc-border hover:border-soc-accent/40"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back to Threat Scanner</span>
          </Link>

          <Link href="/" className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-soc-accent to-emerald-600 flex items-center justify-center shadow-lg shadow-soc-accent/20">
              <Shield className="w-4 h-4 text-soc-darkest" />
            </div>
            <span className="font-bold text-white tracking-tight">ThreatVigil</span>
          </Link>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10 w-full">
        <AboutSection />
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
