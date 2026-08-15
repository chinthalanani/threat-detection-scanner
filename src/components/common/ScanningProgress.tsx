"use client";

import React, { useEffect, useState } from "react";
import { Loader2, Shield, Radio, CheckCircle2 } from "lucide-react";

interface ScanningProgressProps {
  scanType: string;
  target: string;
  customStatus?: string;
}

export function ScanningProgress({ scanType, target, customStatus }: ScanningProgressProps) {
  const [elapsed, setElapsed] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);

  const steps = [
    { label: "Validating input syntax & normalizing payload", duration: 1 },
    { label: scanType === "file" ? "Computing client-side SHA-256 hash" : "Querying signature databases & threat feeds", duration: 2 },
    { label: "Aggregating multi-vendor threat intelligence", duration: 4 },
    { label: "Cross-referencing VirusTotal, AbuseIPDB & Safe Browsing", duration: 6 },
    { label: "Computing normalized risk score & verdict", duration: 8 },
  ];

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsed((prev) => prev + 0.5);
    }, 500);

    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    if (elapsed < 1.5) setCurrentStep(0);
    else if (elapsed < 3.5) setCurrentStep(1);
    else if (elapsed < 6.0) setCurrentStep(2);
    else if (elapsed < 9.0) setCurrentStep(3);
    else setCurrentStep(4);
  }, [elapsed]);

  return (
    <div className="soc-card p-6 md:p-8 rounded-xl border border-soc-border relative overflow-hidden my-6">
      {/* Background cyber grid & scanline effect */}
      <div className="absolute inset-0 bg-gradient-to-b from-soc-accent/5 via-transparent to-transparent pointer-events-none" />
      <div className="absolute inset-x-0 h-1 bg-gradient-to-r from-transparent via-soc-accent/50 to-transparent animate-scanline pointer-events-none" />

      <div className="flex flex-col md:flex-row items-center gap-6 relative z-10">
        {/* Radar Spinner */}
        <div className="relative flex-shrink-0 w-24 h-24 flex items-center justify-center">
          <div className="absolute inset-0 rounded-full border border-soc-accent/30 animate-ping opacity-25" />
          <div className="absolute inset-2 rounded-full border border-soc-border bg-soc-dark/80" />
          <div className="absolute inset-4 rounded-full border border-soc-accent/40 animate-spin" style={{ animationDuration: "4s" }} />
          <Shield className="w-8 h-8 text-soc-accent animate-pulse relative z-10" />
          <div className="absolute bottom-0 right-0 bg-soc-darker border border-soc-border px-1.5 py-0.5 rounded text-[10px] font-mono text-soc-accent">
            {elapsed.toFixed(1)}s
          </div>
        </div>

        {/* Scan Details */}
        <div className="flex-1 text-center md:text-left">
          <div className="flex items-center justify-center md:justify-start gap-2 mb-1">
            <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-soc-accent/10 text-soc-accent border border-soc-accent/30">
              <Radio className="w-3 h-3 animate-pulse" />
              Scanning in progress
            </span>
            <span className="text-xs text-gray-400 font-mono uppercase tracking-wider">
              {scanType} scan
            </span>
          </div>

          <h3 className="text-base md:text-lg font-semibold text-white truncate max-w-xl font-mono">
            {target}
          </h3>

          <p className="text-xs md:text-sm text-gray-400 mt-1">
            {customStatus || steps[currentStep]?.label || "Interrogating multi-vendor threat engines..."}
          </p>

          {/* Stepper Progress */}
          <div className="grid grid-cols-5 gap-1.5 mt-4">
            {steps.map((step, idx) => (
              <div
                key={idx}
                className={`h-1.5 rounded-full transition-all duration-500 ${
                  idx < currentStep
                    ? "bg-soc-accent"
                    : idx === currentStep
                    ? "bg-soc-accent/60 animate-pulse"
                    : "bg-soc-border/50"
                }`}
                title={step.label}
              />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
