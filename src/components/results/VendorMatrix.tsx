"use client";

import React, { useMemo, useState } from "react";
import { EngineResult, EngineVerdict } from "@/types/threat";
import {
  Search,
  CheckCircle2,
  AlertOctagon,
  AlertTriangle,
  HelpCircle,
  Clock,
  Filter,
} from "lucide-react";

interface VendorMatrixProps {
  engines: EngineResult[];
}

export function VendorMatrix({ engines = [] }: VendorMatrixProps) {
  const [search, setSearch] = useState("");
  const [filterCategory, setFilterCategory] = useState<string>("all");

  const counts = useMemo(() => {
    return {
      all: engines.length,
      malicious: engines.filter((e) => e.category === "malicious").length,
      suspicious: engines.filter((e) => e.category === "suspicious").length,
      harmless: engines.filter((e) => e.category === "harmless" || e.category === "undetected").length,
    };
  }, [engines]);

  const filteredEngines = useMemo(() => {
    return engines.filter((e) => {
      const matchesSearch =
        e.engineName.toLowerCase().includes(search.toLowerCase()) ||
        (e.result && e.result.toLowerCase().includes(search.toLowerCase()));

      if (!matchesSearch) return false;

      if (filterCategory === "all") return true;
      if (filterCategory === "malicious") return e.category === "malicious";
      if (filterCategory === "suspicious") return e.category === "suspicious";
      if (filterCategory === "clean") return e.category === "harmless" || e.category === "undetected";

      return true;
    });
  }, [engines, search, filterCategory]);

  const renderVerdictBadge = (category: EngineVerdict, result?: string | null) => {
    switch (category) {
      case "malicious":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-red-500/15 text-red-400 border border-red-500/30">
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>{result || "Malicious"}</span>
          </span>
        );
      case "suspicious":
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>{result || "Suspicious"}</span>
          </span>
        );
      case "harmless":
      case "undetected":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono text-emerald-400/90 bg-emerald-500/10 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>Clean</span>
          </span>
        );
      case "timeout":
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono text-gray-400 bg-gray-800/40">
            <Clock className="w-3 h-3 text-gray-500" />
            <span>Timeout</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono text-gray-400 bg-gray-800/40">
            <HelpCircle className="w-3 h-3 text-gray-500" />
            <span>Unrated</span>
          </span>
        );
    }
  };

  if (engines.length === 0) {
    return (
      <div className="soc-card p-6 rounded-xl text-center text-gray-400 text-sm font-mono">
        No individual vendor records available for this query.
      </div>
    );
  }

  return (
    <div className="soc-card rounded-xl border border-soc-border overflow-hidden my-6">
      {/* Header & Filter Controls */}
      <div className="p-4 md:p-5 border-b border-soc-border/70 flex flex-col md:flex-row md:items-center justify-between gap-4 bg-soc-darker/60">
        <div>
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <span>Security Vendor Detections</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-soc-dark text-gray-300 border border-soc-border">
              {engines.length} Engines
            </span>
          </h3>
          <p className="text-xs text-gray-400 mt-0.5">
            Detailed breakdown of antivirus, IDS, and threat intelligence engines.
          </p>
        </div>

        {/* Filter buttons & Search */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Quick Filter Pills */}
          <div className="flex items-center bg-soc-dark p-1 rounded-lg border border-soc-border text-xs font-mono">
            <button
              onClick={() => setFilterCategory("all")}
              className={`px-2.5 py-1 rounded transition-colors ${
                filterCategory === "all" ? "bg-soc-accent/20 text-soc-accent font-semibold" : "text-gray-400 hover:text-gray-200"
              }`}
            >
              All ({counts.all})
            </button>
            <button
              onClick={() => setFilterCategory("malicious")}
              className={`px-2.5 py-1 rounded transition-colors ${
                filterCategory === "malicious" ? "bg-red-500/20 text-red-400 font-semibold" : "text-gray-400 hover:text-red-300"
              }`}
            >
              Malicious ({counts.malicious})
            </button>
            {counts.suspicious > 0 && (
              <button
                onClick={() => setFilterCategory("suspicious")}
                className={`px-2.5 py-1 rounded transition-colors ${
                  filterCategory === "suspicious" ? "bg-amber-500/20 text-amber-400 font-semibold" : "text-gray-400 hover:text-amber-300"
                }`}
              >
                Suspicious ({counts.suspicious})
              </button>
            )}
            <button
              onClick={() => setFilterCategory("clean")}
              className={`px-2.5 py-1 rounded transition-colors ${
                filterCategory === "clean" ? "bg-emerald-500/20 text-emerald-400 font-semibold" : "text-gray-400 hover:text-emerald-300"
              }`}
            >
              Clean ({counts.harmless})
            </button>
          </div>

          {/* Engine Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter engines..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 text-xs font-mono rounded-lg bg-soc-dark border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent/50 w-36 md:w-48"
            />
          </div>
        </div>
      </div>

      {/* Engines Grid/Table */}
      <div className="max-h-96 overflow-y-auto divide-y divide-soc-border/40">
        {filteredEngines.length === 0 ? (
          <div className="p-8 text-center text-sm font-mono text-gray-400">
            No engines matched your current filter & search query.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-soc-border/40">
            {filteredEngines.map((engine, idx) => (
              <div
                key={`${engine.engineName}-${idx}`}
                className="p-3 md:p-3.5 flex items-center justify-between gap-3 hover:bg-soc-dark/40 transition-colors border-b border-soc-border/20"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div className="w-2 h-2 rounded-full flex-shrink-0 bg-soc-border" />
                  <div className="min-w-0">
                    <div className="text-xs font-semibold text-gray-200 font-mono truncate">
                      {engine.engineName}
                    </div>
                    {engine.method && (
                      <div className="text-[10px] text-gray-500 font-mono">
                        Method: {engine.method}
                      </div>
                    )}
                  </div>
                </div>

                <div className="flex-shrink-0">
                  {renderVerdictBadge(engine.category, engine.result)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
