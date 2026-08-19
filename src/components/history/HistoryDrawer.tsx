"use client";

import React, { useMemo, useState } from "react";
import {
  X,
  History,
  Trash2,
  Download,
  Search,
  ExternalLink,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  HelpCircle,
  Globe,
  Network,
  Hash,
  File,
  QrCode,
} from "lucide-react";
import { clearScanHistory, deleteHistoryItem, exportHistoryAsJson, getScanHistory } from "@/lib/storage";
import { HistoryItem, ScanResult, ScanType, Verdict } from "@/types/threat";

interface HistoryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectScan: (result: ScanResult) => void;
}

export function HistoryDrawer({ isOpen, onClose, onSelectScan }: HistoryDrawerProps) {
  const [history, setHistory] = useState<HistoryItem[]>(() => getScanHistory());
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");

  const refreshHistory = () => {
    setHistory(getScanHistory());
  };

  const handleClearAll = () => {
    if (window.confirm("Are you sure you want to clear your local scan history?")) {
      clearScanHistory();
      setHistory([]);
    }
  };

  const handleDelete = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    const updated = deleteHistoryItem(id);
    setHistory(updated);
  };

  const handleExport = () => {
    const jsonStr = exportHistoryAsJson();
    const blob = new Blob([jsonStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `threat_scanner_history_${new Date().toISOString().split("T")[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const filteredHistory = useMemo(() => {
    return history.filter((item) => {
      const matchesSearch =
        item.target.toLowerCase().includes(search.toLowerCase()) ||
        item.summary.toLowerCase().includes(search.toLowerCase());

      if (!matchesSearch) return false;
      if (typeFilter !== "all" && item.scanType !== typeFilter) return false;

      return true;
    });
  }, [history, search, typeFilter]);

  const getVerdictIcon = (verdict: Verdict) => {
    switch (verdict) {
      case "malicious":
        return <ShieldAlert className="w-4 h-4 text-red-400" />;
      case "suspicious":
        return <AlertTriangle className="w-4 h-4 text-amber-400" />;
      case "clean":
        return <ShieldCheck className="w-4 h-4 text-emerald-400" />;
      default:
        return <HelpCircle className="w-4 h-4 text-gray-400" />;
    }
  };

  const getTypeIcon = (type: ScanType) => {
    switch (type) {
      case "url":
        return <Globe className="w-3.5 h-3.5 text-blue-400" />;
      case "ip":
        return <Network className="w-3.5 h-3.5 text-purple-400" />;
      case "hash":
        return <Hash className="w-3.5 h-3.5 text-emerald-400" />;
      case "file":
        return <File className="w-3.5 h-3.5 text-amber-400" />;
      case "qr":
        return <QrCode className="w-3.5 h-3.5 text-pink-400" />;
      case "email":
        return <Globe className="w-3.5 h-3.5 text-blue-400" />;
      case "domain":
        return <Network className="w-3.5 h-3.5 text-emerald-400" />;
      default:
        return <HelpCircle className="w-3.5 h-3.5 text-gray-400" />;
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/70 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="w-full max-w-md bg-soc-darker border-l border-soc-border h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="p-5 border-b border-soc-border flex items-center justify-between bg-soc-dark/80">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-soc-dark border border-soc-border text-soc-accent">
              <History className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white">Scan History</h3>
              <p className="text-xs text-gray-400 font-mono">{history.length} saved investigations</p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-soc-border/60 text-gray-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Toolbar & Filter */}
        <div className="p-4 border-b border-soc-border/60 space-y-3 bg-soc-dark/40">
          {/* Search */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search target, domain, IP, or hash..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs font-mono rounded-lg bg-soc-dark border border-soc-border text-white placeholder-gray-500 focus:outline-none focus:border-soc-accent"
            />
          </div>

          {/* Filter Pills & Actions */}
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-1 overflow-x-auto text-[11px] font-mono pb-1">
              {["all", "url", "ip", "hash", "file", "email", "domain"].map((t) => (
                <button
                  key={t}
                  onClick={() => setTypeFilter(t)}
                  className={`px-2 py-1 rounded uppercase text-[10px] transition-colors whitespace-nowrap ${
                    typeFilter === t
                      ? "bg-soc-accent/20 text-soc-accent font-bold"
                      : "text-gray-400 hover:text-gray-200"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-1">
              <button
                onClick={handleExport}
                disabled={history.length === 0}
                className="p-1.5 rounded hover:bg-soc-border/60 text-gray-400 hover:text-white transition-colors disabled:opacity-40"
                title="Export history as JSON"
              >
                <Download className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={handleClearAll}
                disabled={history.length === 0}
                className="p-1.5 rounded hover:bg-red-500/20 text-gray-400 hover:text-red-400 transition-colors disabled:opacity-40"
                title="Clear all scan history"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        {/* History List */}
        <div className="flex-1 overflow-y-auto divide-y divide-soc-border/30 p-3 space-y-2">
          {filteredHistory.length === 0 ? (
            <div className="p-8 text-center text-sm font-mono text-gray-400">
              No scans found matching your search.
            </div>
          ) : (
            filteredHistory.map((item) => (
              <div
                key={item.id}
                onClick={() => {
                  onSelectScan(item.fullResult);
                  onClose();
                }}
                className="p-3.5 rounded-lg bg-soc-dark/60 hover:bg-soc-card border border-soc-border/50 hover:border-soc-accent/40 cursor-pointer transition-all group"
              >
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <div className="flex items-center gap-1.5 text-xs font-mono">
                    {getTypeIcon(item.scanType)}
                    <span className="text-gray-400 uppercase">{item.scanType}</span>
                    <span className="text-gray-600">•</span>
                    <span className="text-gray-500 text-[10px]">
                      {new Date(item.timestamp).toLocaleDateString()} {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    {getVerdictIcon(item.verdict)}
                    <button
                      onClick={(e) => handleDelete(item.id, e)}
                      className="opacity-0 group-hover:opacity-100 p-1 hover:text-red-400 text-gray-500 transition-opacity"
                    >
                      <Trash2 className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                <div className="font-mono text-xs font-semibold text-white truncate max-w-[280px]">
                  {item.target}
                </div>

                <div className="text-[11px] text-gray-400 mt-1 font-mono flex items-center justify-between">
                  <span>{item.summary}</span>
                  <span
                    className={`font-bold ${
                      item.verdict === "malicious"
                        ? "text-red-400"
                        : item.verdict === "suspicious"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    Score: {item.threatScore}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
