import { HistoryItem, ScanResult, ScanType, Verdict } from "@/types/threat";

const HISTORY_KEY = "threat_scanner_history_v1";
const API_KEYS_STORAGE_KEY = "threat_scanner_custom_api_keys_v1";

export interface StoredApiKeys {
  virusTotalKey?: string;
  abuseIpDbKey?: string;
  googleSafeBrowsingKey?: string;
}

export function saveScanToHistory(result: ScanResult): HistoryItem {
  try {
    const history = getScanHistory();
    
    let summary = "";
    if (result.scanType === "url") {
      summary = `${result.positives}/${result.totalEngines} engines flagged malicious`;
    } else if (result.scanType === "ip") {
      summary = `Abuse Score: ${result.abuseConfidenceScore}% • ${result.countryName || result.countryCode}`;
    } else if (result.scanType === "hash") {
      summary = result.malwareFamily || `${result.positives}/${result.totalEngines} vendor detections`;
    } else if (result.scanType === "file") {
      summary = `${result.fileName} • ${result.malwareFamily || `${result.positives}/${result.totalEngines} detections`}`;
    }

    const newItem: HistoryItem = {
      id: result.scanId || `hist_${Date.now()}`,
      scanType: result.scanType,
      target: result.target,
      verdict: result.verdict,
      threatScore: result.threatScore,
      summary,
      timestamp: result.timestamp || new Date().toISOString(),
      fullResult: result,
    };

    // Filter out duplicates with the same target and type to keep it clean, prepend new
    const updated = [newItem, ...history.filter(h => !(h.target === result.target && h.scanType === result.scanType))].slice(0, 50);
    
    if (typeof window !== "undefined") {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    }

    return newItem;
  } catch (err) {
    console.error("Failed to save scan to history:", err);
    return {
      id: `err_${Date.now()}`,
      scanType: result.scanType,
      target: result.target,
      verdict: result.verdict,
      threatScore: result.threatScore,
      summary: "Scan completed",
      timestamp: new Date().toISOString(),
      fullResult: result,
    };
  }
}

export function getScanHistory(): HistoryItem[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    if (!raw) return [];
    return JSON.parse(raw) as HistoryItem[];
  } catch (err) {
    console.error("Failed to load history from localStorage:", err);
    return [];
  }
}

export function deleteHistoryItem(id: string): HistoryItem[] {
  const history = getScanHistory().filter(item => item.id !== id);
  if (typeof window !== "undefined") {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
  }
  return history;
}

export function clearScanHistory(): void {
  if (typeof window !== "undefined") {
    localStorage.removeItem(HISTORY_KEY);
  }
}

export function exportHistoryAsJson(): string {
  const history = getScanHistory();
  return JSON.stringify(history, null, 2);
}

export function getStoredApiKeys(): StoredApiKeys {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(API_KEYS_STORAGE_KEY);
    if (!raw) return {};
    return JSON.parse(raw) as StoredApiKeys;
  } catch {
    return {};
  }
}

export function saveStoredApiKeys(keys: StoredApiKeys): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(API_KEYS_STORAGE_KEY, JSON.stringify(keys));
}

export function clearStoredApiKeys(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(API_KEYS_STORAGE_KEY);
}

/**
 * Creates custom headers with user-configured API keys if present
 */
export function getCustomApiHeaders(): Record<string, string> {
  const keys = getStoredApiKeys();
  const headers: Record<string, string> = {};
  if (keys.virusTotalKey?.trim()) {
    headers["x-virustotal-key"] = keys.virusTotalKey.trim();
  }
  if (keys.abuseIpDbKey?.trim()) {
    headers["x-abuseipdb-key"] = keys.abuseIpDbKey.trim();
  }
  if (keys.googleSafeBrowsingKey?.trim()) {
    headers["x-google-safebrowsing-key"] = keys.googleSafeBrowsingKey.trim();
  }
  return headers;
}
