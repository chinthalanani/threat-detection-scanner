import { EngineResult, EngineVerdict, VendorStats, Verdict } from "@/types/threat";

export interface ScoreAssessment {
  score: number; // 0 - 100
  verdict: Verdict;
  levelLabel: string;
  colorClass: string;
  badgeBg: string;
  badgeBorder: string;
  badgeText: string;
  description: string;
}

export function calculateThreatScore(
  stats: VendorStats,
  extraMaliciousIndicator = false
): ScoreAssessment {
  const { malicious, suspicious, harmless, undetected } = stats;
  const total = malicious + suspicious + harmless + undetected;

  if (total === 0) {
    if (extraMaliciousIndicator) {
      return {
        score: 95,
        verdict: "malicious",
        levelLabel: "Critical Threat",
        colorClass: "text-red-400",
        badgeBg: "bg-red-950/60",
        badgeBorder: "border-red-500/40",
        badgeText: "text-red-400",
        description: "Flagged as malicious by authoritative security databases.",
      };
    }
    return {
      score: 0,
      verdict: "unknown",
      levelLabel: "Unrated / Unknown",
      colorClass: "text-gray-400",
      badgeBg: "bg-gray-900/60",
      badgeBorder: "border-gray-700/40",
      badgeText: "text-gray-400",
      description: "No intelligence data or security vendors have evaluated this target yet.",
    };
  }

  // Weightings: malicious carries heavy weight (100%), suspicious carries medium (40%)
  const rawWeighted = malicious * 1.0 + suspicious * 0.4 + (extraMaliciousIndicator ? 3.0 : 0);
  
  // Calculate percentage of positive engines
  let calculatedScore = Math.min(100, Math.round((rawWeighted / Math.max(1, total * 0.15)) * 100));

  if (malicious >= 3 || extraMaliciousIndicator) {
    calculatedScore = Math.max(75, calculatedScore);
  } else if (malicious >= 1) {
    calculatedScore = Math.max(45, calculatedScore);
  } else if (suspicious >= 2) {
    calculatedScore = Math.max(30, calculatedScore);
  }

  if (calculatedScore >= 45 || malicious >= 2 || (malicious >= 1 && suspicious >= 1) || extraMaliciousIndicator) {
    return {
      score: Math.max(65, calculatedScore),
      verdict: "malicious",
      levelLabel: "Malicious Threat",
      colorClass: "text-red-400",
      badgeBg: "bg-red-950/60",
      badgeBorder: "border-red-500/40",
      badgeText: "text-red-400",
      description: `Flagged as malicious by ${malicious} security vendor${malicious === 1 ? '' : 's'}. High risk of compromise.`,
    };
  }

  if (calculatedScore >= 15 || malicious === 1 || suspicious >= 1) {
    return {
      score: Math.max(25, calculatedScore),
      verdict: "suspicious",
      levelLabel: "Suspicious Activity",
      colorClass: "text-amber-400",
      badgeBg: "bg-amber-950/60",
      badgeBorder: "border-amber-500/40",
      badgeText: "text-amber-400",
      description: "Detected low-confidence threats or flagged by single vendor. Proceed with caution.",
    };
  }

  return {
    score: calculatedScore,
    verdict: "clean",
    levelLabel: "Clean / Harmless",
    colorClass: "text-emerald-400",
    badgeBg: "bg-emerald-950/60",
    badgeBorder: "border-emerald-500/40",
    badgeText: "text-emerald-400",
    description: `Evaluated by ${total} security engines with no threat detections.`,
  };
}

export function parseVirusTotalEngines(
  lastAnalysisResults: Record<string, { category: string; result?: string; method?: string; update_date?: string }> = {}
): EngineResult[] {
  return Object.entries(lastAnalysisResults).map(([engineName, data]) => {
    let cat: EngineVerdict = "undetected";
    if (data.category === "malicious") cat = "malicious";
    else if (data.category === "suspicious") cat = "suspicious";
    else if (data.category === "harmless") cat = "harmless";
    else if (data.category === "timeout") cat = "timeout";
    else if (data.category === "type-unsupported") cat = "type-unsupported";

    return {
      engineName,
      category: cat,
      result: data.result || (cat === 'harmless' || cat === 'undetected' ? 'Clean' : data.category),
      method: data.method,
      updateDate: data.update_date,
    };
  });
}
