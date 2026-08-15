import { getApiKeys } from "@/lib/api-keys";
import { getDemoIpScan } from "@/lib/demo-data";
import { checkRateLimit } from "@/lib/rate-limiter";
import { calculateThreatScore, parseVirusTotalEngines } from "@/lib/threat-scorer";
import { isValidIp } from "@/lib/validators";
import { AbuseReportItem, EngineResult, IpScanResult, VendorStats } from "@/types/threat";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const clientIp = req.headers.get("x-forwarded-for") || "local_client";
    const limit = checkRateLimit(`ip_${clientIp}`, 20, 60);
    if (!limit.allowed) {
      return NextResponse.json(
        { error: `Rate limit exceeded. Please wait ${limit.resetInSeconds} seconds before scanning again.` },
        { status: 429 }
      );
    }

    const body = await req.json();
    const rawIp = body?.ip?.trim();

    const ipCheck = isValidIp(rawIp);
    if (!ipCheck.isValid) {
      return NextResponse.json(
        { error: "Invalid IP address format. Please provide a valid IPv4 (e.g. 8.8.8.8) or IPv6 address." },
        { status: 400 }
      );
    }

    const targetIp = rawIp;
    const keys = getApiKeys(req);

    // If neither key is provided, return realistic demo intelligence data
    if (!keys.abuseIpDbKey && !keys.virusTotalKey) {
      const demoResult = getDemoIpScan(targetIp);
      return NextResponse.json(demoResult);
    }

    // Call AbuseIPDB and VirusTotal concurrently
    const [abuseResult, vtResult] = await Promise.allSettled([
      queryAbuseIpDb(targetIp, keys.abuseIpDbKey),
      queryVirusTotalIp(targetIp, keys.virusTotalKey),
    ]);

    const abuseData = abuseResult.status === "fulfilled" ? abuseResult.value : null;
    const vtData = vtResult.status === "fulfilled" ? vtResult.value : null;

    let countryCode = abuseData?.countryCode || vtData?.countryCode || "UNKNOWN";
    let countryName = abuseData?.countryName || vtData?.countryName || "Unknown Country";
    let isp = abuseData?.isp || vtData?.asOwner || "Unknown ISP";
    let domain = abuseData?.domain || vtData?.network;
    let hostnames = abuseData?.hostnames || [];
    let usageType = abuseData?.usageType || "Commercial / Hosting";
    let abuseConfidenceScore = abuseData?.abuseConfidenceScore ?? (vtData ? (vtData.stats.malicious > 0 ? 80 : 0) : 0);
    let totalReports = abuseData?.totalReports ?? (vtData?.stats.malicious || 0);
    let numDistinctUsers = abuseData?.numDistinctUsers ?? 0;
    let lastReportedAt = abuseData?.lastReportedAt;
    let isWhitelisted = abuseData?.isWhitelisted ?? false;
    let isTor = abuseData?.isTor ?? false;
    let recentReports: AbuseReportItem[] = abuseData?.reports || [];

    const stats: VendorStats = vtData?.stats || {
      malicious: abuseConfidenceScore > 50 ? 5 : (abuseConfidenceScore > 20 ? 1 : 0),
      suspicious: abuseConfidenceScore > 20 && abuseConfidenceScore <= 50 ? 2 : 0,
      harmless: abuseConfidenceScore === 0 ? 75 : 10,
      undetected: 10,
      timeout: 0,
    };

    let engines: EngineResult[] = vtData?.engines || [];
    
    // Add AbuseIPDB as a primary engine
    if (abuseData) {
      engines.unshift({
        engineName: "AbuseIPDB Threat Intelligence",
        category: abuseConfidenceScore >= 50 ? "malicious" : (abuseConfidenceScore > 15 ? "suspicious" : "harmless"),
        result: `Abuse Score: ${abuseConfidenceScore}% (${totalReports} reports)`,
        updateDate: new Date().toISOString().split("T")[0],
      });
    }

    const assessment = calculateThreatScore(stats, abuseConfidenceScore >= 50);

    const result: IpScanResult = {
      scanId: `scan_ip_${Date.now()}`,
      scanType: "ip",
      target: targetIp,
      verdict: assessment.verdict,
      threatScore: Math.max(assessment.score, abuseConfidenceScore),
      abuseConfidenceScore,
      ipVersion: ipCheck.version || 4,
      countryCode,
      countryName,
      isp,
      domain,
      hostnames,
      usageType,
      totalReports,
      numDistinctUsers,
      lastReportedAt,
      isWhitelisted,
      isTor,
      recentReports,
      virusTotalStats: stats,
      engines,
      timestamp: new Date().toISOString(),
      isDemo: false,
    };

    return NextResponse.json(result);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal IP scan error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

async function queryAbuseIpDb(ip: string, apiKey?: string) {
  if (!apiKey) return null;

  try {
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
      headers: {
        Key: apiKey,
        Accept: "application/json",
      },
      next: { revalidate: 300 },
    });

    if (!res.ok) {
      console.warn("AbuseIPDB request failed with status:", res.status);
      return null;
    }

    const json = await res.json();
    const data = json.data;
    if (!data) return null;

    return {
      ipAddress: data.ipAddress,
      isPublic: data.isPublic,
      ipVersion: data.ipVersion,
      isWhitelisted: data.isWhitelisted,
      abuseConfidenceScore: data.abuseConfidenceScore || 0,
      countryCode: data.countryCode || "UNKNOWN",
      countryName: data.countryName || "Unknown",
      usageType: data.usageType || "Unknown",
      isp: data.isp || "Unknown",
      domain: data.domain,
      hostnames: data.hostnames || [],
      isTor: data.isTor || false,
      totalReports: data.totalReports || 0,
      numDistinctUsers: data.numDistinctUsers || 0,
      lastReportedAt: data.lastReportedAt,
      reports: (data.reports || []).slice(0, 10).map((r: { reportedAt: string; comment: string; categories: number[]; reporterId: number; reporterCountryCode: string }) => ({
        reportedAt: r.reportedAt,
        comment: r.comment,
        categories: r.categories,
        reporterId: r.reporterId,
        reporterCountryCode: r.reporterCountryCode,
      })),
    };
  } catch (err) {
    console.error("AbuseIPDB query error:", err);
    return null;
  }
}

async function queryVirusTotalIp(ip: string, apiKey?: string) {
  if (!apiKey) return null;

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { "x-apikey": apiKey },
      next: { revalidate: 300 },
    });

    if (!res.ok) return null;

    const data = await res.json();
    const attr = data.data?.attributes;
    if (!attr) return null;

    const stats: VendorStats = {
      malicious: attr.last_analysis_stats?.malicious || 0,
      suspicious: attr.last_analysis_stats?.suspicious || 0,
      harmless: attr.last_analysis_stats?.harmless || 0,
      undetected: attr.last_analysis_stats?.undetected || 0,
      timeout: attr.last_analysis_stats?.timeout || 0,
    };

    const engines = parseVirusTotalEngines(attr.last_analysis_results || {});

    return {
      stats,
      engines,
      countryCode: attr.country || "UNKNOWN",
      countryName: attr.country || "Unknown",
      asOwner: attr.as_owner,
      network: attr.network,
    };
  } catch (err) {
    console.error("VirusTotal IP lookup error:", err);
    return null;
  }
}
