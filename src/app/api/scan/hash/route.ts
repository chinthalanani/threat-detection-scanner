import { getApiKeys } from "@/lib/api-keys";
import { getDemoHashScan } from "@/lib/demo-data";
import { checkRateLimit } from "@/lib/rate-limiter";
import { calculateThreatScore, parseVirusTotalEngines } from "@/lib/threat-scorer";
import { detectHashType } from "@/lib/validators";
import { HashScanResult, VendorStats } from "@/types/threat";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    const clientIp = req.headers.get("x-forwarded-for") || "local_client";
    const limit = checkRateLimit(`hash_${clientIp}`, 20, 60);
    if (!limit.allowed) {
      return NextResponse.json(
        { error: `Rate limit exceeded. Please wait ${limit.resetInSeconds} seconds before scanning again.` },
        { status: 429 }
      );
    }

    const body = await req.json();
    const rawHash = body?.hash?.trim()?.toLowerCase();

    const hashType = detectHashType(rawHash);
    if (!hashType) {
      return NextResponse.json(
        { error: "Invalid hash format. Please provide a valid MD5 (32 hex), SHA-1 (40 hex), or SHA-256 (64 hex) string." },
        { status: 400 }
      );
    }

    const targetHash = rawHash;
    const keys = getApiKeys(req);

    // If no VirusTotal key, return realistic demo data
    if (!keys.virusTotalKey) {
      const demoResult = getDemoHashScan(targetHash);
      return NextResponse.json(demoResult);
    }

    const vtData = await queryVirusTotalHash(targetHash, keys.virusTotalKey);
    if (!vtData) {
      return NextResponse.json(
        {
          scanId: `scan_hash_${Date.now()}`,
          scanType: "hash",
          target: targetHash,
          hashType,
          verdict: "unknown",
          threatScore: 0,
          positives: 0,
          totalEngines: 0,
          stats: {
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            timeout: 0,
          },
          engines: [],
          timestamp: new Date().toISOString(),
          isDemo: false,
          message: "Hash not found in VirusTotal database. This file may not have been analyzed yet.",
        } as HashScanResult
      );
    }

    const assessment = calculateThreatScore(vtData.stats);
    const totalEngines =
      vtData.stats.malicious +
      vtData.stats.suspicious +
      vtData.stats.harmless +
      vtData.stats.undetected;

    const result: HashScanResult = {
      scanId: `scan_hash_${Date.now()}`,
      scanType: "hash",
      target: targetHash,
      hashType,
      verdict: assessment.verdict,
      threatScore: assessment.score,
      positives: vtData.stats.malicious + vtData.stats.suspicious,
      totalEngines,
      stats: vtData.stats,
      malwareFamily: vtData.malwareFamily,
      threatNames: vtData.threatNames,
      meaningfulName: vtData.meaningfulName,
      fileType: vtData.fileType,
      fileSize: vtData.fileSize,
      firstSeen: vtData.firstSeen,
      lastSeen: vtData.lastSeen,
      md5: vtData.md5,
      sha1: vtData.sha1,
      sha256: vtData.sha256,
      ssdeep: vtData.ssdeep,
      tags: vtData.tags,
      engines: vtData.engines,
      virusTotalPermalink: `https://www.virustotal.com/gui/file/${targetHash}`,
      timestamp: new Date().toISOString(),
      isDemo: false,
    };

    return NextResponse.json(result);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal hash lookup error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

async function queryVirusTotalHash(hash: string, apiKey: string) {
  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": apiKey },
      next: { revalidate: 300 },
    });

    if (res.status === 404) return null;
    if (!res.ok) {
      throw new Error(`VirusTotal file lookup failed (${res.status})`);
    }

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
    
    // Extract threat classifications
    const popularClass = attr.popular_threat_classification;
    const malwareFamily = popularClass?.suggested_threat_label;
    const threatNames: string[] = [];
    if (popularClass?.popular_threat_name) {
      for (const item of popularClass.popular_threat_name) {
        if (item.value) threatNames.push(item.value);
      }
    }

    return {
      stats,
      engines,
      malwareFamily,
      threatNames,
      meaningfulName: attr.meaningful_name || attr.names?.[0],
      fileType: attr.type_description || attr.magic,
      fileSize: attr.size,
      firstSeen: attr.first_submission_date ? new Date(attr.first_submission_date * 1000).toISOString() : undefined,
      lastSeen: attr.last_submission_date ? new Date(attr.last_submission_date * 1000).toISOString() : undefined,
      md5: attr.md5,
      sha1: attr.sha1,
      sha256: attr.sha256,
      ssdeep: attr.ssdeep,
      tags: attr.tags || [],
    };
  } catch (err) {
    console.error("VT hash query error:", err);
    return null;
  }
}
