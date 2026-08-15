import { getApiKeys } from "@/lib/api-keys";
import { calculateThreatScore, parseVirusTotalEngines } from "@/lib/threat-scorer";
import { FileScanResult, VendorStats } from "@/types/threat";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const analysisId = searchParams.get("id");
    const fileName = searchParams.get("fileName") || "uploaded_file";

    if (!analysisId) {
      return NextResponse.json({ error: "Missing analysis ID." }, { status: 400 });
    }

    const keys = getApiKeys(req);
    if (!keys.virusTotalKey) {
      return NextResponse.json({ error: "VirusTotal API key is required to check analysis status." }, { status: 400 });
    }

    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": keys.virusTotalKey },
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: `VirusTotal analysis check failed with status ${res.status}` },
        { status: res.status }
      );
    }

    const data = await res.json();
    const attr = data?.data?.attributes;

    if (!attr) {
      return NextResponse.json({ error: "Invalid analysis response format" }, { status: 500 });
    }

    if (attr.status !== "completed") {
      return NextResponse.json({
        status: attr.status || "queued",
        progress: attr.stats ? `${attr.stats.malicious + attr.stats.harmless + attr.stats.undetected} engines completed` : "Scanning...",
      });
    }

    const stats: VendorStats = {
      malicious: attr.stats?.malicious || 0,
      suspicious: attr.stats?.suspicious || 0,
      harmless: attr.stats?.harmless || 0,
      undetected: attr.stats?.undetected || 0,
      timeout: attr.stats?.timeout || 0,
    };

    const engines = parseVirusTotalEngines(attr.results || {});
    const assessment = calculateThreatScore(stats);
    const totalEngines = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

    const fileResult: FileScanResult = {
      scanId: `scan_file_${Date.now()}`,
      scanType: "file",
      target: fileName,
      fileName,
      hashType: "sha256",
      verdict: assessment.verdict,
      threatScore: assessment.score,
      positives: stats.malicious + stats.suspicious,
      totalEngines,
      stats,
      engines,
      virusTotalPermalink: `https://www.virustotal.com/gui/file-analysis/${analysisId}`,
      timestamp: new Date().toISOString(),
      isDemo: false,
      isNewUpload: true,
      analysisId,
    };

    return NextResponse.json({
      status: "completed",
      result: fileResult,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error checking analysis status";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
