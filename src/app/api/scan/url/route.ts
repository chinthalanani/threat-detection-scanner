import { getApiKeys } from "@/lib/api-keys";
import { getDemoUrlScan } from "@/lib/demo-data";
import { checkRateLimit } from "@/lib/rate-limiter";
import { calculateThreatScore, parseVirusTotalEngines } from "@/lib/threat-scorer";
import { isValidUrl, normalizeUrl } from "@/lib/validators";
import { EngineResult, GoogleSafeBrowsingResult, UrlScanResult, VendorStats } from "@/types/threat";
import { NextRequest, NextResponse } from "next/server";

export async function POST(req: NextRequest) {
  try {
    // Rate limit check
    const clientIp = req.headers.get("x-forwarded-for") || "local_client";
    const limit = checkRateLimit(`url_${clientIp}`, 15, 60);
    if (!limit.allowed) {
      return NextResponse.json(
        { error: `Rate limit exceeded. Please wait ${limit.resetInSeconds} seconds before scanning again.` },
        { status: 429 }
      );
    }

    const body = await req.json();
    const rawUrl = body?.url;

    if (!rawUrl || !isValidUrl(rawUrl)) {
      return NextResponse.json(
        { error: "Invalid URL provided. Please enter a valid URL (e.g. example.com or https://example.com)." },
        { status: 400 }
      );
    }

    const targetUrl = normalizeUrl(rawUrl);
    const keys = getApiKeys(req);

    // If neither key is provided, return realistic demo intelligence data
    if (!keys.virusTotalKey && !keys.googleSafeBrowsingKey) {
      const demoResult = getDemoUrlScan(targetUrl);
      return NextResponse.json(demoResult);
    }

    // Call VirusTotal and Google Safe Browsing concurrently
    const [vtResult, gsbResult] = await Promise.allSettled([
      queryVirusTotalUrl(targetUrl, keys.virusTotalKey),
      queryGoogleSafeBrowsing(targetUrl, keys.googleSafeBrowsingKey),
    ]);

    let vtData = vtResult.status === "fulfilled" ? vtResult.value : null;
    const gsbData: GoogleSafeBrowsingResult | undefined =
      gsbResult.status === "fulfilled" ? gsbResult.value : undefined;

    // If VT failed or no key, build reasonable fallback with GSB if available
    let engines: EngineResult[] = [];
    let stats: VendorStats = {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      timeout: 0,
    };
    let categories: Record<string, string> = {};
    let finalUrl = targetUrl;
    let httpResponseCode = 200;
    let permalink = "";

    if (vtData) {
      stats = vtData.stats;
      engines = vtData.engines;
      categories = vtData.categories || {};
      finalUrl = vtData.finalUrl || targetUrl;
      httpResponseCode = vtData.httpResponseCode || 200;
      permalink = vtData.permalink || "";
    }

    // Incorporate Google Safe Browsing result as an authoritative engine
    if (gsbData) {
      if (gsbData.isMalicious) {
        stats.malicious += 1;
        engines.unshift({
          engineName: "Google Safe Browsing",
          category: "malicious",
          result: gsbData.matches.map((m) => m.threatType).join(", ") || "Malicious Threat",
          updateDate: new Date().toISOString().split("T")[0],
        });
      } else {
        stats.harmless += 1;
        engines.unshift({
          engineName: "Google Safe Browsing",
          category: "harmless",
          result: "Clean",
          updateDate: new Date().toISOString().split("T")[0],
        });
      }
    }

    const assessment = calculateThreatScore(stats, gsbData?.isMalicious);
    const totalEngines = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

    const result: UrlScanResult = {
      scanId: `scan_url_${Date.now()}`,
      scanType: "url",
      target: targetUrl,
      verdict: assessment.verdict,
      threatScore: assessment.score,
      positives: stats.malicious + stats.suspicious,
      totalEngines,
      stats,
      engines,
      categories,
      finalUrl,
      httpResponseCode,
      googleSafeBrowsing: gsbData,
      virusTotalPermalink: permalink,
      timestamp: new Date().toISOString(),
      isDemo: false,
    };

    return NextResponse.json(result);
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal scanning error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

async function queryVirusTotalUrl(url: string, apiKey?: string) {
  if (!apiKey) return null;

  try {
    // Generate URL identifier for VT v3: base64 without padding
    const urlId = Buffer.from(url).toString("base64").replace(/=/g, "");
    
    // First try GET existing analysis
    let res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: { "x-apikey": apiKey },
      next: { revalidate: 300 },
    });

    if (res.status === 404) {
      // Submit URL for scan
      const submitRes = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
          "x-apikey": apiKey,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: `url=${encodeURIComponent(url)}`,
      });

      if (!submitRes.ok) {
        throw new Error(`VirusTotal URL submission failed (${submitRes.status})`);
      }

      const submitData = await submitRes.json();
      const analysisId = submitData?.data?.id;

      // Poll analysis result (up to 3 tries)
      for (let i = 0; i < 3; i++) {
        await new Promise((r) => setTimeout(r, 1500));
        const analysisRes = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
          headers: { "x-apikey": apiKey },
        });
        if (analysisRes.ok) {
          const analysisJson = await analysisRes.json();
          if (analysisJson.data?.attributes?.status === "completed") {
            const attr = analysisJson.data.attributes;
            return {
              stats: {
                malicious: attr.stats?.malicious || 0,
                suspicious: attr.stats?.suspicious || 0,
                harmless: attr.stats?.harmless || 0,
                undetected: attr.stats?.undetected || 0,
                timeout: attr.stats?.timeout || 0,
              },
              engines: parseVirusTotalEngines(attr.results || {}),
              categories: {},
              finalUrl: url,
              httpResponseCode: 200,
              permalink: `https://www.virustotal.com/gui/url/${urlId}`,
            };
          }
        }
      }

      // If still pending, fetch URL object directly
      res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
        headers: { "x-apikey": apiKey },
      });
    }

    if (!res.ok) {
      return null;
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

    return {
      stats,
      engines,
      categories: attr.categories || {},
      finalUrl: attr.last_final_url || url,
      httpResponseCode: attr.last_http_response_code || 200,
      permalink: `https://www.virustotal.com/gui/url/${urlId}`,
    };
  } catch (err) {
    console.error("VT URL lookup error:", err);
    return null;
  }
}

async function queryGoogleSafeBrowsing(url: string, apiKey?: string): Promise<GoogleSafeBrowsingResult | undefined> {
  if (!apiKey) return undefined;

  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: {
          clientId: "threat-intelligence-scanner",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });

    if (!res.ok) {
      console.warn("GSB API returned status:", res.status);
      return undefined;
    }

    const data = await res.json();
    const matches = data.matches || [];
    return {
      isMalicious: matches.length > 0,
      matches,
    };
  } catch (err) {
    console.error("GSB query error:", err);
    return undefined;
  }
}
