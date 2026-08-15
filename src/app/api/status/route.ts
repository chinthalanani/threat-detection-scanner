import { getApiKeys } from "@/lib/api-keys";
import { NextRequest, NextResponse } from "next/server";

export async function GET(req: NextRequest) {
  const keys = getApiKeys(req);
  
  const vtConfigured = Boolean(keys.virusTotalKey && keys.virusTotalKey.trim().length > 5);
  const abuseConfigured = Boolean(keys.abuseIpDbKey && keys.abuseIpDbKey.trim().length > 5);
  const gsbConfigured = Boolean(keys.googleSafeBrowsingKey && keys.googleSafeBrowsingKey.trim().length > 5);

  const usingServerKeys = Boolean(
    process.env.VIRUSTOTAL_API_KEY ||
    process.env.ABUSEIPDB_API_KEY ||
    process.env.GOOGLE_SAFE_BROWSING_API_KEY
  );

  return NextResponse.json({
    virusTotalConfigured: vtConfigured,
    abuseIpDbConfigured: abuseConfigured,
    googleSafeBrowsingConfigured: gsbConfigured,
    isAllConfigured: vtConfigured && abuseConfigured && gsbConfigured,
    usingServerKeys,
  });
}
