import { NextRequest } from "next/server";

export interface ExtractedApiKeys {
  virusTotalKey?: string;
  abuseIpDbKey?: string;
  googleSafeBrowsingKey?: string;
}

export function getApiKeys(req?: NextRequest): ExtractedApiKeys {
  const vtHeader = req?.headers.get("x-virustotal-key");
  const abuseHeader = req?.headers.get("x-abuseipdb-key");
  const gsbHeader = req?.headers.get("x-google-safebrowsing-key");

  return {
    virusTotalKey: vtHeader || process.env.VIRUSTOTAL_API_KEY || process.env.NEXT_PUBLIC_VIRUSTOTAL_API_KEY || undefined,
    abuseIpDbKey: abuseHeader || process.env.ABUSEIPDB_API_KEY || process.env.NEXT_PUBLIC_ABUSEIPDB_API_KEY || undefined,
    googleSafeBrowsingKey: gsbHeader || process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.NEXT_PUBLIC_GOOGLE_SAFE_BROWSING_API_KEY || undefined,
  };
}
