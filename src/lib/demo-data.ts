import {
  FileScanResult,
  HashScanResult,
  IpScanResult,
  UrlScanResult,
} from "@/types/threat";

export const SAMPLE_TARGETS = {
  url: [
    { label: "Phishing Credential Harvester", value: "http://secure-update-paypal-verify-account.net/login" },
    { label: "Known Safe Domain", value: "https://www.github.com" },
    { label: "Suspicious Dynamic DNS", value: "http://free-crypto-giveaway-airdrop.duckdns.org" },
  ],
  ip: [
    { label: "Abusive SSH Brute-Force C2", value: "185.220.101.5" },
    { label: "Google Public DNS (Clean)", value: "8.8.8.8" },
    { label: "Cloudflare DNS (Clean)", value: "1.1.1.1" },
    { label: "Compromised Scanning Host", value: "45.154.255.99" },
  ],
  hash: [
    { label: "EICAR Standard Antivirus Test File", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" },
    { label: "WannaCry Ransomware SHA256", value: "ed01ebf83334a19373140c2a21f4ea96fc51e07dc43141400d31654a260e40cb" },
    { label: "Emotet Banking Trojan MD5", value: "66403d1da9a4c52fd88e2c0e86b24de5" },
    { label: "Clean Windows Notepad SHA256", value: "4b825dc642cb6eb9a060e54bd8d69288fbee4904dc62975732f7e02b704c7d0d" },
  ]
};

export function getDemoUrlScan(url: string): UrlScanResult {
  const lower = url.toLowerCase();
  const isIpLogger = lower.includes("iplogger") || lower.includes("grabify") || lower.includes("2no.co") || lower.includes("yip.su") || lower.includes("iplis") || lower.includes("ezstat") || lower.includes("blasze");
  const isMalicious = isIpLogger || lower.includes("paypal") || lower.includes("airdrop") || lower.includes("malware") || lower.includes("phish");
  const isSuspicious = !isMalicious && (lower.includes("duckdns") || lower.includes("temp") || lower.includes("short"));

  const engines = [
    { 
      engineName: "Google Safe Browsing", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Social Engineering / IP Logger Tracker" : (isMalicious ? "Social Engineering / Phishing" : "Clean") 
    },
    { 
      engineName: "Kaspersky", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Malicious IP Logger / Tracker" : (isMalicious ? "Phishing URL" : "Clean") 
    },
    { 
      engineName: "Sophos", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Spyware / IP Harvester" : (isMalicious ? "Malicious Site" : "Clean") 
    },
    { 
      engineName: "BitDefender", 
      category: isMalicious ? ("malicious" as const) : (isSuspicious ? ("suspicious" as const) : ("harmless" as const)), 
      result: isIpLogger ? "Malicious Tracking Redirect" : (isMalicious ? "Fraudulent URL" : "Clean") 
    },
    { 
      engineName: "Fortinet", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Malicious Web Link" : (isMalicious ? "Phishing" : "Clean") 
    },
    { 
      engineName: "ESET", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Suspicious Redirection Service" : (isMalicious ? "Malware Distribution" : "Clean") 
    },
    { 
      engineName: "Avast-ThreatLabs", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "IP Harvester Redirect" : (isMalicious ? "Phishing" : "Clean") 
    },
    { engineName: "CRDF", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isMalicious ? "Malicious URL" : "Clean" },
    { engineName: "Forcepoint ThreatSeeker", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isMalicious ? "Suspicious Activity" : "Clean" },
    { engineName: "Microsoft Defender SmartScreen", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isIpLogger ? "Phishing / Tracking Redirect" : (isMalicious ? "Phishing" : "Clean") },
    { engineName: "Symantec / Broadcom", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isMalicious ? "Suspicious URL" : "Clean" },
    { engineName: "Yandex Safebrowsing", category: "undetected" as const, result: "Clean" },
    { engineName: "AlienVault", category: "harmless" as const, result: "Clean" },
    { engineName: "AlphaSOC", category: "harmless" as const, result: "Clean" },
    { engineName: "Webroot", category: "harmless" as const, result: "Clean" },
    { engineName: "Sucuri SiteCheck", category: "harmless" as const, result: "Clean" },
  ];

  const maliciousCount = engines.filter(e => e.category === "malicious").length;
  const suspiciousCount = engines.filter(e => e.category === "suspicious").length;
  const harmlessCount = engines.filter(e => e.category === "harmless").length;
  const undetectedCount = engines.filter(e => e.category === "undetected").length;

  return {
    scanId: `scan_url_${Date.now()}`,
    scanType: "url",
    target: url,
    verdict: isMalicious ? "malicious" : (isSuspicious ? "suspicious" : "clean"),
    threatScore: isMalicious ? 88 : (isSuspicious ? 35 : 0),
    positives: maliciousCount + suspiciousCount,
    totalEngines: engines.length,
    stats: {
      malicious: maliciousCount,
      suspicious: suspiciousCount,
      harmless: harmlessCount,
      undetected: undetectedCount,
      timeout: 0,
    },
    engines,
    categories: {
      "Google": isMalicious ? "Phishing / Social Engineering" : "Software & Technology",
      "BitDefender": isMalicious ? "Fraud" : "Information Technology",
      "Forcepoint": isMalicious ? "Malicious Web Sites" : "General Business",
    },
    finalUrl: url,
    httpResponseCode: 200,
    googleSafeBrowsing: {
      isMalicious: isMalicious,
      matches: isMalicious ? [
        { threatType: "SOCIAL_ENGINEERING", platformType: "ANY_PLATFORM", threatEntryType: "URL" }
      ] : [],
    },
    virusTotalPermalink: `https://www.virustotal.com/gui/url/demo`,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoIpScan(ip: string): IpScanResult {
  const isMalicious = ip.startsWith("185.") || ip.startsWith("45.") || ip.includes("666");
  const isCleanDns = ip === "8.8.8.8" || ip === "1.1.1.1";

  const engines = [
    { engineName: "AbuseIPDB Database", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Reported for SSH Brute Force & Port Scanning" : "Clean" },
    { engineName: "Kaspersky Threat Intelligence", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Botnet Node" : "Clean" },
    { engineName: "AlienVault OTX", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "C2 Server Indicator" : "Clean" },
    { engineName: "CrowdStrike Falcon", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Malicious IP" : "Clean" },
    { engineName: "Cisco Talos", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Poor Reputation" : "Clean" },
    { engineName: "Spamhaus DROP", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Compromised / Hijacked Subnet" : "Clean" },
    { engineName: "ThreatConnect", category: "harmless" as const, result: "Clean" },
    { engineName: "Fortinet", category: "harmless" as const, result: "Clean" },
  ];

  return {
    scanId: `scan_ip_${Date.now()}`,
    scanType: "ip",
    target: ip,
    verdict: isMalicious ? "malicious" : "clean",
    threatScore: isMalicious ? 92 : 0,
    abuseConfidenceScore: isMalicious ? 87 : 0,
    ipVersion: ip.includes(":") ? 6 : 4,
    countryCode: isMalicious ? "NL" : (isCleanDns ? "US" : "US"),
    countryName: isMalicious ? "Netherlands" : "United States",
    isp: isCleanDns ? (ip === "8.8.8.8" ? "Google LLC" : "Cloudflare, Inc.") : (isMalicious ? "Hostinger International Ltd" : "Amazon Technologies Inc."),
    domain: isCleanDns ? "dns.google" : (isMalicious ? "host-vps-direct.net" : "aws.amazon.com"),
    hostnames: isCleanDns ? ["dns.google"] : ["scanner-node-04.net"],
    usageType: isCleanDns ? "Data Center / Web Hosting / Transit" : (isMalicious ? "Commercial / VPN / Proxy" : "Commercial"),
    totalReports: isMalicious ? 412 : 0,
    numDistinctUsers: isMalicious ? 83 : 0,
    lastReportedAt: isMalicious ? new Date(Date.now() - 3600000).toISOString() : undefined,
    isWhitelisted: isCleanDns,
    isTor: isMalicious,
    recentReports: isMalicious ? [
      {
        reportedAt: new Date(Date.now() - 3600000).toISOString(),
        comment: "SSH login attempts with common passwords (admin, root, user). Blocked by fail2ban.",
        categories: [18, 22],
        reporterId: 44102,
        reporterCountryCode: "DE",
      },
      {
        reportedAt: new Date(Date.now() - 86400000).toISOString(),
        comment: "Port 445 / SMB enumeration and vulnerability probing.",
        categories: [14],
        reporterId: 12093,
        reporterCountryCode: "US",
      },
      {
        reportedAt: new Date(Date.now() - 172800000).toISOString(),
        comment: "Mass HTTP GET scanning for vulnerable WordPress plugins.",
        categories: [21],
        reporterId: 98124,
        reporterCountryCode: "GB",
      }
    ] : [],
    virusTotalStats: {
      malicious: isMalicious ? 6 : 0,
      suspicious: isMalicious ? 1 : 0,
      harmless: isMalicious ? 70 : 85,
      undetected: 10,
      timeout: 0,
    },
    engines,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoHashScan(hash: string): HashScanResult {
  const isEicar = hash.toLowerCase().includes("275a021b") || hash.toLowerCase().includes("44d88612fea8a8f36de82e1278abb02f");
  const isWannaCry = hash.toLowerCase().includes("ed01ebf8");
  const isEmotet = hash.toLowerCase().includes("66403d1d");
  const isMalicious = isEicar || isWannaCry || isEmotet;

  const malwareFamily = isEicar 
    ? "EICAR-Test-File (Standard AV Verification Sample)"
    : isWannaCry 
    ? "WannaCry.Ransomware.Cryptor" 
    : isEmotet 
    ? "Emotet.Trojan.Banker" 
    : (isMalicious ? "Trojan.GenericKD" : undefined);

  const engines = [
    { engineName: "Microsoft Defender", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (isEicar ? "Virus:DOS/EICAR_Test_File" : "Ransom:Win32/WannaCrypt") : "Clean" },
    { engineName: "Kaspersky", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (isEicar ? "EICAR-Test-File" : "Trojan-Ransom.Win32.Wanna.m") : "Clean" },
    { engineName: "CrowdStrike Falcon", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Win/malicious_confidence_1.00" : "Clean" },
    { engineName: "Sophos", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (isEicar ? "EICAR-AV-Test" : "Troj/Wanna-G") : "Clean" },
    { engineName: "BitDefender", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (isEicar ? "EICAR-Test-File" : "Gen:Variant.Ransom.Wannacry.1") : "Clean" },
    { engineName: "Symantec", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Ransom.Wannacry" : "Clean" },
    { engineName: "ESET-NOD32", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "EICAR Test File" : "Clean" },
    { engineName: "Avast", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "EICAR-Test-File" : "Clean" },
    { engineName: "SentinelOne", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Static AI - Malicious PE" : "Clean" },
    { engineName: "TrendMicro", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "EICAR_TEST_FILE" : "Clean" },
    { engineName: "Malwarebytes", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Generic.Trojan" : "Clean" },
    { engineName: "Yandex", category: "undetected" as const, result: "Clean" },
    { engineName: "ClamAV", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Eicar-Signature" : "Clean" },
    { engineName: "Tencent", category: "harmless" as const, result: "Clean" },
  ];

  const malCount = engines.filter(e => e.category === "malicious").length;
  const harmlessCount = engines.filter(e => e.category === "harmless").length;

  return {
    scanId: `scan_hash_${Date.now()}`,
    scanType: "hash",
    target: hash,
    hashType: hash.length === 32 ? "md5" : (hash.length === 40 ? "sha1" : "sha256"),
    verdict: isMalicious ? "malicious" : "clean",
    threatScore: isMalicious ? 96 : 0,
    positives: malCount,
    totalEngines: engines.length,
    stats: {
      malicious: malCount,
      suspicious: 0,
      harmless: harmlessCount,
      undetected: 1,
      timeout: 0,
    },
    malwareFamily,
    threatNames: isMalicious ? [malwareFamily!, "Trojan.Ransomware", "W32/WannaCryptor"] : [],
    meaningfulName: isEicar ? "eicar.com" : (isWannaCry ? "mssecsvc.exe" : "sample_binary.bin"),
    fileType: isEicar ? "DOS executable / text" : "Win32 Executable (PE32)",
    fileSize: isEicar ? 68 : 3514368,
    firstSeen: "2017-05-12T10:15:00Z",
    lastSeen: new Date().toISOString(),
    md5: "44d88612fea8a8f36de82e1278abb02f",
    sha1: "3395856ce81f2b7382dee72602f798b642f14140",
    sha256: hash.length === 64 ? hash : "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    tags: isMalicious ? ["ransomware", "trojan", "peexe", "direct-cpu-clock-access"] : ["signed", "verified"],
    engines,
    virusTotalPermalink: `https://www.virustotal.com/gui/file/${hash}`,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoFileScan(fileName: string, hash: string, fileSize: number): FileScanResult {
  const hashScan = getDemoHashScan(hash);
  return {
    ...hashScan,
    scanType: "file",
    fileName,
    fileSize,
    fileMimeType: "application/octet-stream",
  };
}
