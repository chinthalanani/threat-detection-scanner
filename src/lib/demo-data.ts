import {
  FileScanResult,
  HashScanResult,
  IpScanResult,
  UrlScanResult,
} from "@/types/threat";

export const SAMPLE_TARGETS = {
  url: [
    { label: "IP Logger & Tracker Redirect", value: "https://iplogger.com/2fEeb6" },
    { label: "Phishing Credential Harvester", value: "http://secure-update-paypal-verify-account.net/login" },
    { label: "MetaMask Crypto Drainer Phish", value: "https://metamask-claim-airdrop-rewards.duckdns.org" },
    { label: "Known Safe Domain (GitHub)", value: "https://www.github.com" },
  ],
  ip: [
    { label: "Cobalt Strike C2 / Brute-Force", value: "185.220.101.5" },
    { label: "Mirai Botnet Scanner Host", value: "45.154.255.99" },
    { label: "Google Public DNS (Clean)", value: "8.8.8.8" },
    { label: "Cloudflare DNS (Clean)", value: "1.1.1.1" },
  ],
  hash: [
    { label: "EICAR Antivirus Test Signature", value: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" },
    { label: "WannaCry Ransomware (SHA-256)", value: "ed01ebf83334a19373140c2a21f4ea96fc51e07dc43141400d31654a260e40cb" },
    { label: "Emotet Banking Trojan (MD5)", value: "66403d1da9a4c52fd88e2c0e86b24de5" },
    { label: "RedLine Stealer Payload (SHA-256)", value: "b455b5f257a41ebf2c52fb58f691c360dbb6d8a4e9b7a4efcf639a04f2bf94e3" },
    { label: "Clean Windows Notepad (SHA-256)", value: "4b825dc642cb6eb9a060e54bd8d69288fbee4904dc62975732f7e02b704c7d0d" },
  ]
};

// Known malware hash signatures dictionary
const KNOWN_MALWARE_HASHES: Record<string, { family: string; name: string; fileType: string; score: number }> = {
  // EICAR
  "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": { family: "EICAR-Test-File (Standard AV Sample)", name: "eicar.com", fileType: "DOS executable / text", score: 98 },
  "44d88612fea8a8f36de82e1278abb02f": { family: "EICAR-Test-File (Standard AV Sample)", name: "eicar.com", fileType: "DOS executable / text", score: 98 },
  "3395856ce81f2b7382dee72602f798b642f14140": { family: "EICAR-Test-File (Standard AV Sample)", name: "eicar.com", fileType: "DOS executable / text", score: 98 },
  
  // WannaCry
  "ed01ebf83334a19373140c2a21f4ea96fc51e07dc43141400d31654a260e40cb": { family: "WannaCry.Ransomware.Cryptor", name: "mssecsvc.exe", fileType: "Win32 Executable (PE32)", score: 96 },
  "84c82835a5d21bbcf75a61706d8ab549": { family: "WannaCry.Ransomware.Cryptor", name: "tasksche.exe", fileType: "Win32 Executable (PE32)", score: 96 },
  
  // Emotet
  "66403d1da9a4c52fd88e2c0e86b24de5": { family: "Emotet.Trojan.Banker", name: "emotet_payload.dll", fileType: "Win32 DLL", score: 94 },
  
  // RedLine Stealer
  "b455b5f257a41ebf2c52fb58f691c360dbb6d8a4e9b7a4efcf639a04f2bf94e3": { family: "RedLine.Stealer.CredentialTheft", name: "Client.exe", fileType: "Win32 .NET Executable", score: 92 },
  
  // Mirai
  "1a100a0adb22154a49c9584d4ab282c0": { family: "Mirai.Botnet.DDoS", name: "mirai.arm", fileType: "ELF 32-bit LSB executable, ARM", score: 90 },
};

export function getDemoUrlScan(url: string): UrlScanResult {
  const lower = url.toLowerCase();
  
  const isIpLogger = 
    lower.includes("iplogger") || 
    lower.includes("grabify") || 
    lower.includes("2no.co") || 
    lower.includes("yip.su") || 
    lower.includes("iplis") || 
    lower.includes("ezstat") || 
    lower.includes("blasze") ||
    lower.includes("stopify") ||
    lower.includes("spottyfly") ||
    lower.includes("bmwforum") ||
    lower.includes("yoatu.be");

  const isPhishing = 
    lower.includes("paypal") || 
    lower.includes("metamask") ||
    lower.includes("airdrop") || 
    lower.includes("malware") || 
    lower.includes("phish") ||
    lower.includes("binance") ||
    lower.includes("trustwallet") ||
    lower.includes("free-nitro") ||
    lower.includes("apple-id") ||
    lower.includes("netflix-bill") ||
    lower.includes("steam-gift");

  const isSuspicious = !isIpLogger && !isPhishing && (
    lower.includes("duckdns") || 
    lower.includes("temp") || 
    lower.includes("ngrok") ||
    lower.includes("loca.lt") ||
    lower.includes("trycloudflare") ||
    lower.includes(".ru/") ||
    lower.includes(".xyz/") ||
    lower.includes(".top/")
  );

  const isMalicious = isIpLogger || isPhishing;

  const engines = [
    { 
      engineName: "Google Safe Browsing", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Social Engineering / IP Harvester" : (isPhishing ? "Social Engineering / Phishing" : "Clean") 
    },
    { 
      engineName: "Kaspersky", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Malicious IP Logger / Tracker" : (isPhishing ? "Phishing URL" : "Clean") 
    },
    { 
      engineName: "Sophos", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Spyware / IP Grabber Link" : (isPhishing ? "Malicious Site" : "Clean") 
    },
    { 
      engineName: "BitDefender", 
      category: isMalicious ? ("malicious" as const) : (isSuspicious ? ("suspicious" as const) : ("harmless" as const)), 
      result: isIpLogger ? "Malicious Tracking Redirect" : (isPhishing ? "Fraudulent URL" : "Clean") 
    },
    { 
      engineName: "Fortinet", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Malicious Web Link" : (isPhishing ? "Phishing" : "Clean") 
    },
    { 
      engineName: "ESET", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "Suspicious Redirection Service" : (isPhishing ? "Malware Distribution" : "Clean") 
    },
    { 
      engineName: "Avast-ThreatLabs", 
      category: isMalicious ? ("malicious" as const) : ("harmless" as const), 
      result: isIpLogger ? "IP Harvester Redirect" : (isPhishing ? "Phishing" : "Clean") 
    },
    { engineName: "CRDF", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isMalicious ? "Malicious URL" : "Clean" },
    { engineName: "Forcepoint ThreatSeeker", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isMalicious ? "Suspicious Activity" : "Clean" },
    { engineName: "Microsoft Defender SmartScreen", category: isMalicious ? ("malicious" as const) : ("harmless" as const), result: isIpLogger ? "Phishing / Tracking Redirect" : (isPhishing ? "Phishing" : "Clean") },
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
    threatScore: isMalicious ? 92 : (isSuspicious ? 40 : 0),
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
      "Google": isIpLogger ? "IP Grabber & Tracking" : (isPhishing ? "Phishing / Social Engineering" : "Software & Technology"),
      "BitDefender": isMalicious ? "Fraud & Tracking" : "Information Technology",
      "Forcepoint": isMalicious ? "Malicious Web Sites" : "General Business",
    },
    finalUrl: url,
    httpResponseCode: 200,
    googleSafeBrowsing: {
      isMalicious: isMalicious,
      matches: isMalicious ? [
        { threatType: isIpLogger ? "SOCIAL_ENGINEERING / IP_GRABBER" : "SOCIAL_ENGINEERING", platformType: "ANY_PLATFORM", threatEntryType: "URL" }
      ] : [],
    },
    virusTotalPermalink: `https://www.virustotal.com/gui/url/demo`,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoIpScan(ip: string): IpScanResult {
  const isCleanDns = ip === "8.8.8.8" || ip === "1.1.1.1" || ip === "9.9.9.9" || ip === "208.67.222.222";
  
  // Known abusive ranges / scanning nodes
  const isMalicious = 
    !isCleanDns && (
      ip.startsWith("185.") || 
      ip.startsWith("45.") || 
      ip.startsWith("194.") || 
      ip.startsWith("91.") || 
      ip.startsWith("109.") || 
      ip.startsWith("141.") || 
      ip.startsWith("193.") || 
      ip.startsWith("5.188.") || 
      ip.startsWith("89.248.") ||
      ip.includes("666")
    );

  const engines = [
    { engineName: "AbuseIPDB Database", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Reported for SSH Brute Force, Port Scanning & Cobalt Strike C2" : "Clean" },
    { engineName: "Kaspersky Threat Intelligence", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Botnet Node / C2 Beacon" : "Clean" },
    { engineName: "AlienVault OTX", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "C2 Server Indicator" : "Clean" },
    { engineName: "CrowdStrike Falcon", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Malicious Host" : "Clean" },
    { engineName: "Cisco Talos", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Poor Reputation / Known Exploiter" : "Clean" },
    { engineName: "Spamhaus DROP", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Compromised / Hijacked Subnet" : "Clean" },
    { engineName: "ThreatConnect", category: "harmless" as const, result: "Clean" },
    { engineName: "Fortinet", category: "harmless" as const, result: "Clean" },
  ];

  return {
    scanId: `scan_ip_${Date.now()}`,
    scanType: "ip",
    target: ip,
    verdict: isMalicious ? "malicious" : "clean",
    threatScore: isMalicious ? 95 : 0,
    abuseConfidenceScore: isMalicious ? 92 : 0,
    ipVersion: ip.includes(":") ? 6 : 4,
    countryCode: isMalicious ? "NL" : (isCleanDns ? "US" : "US"),
    countryName: isMalicious ? "Netherlands (Bulletproof Hosting Subnet)" : "United States",
    isp: isCleanDns ? (ip === "8.8.8.8" ? "Google LLC" : "Cloudflare, Inc.") : (isMalicious ? "Hostinger International / Unknown VPS" : "Amazon Technologies Inc."),
    domain: isCleanDns ? "dns.google" : (isMalicious ? "host-vps-c2-direct.net" : "aws.amazon.com"),
    hostnames: isCleanDns ? ["dns.google"] : ["scanner-node-04.net"],
    usageType: isCleanDns ? "Data Center / Web Hosting / Transit" : (isMalicious ? "Commercial / Bulletproof VPN / Proxy / C2" : "Commercial"),
    totalReports: isMalicious ? 528 : 0,
    numDistinctUsers: isMalicious ? 94 : 0,
    lastReportedAt: isMalicious ? new Date(Date.now() - 1800000).toISOString() : undefined,
    isWhitelisted: isCleanDns,
    isTor: isMalicious,
    recentReports: isMalicious ? [
      {
        reportedAt: new Date(Date.now() - 1800000).toISOString(),
        comment: "Massive SSH login attempts and brute-force dictionary attacks. Blocked by Fail2Ban.",
        categories: [18, 22],
        reporterId: 44102,
        reporterCountryCode: "DE",
      },
      {
        reportedAt: new Date(Date.now() - 43200000).toISOString(),
        comment: "Cobalt Strike Team Server beacon listener detected on port 443.",
        categories: [15, 18],
        reporterId: 87401,
        reporterCountryCode: "US",
      },
      {
        reportedAt: new Date(Date.now() - 86400000).toISOString(),
        comment: "Port 445 / SMB enumeration and vulnerability probing.",
        categories: [14],
        reporterId: 12093,
        reporterCountryCode: "US",
      }
    ] : [],
    virusTotalStats: {
      malicious: isMalicious ? 8 : 0,
      suspicious: isMalicious ? 1 : 0,
      harmless: isMalicious ? 68 : 85,
      undetected: 8,
      timeout: 0,
    },
    engines,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoHashScan(hash: string): HashScanResult {
  const cleanHash = hash.trim().toLowerCase();
  
  // Check exact signature match
  const known = KNOWN_MALWARE_HASHES[cleanHash];
  
  // Or check known sample prefixes or substrings
  const isEicar = cleanHash.includes("275a021b") || cleanHash.includes("44d88612");
  const isWannaCry = cleanHash.includes("ed01ebf8") || cleanHash.includes("84c82835");
  const isEmotet = cleanHash.includes("66403d1d");
  const isRedLine = cleanHash.includes("b455b5f2");
  const isCleanNotepad = cleanHash.includes("4b825dc6");

  const isMalicious = Boolean(known) || isEicar || isWannaCry || isEmotet || isRedLine || (!isCleanNotepad && (cleanHash.startsWith("dead") || cleanHash.startsWith("bad") || cleanHash.startsWith("c001")));

  const malwareFamily = known?.family || (
    isEicar 
      ? "EICAR-Test-File (Standard AV Verification Sample)"
      : isWannaCry 
      ? "WannaCry.Ransomware.Cryptor" 
      : isEmotet 
      ? "Emotet.Trojan.Banker" 
      : isRedLine
      ? "RedLine.Stealer.CredentialTheft"
      : (isMalicious ? "Trojan.Win32.GenericKD" : undefined)
  );

  const engines = [
    { engineName: "Microsoft Defender", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "Trojan:Win32/Wacatac.B!ml") : "Clean" },
    { engineName: "Kaspersky", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "HEUR:Trojan.Win32.Generic") : "Clean" },
    { engineName: "CrowdStrike Falcon", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Win/malicious_confidence_1.00" : "Clean" },
    { engineName: "Sophos", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "Troj/Generic-K") : "Clean" },
    { engineName: "BitDefender", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "Gen:Variant.Trojan.1") : "Clean" },
    { engineName: "Symantec", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Malicious PE Trojan" : "Clean" },
    { engineName: "ESET-NOD32", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "A Variant of Win32/Trojan") : "Clean" },
    { engineName: "Avast", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "Win32:Evo-gen [Trj]") : "Clean" },
    { engineName: "SentinelOne", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Static AI - Malicious PE" : "Clean" },
    { engineName: "TrendMicro", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? (malwareFamily || "TROJ_GEN.R002C0WL921") : "Clean" },
    { engineName: "Malwarebytes", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Generic.Malware/Suspicious" : "Clean" },
    { engineName: "Yandex", category: "undetected" as const, result: "Clean" },
    { engineName: "ClamAV", category: isMalicious ? "malicious" as const : "harmless" as const, result: isMalicious ? "Win.Malware-Signature" : "Clean" },
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
    threatScore: isMalicious ? (known?.score || 94) : 0,
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
    threatNames: isMalicious ? [malwareFamily!, "Trojan.Malware", "PE.Heuristics"] : [],
    meaningfulName: known?.name || (isEicar ? "eicar.com" : (isWannaCry ? "mssecsvc.exe" : "sample_payload.exe")),
    fileType: known?.fileType || (isEicar ? "DOS executable / text" : "Win32 Executable (PE32)"),
    fileSize: isEicar ? 68 : 3514368,
    firstSeen: "2018-05-12T10:15:00Z",
    lastSeen: new Date().toISOString(),
    md5: hash.length === 32 ? hash : "44d88612fea8a8f36de82e1278abb02f",
    sha1: hash.length === 40 ? hash : "3395856ce81f2b7382dee72602f798b642f14140",
    sha256: hash.length === 64 ? hash : "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    tags: isMalicious ? ["malware", "trojan", "peexe", "direct-cpu-clock-access", "dropper"] : ["signed", "verified"],
    engines,
    virusTotalPermalink: `https://www.virustotal.com/gui/file/${hash}`,
    timestamp: new Date().toISOString(),
    isDemo: true,
  };
}

export function getDemoFileScan(fileName: string, hash: string, fileSize: number): FileScanResult {
  const lowerName = fileName.toLowerCase();
  
  // Detect risky extensions or double-extension attacks
  const isDangerousExt = 
    lowerName.endsWith(".exe") ||
    lowerName.endsWith(".scr") ||
    lowerName.endsWith(".bat") ||
    lowerName.endsWith(".cmd") ||
    lowerName.endsWith(".vbs") ||
    lowerName.endsWith(".ps1") ||
    lowerName.endsWith(".hta") ||
    lowerName.endsWith(".pif") ||
    lowerName.endsWith(".dll") ||
    lowerName.endsWith(".iso") ||
    lowerName.endsWith(".apk");

  const isDoubleExt = 
    lowerName.includes(".pdf.exe") ||
    lowerName.includes(".jpg.exe") ||
    lowerName.includes(".doc.exe") ||
    lowerName.includes(".png.scr") ||
    lowerName.includes(".invoice.bat");

  const isEicar = lowerName.includes("eicar") || hash.includes("275a021b");
  const isMalicious = isEicar || isDoubleExt || (isDangerousExt && (lowerName.includes("crack") || lowerName.includes("hack") || lowerName.includes("payload") || lowerName.includes("stealer") || lowerName.includes("trojan") || lowerName.includes("malware") || lowerName.includes("setup_free")));

  const hashScan = getDemoHashScan(isMalicious ? (isEicar ? "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f" : "ed01ebf83334a19373140c2a21f4ea96fc51e07dc43141400d31654a260e40cb") : hash);

  if (isDoubleExt || (isDangerousExt && isMalicious)) {
    hashScan.verdict = "malicious";
    hashScan.threatScore = 95;
    hashScan.malwareFamily = isDoubleExt ? "Trojan.DoubleExtension.ObfuscatedPayload" : "Trojan.Generic.Executable";
  }

  return {
    ...hashScan,
    scanType: "file",
    fileName,
    fileSize,
    fileMimeType: isDangerousExt ? "application/x-msdownload" : "application/octet-stream",
  };
}
