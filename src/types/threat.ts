export type ScanType = 'url' | 'ip' | 'hash' | 'file' | 'qr' | 'email' | 'domain' | 'cve' | 'about';

export type Verdict = 'clean' | 'suspicious' | 'malicious' | 'unknown';

export type EngineVerdict = 'malicious' | 'suspicious' | 'harmless' | 'undetected' | 'timeout' | 'type-unsupported';

export interface EngineResult {
  engineName: string;
  category: EngineVerdict;
  result?: string | null;
  method?: string;
  updateDate?: string;
}

export interface VendorStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: number;
}

export interface GoogleSafeBrowsingMatch {
  threatType: string;
  platformType: string;
  threatEntryType: string;
}

export interface GoogleSafeBrowsingResult {
  isMalicious: boolean;
  matches: GoogleSafeBrowsingMatch[];
}

export interface UrlScanResult {
  scanId: string;
  scanType: 'url';
  target: string;
  verdict: Verdict;
  threatScore: number; // 0 to 100
  positives: number;
  totalEngines: number;
  stats: VendorStats;
  engines: EngineResult[];
  categories?: Record<string, string>;
  finalUrl?: string;
  httpResponseCode?: number;
  googleSafeBrowsing?: GoogleSafeBrowsingResult;
  virusTotalPermalink?: string;
  timestamp: string;
  isDemo?: boolean;
}

export interface AbuseReportItem {
  reportedAt: string;
  comment: string;
  categories: number[];
  reporterId: number;
  reporterCountryCode: string;
}

export interface IpScanResult {
  scanId: string;
  scanType: 'ip';
  target: string;
  verdict: Verdict;
  threatScore: number; // 0 to 100
  abuseConfidenceScore: number; // 0 to 100 from AbuseIPDB
  ipVersion: 4 | 6;
  countryCode: string;
  countryName: string;
  isp: string;
  domain?: string;
  hostnames?: string[];
  usageType?: string;
  totalReports: number;
  numDistinctUsers: number;
  lastReportedAt?: string;
  isWhitelisted: boolean;
  isTor?: boolean;
  recentReports?: AbuseReportItem[];
  virusTotalStats?: VendorStats;
  engines?: EngineResult[];
  timestamp: string;
  isDemo?: boolean;
}

export interface HashScanResult {
  scanId: string;
  scanType: 'hash';
  target: string;
  hashType: 'md5' | 'sha1' | 'sha256';
  verdict: Verdict;
  threatScore: number;
  positives: number;
  totalEngines: number;
  stats: VendorStats;
  malwareFamily?: string;
  threatNames?: string[];
  meaningfulName?: string;
  fileType?: string;
  fileSize?: number;
  firstSeen?: string;
  lastSeen?: string;
  md5?: string;
  sha1?: string;
  sha256?: string;
  ssdeep?: string;
  tags?: string[];
  engines: EngineResult[];
  virusTotalPermalink?: string;
  timestamp: string;
  isDemo?: boolean;
}

export interface FileScanResult extends Omit<HashScanResult, 'scanType'> {
  scanType: 'file';
  fileName: string;
  fileMimeType?: string;
  isNewUpload?: boolean;
  analysisId?: string;
}

// --- NEW SCANNERS ---

export interface ExtractedEmailLink {
  url: string;
  isSuspicious: boolean;
  threatSummary?: string;
}

export interface EmailScanResult {
  scanId: string;
  scanType: 'email';
  target: string; // The email or snippet
  emailAddress?: string;
  mode: 'address' | 'content';
  verdict: Verdict;
  threatScore: number; // 0 to 100
  domain: string;
  isDisposable: boolean;
  isFreeMail: boolean;
  hasMxRecords: boolean;
  typosquattingTarget?: string;
  breachCount: number;
  breachesExposed: string[];
  phishingIndicators: string[];
  extractedLinks: ExtractedEmailLink[];
  spfStatus?: 'pass' | 'fail' | 'neutral' | 'unconfigured';
  dmarcStatus?: 'pass' | 'fail' | 'unconfigured';
  senderSpoofed?: boolean;
  engines: EngineResult[];
  timestamp: string;
  isDemo?: boolean;
}

export interface DnsRecordItem {
  type: string;
  value: string;
  ttl?: number;
}

export interface SslCertificateInfo {
  valid: boolean;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  isSelfSigned: boolean;
  subjectAltNames?: string[];
}

export interface DomainScanResult {
  scanId: string;
  scanType: 'domain';
  target: string;
  verdict: Verdict;
  threatScore: number;
  registrar?: string;
  creationDate?: string;
  expirationDate?: string;
  domainAgeDays?: number;
  isNewlyRegistered: boolean; // < 30 days
  dnsRecords: DnsRecordItem[];
  sslCertificate?: SslCertificateInfo;
  spfConfigured: boolean;
  dmarcConfigured: boolean;
  dnssecEnabled: boolean;
  dgaEntropyScore: number; // 0 to 100
  isDgaSuspicious: boolean;
  engines: EngineResult[];
  categories?: Record<string, string>;
  timestamp: string;
  isDemo?: boolean;
}

export interface CveScanResult {
  scanId: string;
  scanType: 'cve';
  target: string; // e.g. CVE-2021-44228
  verdict: Verdict;
  threatScore: number; // 0 to 100
  cveId: string;
  cvssVersion: '3.1' | '3.0' | '2.0';
  cvssScore: number; // 0.0 to 10.0
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  vectorString?: string;
  epssScore: number; // 0.0 to 1.0 (Exploit Prediction Scoring System)
  epssPercentile: number;
  isCisaKevKnownExploit: boolean; // In CISA Known Exploited Vulnerabilities catalog
  cwe?: string;
  cweName?: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  affectedProducts: string[];
  remediation?: string;
  references: string[];
  engines: EngineResult[];
  timestamp: string;
  isDemo?: boolean;
}

export type ScanResult = 
  | UrlScanResult 
  | IpScanResult 
  | HashScanResult 
  | FileScanResult 
  | EmailScanResult 
  | DomainScanResult 
  | CveScanResult;

export interface HistoryItem {
  id: string;
  scanType: ScanType;
  target: string;
  verdict: Verdict;
  threatScore: number;
  summary: string;
  timestamp: string;
  fullResult: ScanResult;
}

export interface ApiStatusResponse {
  virusTotalConfigured: boolean;
  abuseIpDbConfigured: boolean;
  googleSafeBrowsingConfigured: boolean;
  isAllConfigured: boolean;
  usingServerKeys: boolean;
}
