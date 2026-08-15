export type ScanType = 'url' | 'ip' | 'hash' | 'file' | 'qr';

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

export type ScanResult = UrlScanResult | IpScanResult | HashScanResult | FileScanResult;

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
