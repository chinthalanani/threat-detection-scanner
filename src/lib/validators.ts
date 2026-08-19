export function isValidUrl(input: string): boolean {
  if (!input || typeof input !== 'string') return false;
  const trimmed = input.trim();
  try {
    const url = new URL(trimmed.startsWith('http://') || trimmed.startsWith('https://') ? trimmed : `http://${trimmed}`);
    return Boolean(url.hostname && url.hostname.includes('.'));
  } catch {
    return false;
  }
}

export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

export function isValidIp(input: string): { isValid: boolean; version?: 4 | 6 } {
  if (!input || typeof input !== 'string') return { isValid: false };
  const trimmed = input.trim();

  // IPv4 Regex
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  if (ipv4Regex.test(trimmed)) {
    return { isValid: true, version: 4 };
  }

  // IPv6 Regex
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  if (ipv6Regex.test(trimmed)) {
    return { isValid: true, version: 6 };
  }

  return { isValid: false };
}

export function detectHashType(input: string): 'md5' | 'sha1' | 'sha256' | null {
  if (!input || typeof input !== 'string') return null;
  const trimmed = input.trim().toLowerCase();

  if (/^[a-f0-9]{32}$/.test(trimmed)) return 'md5';
  if (/^[a-f0-9]{40}$/.test(trimmed)) return 'sha1';
  if (/^[a-f0-9]{64}$/.test(trimmed)) return 'sha256';

  return null;
}

export function isValidEmail(input: string): boolean {
  if (!input || typeof input !== 'string') return false;
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
  return emailRegex.test(input.trim());
}

export function isValidDomain(input: string): boolean {
  if (!input || typeof input !== 'string') return false;
  const cleaned = input.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(cleaned);
}

export function extractUrlsFromText(text: string): string[] {
  if (!text) return [];
  const urlRegex = /(https?:\/\/[^\s<>"'{}|\\^`]+)/gi;
  const matches = text.match(urlRegex) || [];
  return Array.from(new Set(matches));
}
