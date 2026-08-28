/**
 * Strict URL Validation Utility for PhishGuard Threat Scanner
 *
 * Rules:
 * 1. Must be a non-empty string with no internal unencoded spaces.
 * 2. Must start with http:// or https:// (case-insensitive).
 * 3. Must have a valid hostname (domain with TLD or valid IP / localhost).
 * 4. Must reject plain text, numbers, emails, usernames, unsupported schemes (javascript:, file:, ftp:, mailto:),
 *    and domain-like strings without protocol (e.g. google.com).
 */

export function isValidUrl(input) {
  if (!input || typeof input !== 'string') {
    return false;
  }

  const trimmed = input.trim();
  if (!trimmed) {
    return false;
  }

  // 1. Must strictly start with http:// or https://
  const schemeRegex = /^https?:\/\//i;
  if (!schemeRegex.test(trimmed)) {
    return false;
  }

  // 2. Must not contain unencoded spaces or line breaks
  if (/\s/.test(trimmed)) {
    return false;
  }

  // 3. Reject prohibited schemes or script injection patterns
  const prohibitedSchemes = /^(javascript|data|file|ftp|mailto|about|blob|vbscript):/i;
  if (prohibitedSchemes.test(trimmed)) {
    return false;
  }

  // 4. Parse using URL constructor
  try {
    const parsed = new URL(trimmed);

    // Protocol must strictly be http: or https:
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    const hostname = parsed.hostname;
    if (!hostname || hostname.length === 0) {
      return false;
    }

    // Hostname cannot contain spaces or invalid characters
    if (/[\s\r\n\t]/.test(hostname)) {
      return false;
    }

    // Hostname cannot be purely numeric without dots (e.g. http://123456789)
    if (/^\d+$/.test(hostname)) {
      return false;
    }

    // Check if hostname is an IPv4 address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(hostname)) {
      const parts = hostname.split('.').map(Number);
      const validIpv4 = parts.every((p) => p >= 0 && p <= 255);
      if (!validIpv4) return false;
      return true;
    }

    // Check if hostname is localhost or IPv6
    if (hostname === 'localhost' || hostname.startsWith('[') && hostname.endsWith(']')) {
      return true;
    }

    // For standard domains, must contain at least one dot and a valid TLD
    // Reject plain strings like http://google or http://test
    if (!hostname.includes('.')) {
      return false;
    }

    // Domain name parts check
    const domainParts = hostname.split('.');
    const tld = domainParts[domainParts.length - 1];

    // TLD must be at least 2 characters and only letters (or punycode xn--)
    if (!tld || tld.length < 2 || !/^[a-zA-Z0-9-]+$/.test(tld) || /^\d+$/.test(tld)) {
      return false;
    }

    // Each label in domain must be non-empty and valid
    for (const part of domainParts) {
      if (!part || part.length === 0 || part.startsWith('-') || part.endsWith('-')) {
        return false;
      }
      if (!/^[a-zA-Z0-9-]+$/.test(part)) {
        return false;
      }
    }

    return true;
  } catch (err) {
    return false;
  }
}
