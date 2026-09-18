/**
 * TypeScript interfaces for the Google Safe Browsing API v4 (Lookup API).
 *
 * Reference: https://developers.google.com/safe-browsing/v4/lookup-api
 * Endpoint: POST https://safebrowsing.googleapis.com/v4/threatMatches:find?key=API_KEY
 *
 * Note: Google's v5 API exists only as an alpha release
 * (google.security.safebrowsing.v5alpha1) as of this writing. v4 is the
 * documented, generally-available, stable API and is what this server uses.
 */

// The threat categories Safe Browsing can report for a URL.
export type SafeBrowsingThreatType =
  | "THREAT_TYPE_UNSPECIFIED"
  | "MALWARE"
  | "SOCIAL_ENGINEERING"
  | "UNWANTED_SOFTWARE"
  | "POTENTIALLY_HARMFUL_APPLICATION";

// The platforms a threat applies to. This server always queries with
// ANY_PLATFORM so it does not need to distinguish between the others.
export type SafeBrowsingPlatformType =
  | "PLATFORM_TYPE_UNSPECIFIED"
  | "WINDOWS"
  | "LINUX"
  | "ANDROID"
  | "OSX"
  | "IOS"
  | "ANY_PLATFORM"
  | "ALL_PLATFORMS"
  | "CHROME";

export interface SafeBrowsingThreatEntryMetadataEntry {
  key: string;
  value: string;
}

export interface SafeBrowsingMatch {
  threatType: SafeBrowsingThreatType;
  platformType: SafeBrowsingPlatformType;
  threatEntryType: string;
  threat: { url: string };
  threatEntryMetadata?: { entries?: SafeBrowsingThreatEntryMetadataEntry[] };
  cacheDuration?: string;
}

// Raw response shape from threatMatches:find. When a URL has no matches,
// Google returns an empty object (no `matches` key at all).
export interface SafeBrowsingFindResponse {
  matches?: SafeBrowsingMatch[];
}

// Simplified, per-URL Safe Browsing verdict used in this server's
// structuredContent output.
export interface SafeBrowsingResult {
  url: string;
  threats_found: boolean;
  matches: SafeBrowsingMatch[];
  checked_at: string;
}

// One source's contribution to a combined multi-source check. `checked`
// indicates whether the source was queried at all (false when Safe Browsing
// is skipped for lack of an API key); `available` indicates whether the
// query succeeded (false on a network/auth/API error, with `error` set).
export interface MultiSourcePhishTankResult {
  checked: boolean;
  available: boolean;
  in_database?: boolean;
  verified?: boolean;
  phish_id?: number;
  phish_detail_page?: string;
  error?: string;
}

export interface MultiSourceSafeBrowsingResult {
  checked: boolean;
  available: boolean;
  threats_found?: boolean;
  matches?: SafeBrowsingMatch[];
  error?: string;
}

export type MultiSourceVerdict =
  | "malicious"
  | "likely_safe"
  | "inconclusive"
  | "unknown";

export interface MultiSourceCheckResult {
  url: string;
  sources: {
    phishtank: MultiSourcePhishTankResult;
    safeBrowsing: MultiSourceSafeBrowsingResult;
  };
  verdict: MultiSourceVerdict;
  summary: string;
}
