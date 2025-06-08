/**
 * TypeScript interfaces for PhishTank API responses and data structures
 */

// URL Check API Response
export interface PhishTankUrlCheckResponse {
  meta?: {
    timestamp: string;
    format: string;
  };
  results?: {
    url: string;
    in_database: boolean;
    phish_id?: number;
    phish_detail_page?: string;
    verified?: boolean;
    verified_at?: string;
    valid?: boolean;
    submitted_at?: string;
  };
}

// Database Entry for downloaded data
export interface PhishTankEntry {
  phish_id: number;
  url: string;
  phish_detail_url: string;
  submission_time: string;
  verified: string;
  verification_time: string;
  online: string;
  target?: string;
  details?: PhishTankDetail[];
}

// Detail information for each phish entry
export interface PhishTankDetail {
  ip_address: string;
  cidr_block: string;
  announcing_network: string;
  rir: string;
  detail_time: string;
}

// Database download response structure
export interface PhishTankDatabase {
  meta?: {
    total_entries: number;
  };
  entries?: PhishTankEntry[];
}

// Rate limiting information from response headers
export interface RateLimitInfo {
  interval: string;
  limit: number;
  count: number;
  remaining: number;
}

// Configuration options for the server
export interface PhishTankConfig {
  apiKey?: string;
  userAgent: string;
  rateLimitWindow: number; // in milliseconds
  rateLimitMax: number;
  cacheTimeout: number; // in milliseconds
  maxDatabaseAge: number; // in milliseconds
}

// API response wrapper for tool results
export interface PhishTankToolResponse {
  success: boolean;
  data: any;
  error?: string;
  rateLimitInfo?: RateLimitInfo;
  summary: string;
}

// Search criteria for filtering phish data
export interface PhishSearchCriteria {
  target?: string;
  startDate?: string;
  endDate?: string;
  verified?: boolean;
  online?: boolean;
  limit?: number;
  offset?: number;
}

// Statistics response structure
export interface PhishTankStats {
  total_phish: number;
  total_verified: number;
  total_online: number;
  top_targets: Array<{
    target: string;
    count: number;
  }>;
  recent_submissions: number;
  date_range: {
    from: string;
    to: string;
  };
}

// Request parameters for URL checking
export interface UrlCheckRequest {
  url: string;
  format?: 'json' | 'xml' | 'php';
  app_key?: string;
}

// Batch URL check request
export interface BatchUrlCheckRequest {
  urls: string[];
  format?: 'json' | 'xml' | 'php';
  app_key?: string;
  maxConcurrent?: number;
}

// Cache entry structure
export interface CacheEntry<T> {
  data: T;
  timestamp: number;
  expires: number;
}

// Error types
export type PhishTankErrorType = 
  | 'RATE_LIMIT_EXCEEDED'
  | 'INVALID_URL'
  | 'API_ERROR'
  | 'NETWORK_ERROR'
  | 'CACHE_ERROR'
  | 'VALIDATION_ERROR';

export interface PhishTankError extends Error {
  type: PhishTankErrorType;
  statusCode?: number;
  details?: any;
}
