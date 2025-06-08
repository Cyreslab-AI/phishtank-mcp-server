#!/usr/bin/env node

/**
 * PhishTank MCP Server
 * 
 * This MCP server provides access to PhishTank (https://phishtank.org/),
 * a collaborative clearing house for data and information about phishing
 * on the Internet, operated by Cisco Talos Intelligence Group.
 * 
 * PhishTank API endpoints:
 * - URL Check: Verify if a URL is in the phishing database
 * - Database Download: Get comprehensive phishing database
 * - Phish Search: Search and filter phishing data
 * - Statistics: Get phishing trends and statistics
 * 
 * The PhishTank API is free to use but has rate limits.
 * API keys are recommended for higher rate limits and database downloads.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from 'axios';
import NodeCache from 'node-cache';
import { URL } from 'url';
import {
  PhishTankUrlCheckResponse,
  PhishTankEntry,
  PhishTankDatabase,
  PhishTankConfig,
  PhishTankStats,
  RateLimitInfo,
  PhishSearchCriteria,
  CacheEntry,
  PhishTankError
} from './types/phishtank-types.js';

class PhishTankServer {
  private server: Server;
  private axiosInstance: AxiosInstance;
  private cache: NodeCache;
  private config: PhishTankConfig;
  private lastRequestTime: number = 0;

  constructor() {
    this.server = new Server(
      {
        name: "phishtank-server",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    // Configuration with environment variables
    this.config = {
      apiKey: process.env.PHISHTANK_API_KEY,
      userAgent: process.env.PHISHTANK_USER_AGENT || 'phishtank-mcp-server/1.0.0',
      rateLimitWindow: 60000, // 1 minute
      rateLimitMax: process.env.PHISHTANK_API_KEY ? 100 : 10, // Higher limit with API key
      cacheTimeout: 300000, // 5 minutes for URL checks
      maxDatabaseAge: 3600000, // 1 hour for database cache
    };

    // Initialize cache
    this.cache = new NodeCache({
      stdTTL: this.config.cacheTimeout / 1000,
      checkperiod: 120,
      useClones: false,
    });

    // Initialize HTTP client
    this.axiosInstance = axios.create({
      timeout: 30000,
      headers: {
        'User-Agent': this.config.userAgent,
      },
    });

    this.setupToolHandlers();
    
    // Error handling
    this.server.onerror = (error) => console.error('[MCP Error]', error);
    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  private setupToolHandlers() {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: [
        {
          name: 'check_url',
          description: 'Check if a URL is in PhishTank\'s phishing database',
          inputSchema: {
            type: 'object',
            properties: {
              url: {
                type: 'string',
                description: 'The URL to check for phishing (must be a complete URL with protocol)',
              },
              format: {
                type: 'string',
                description: 'Response format: json, xml, or php (default: json)',
                enum: ['json', 'xml', 'php'],
              },
            },
            required: ['url'],
          },
        },
        {
          name: 'check_multiple_urls',
          description: 'Check multiple URLs for phishing with intelligent rate limiting',
          inputSchema: {
            type: 'object',
            properties: {
              urls: {
                type: 'array',
                description: 'Array of URLs to check',
                items: {
                  type: 'string',
                },
                maxItems: 50,
              },
              delay: {
                type: 'number',
                description: 'Delay between requests in milliseconds (default: 1000)',
                minimum: 500,
                maximum: 10000,
              },
            },
            required: ['urls'],
          },
        },
        {
          name: 'get_recent_phish',
          description: 'Get recent verified phishing URLs from PhishTank database',
          inputSchema: {
            type: 'object',
            properties: {
              limit: {
                type: 'number',
                description: 'Number of entries to return (1-1000, default: 100)',
                minimum: 1,
                maximum: 1000,
              },
              include_offline: {
                type: 'boolean',
                description: 'Include offline phishing URLs (default: false)',
              },
            },
          },
        },
        {
          name: 'search_phish_by_target',
          description: 'Search phishing URLs by target company/brand',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target company or brand name to search for (e.g., "PayPal", "Apple")',
              },
              limit: {
                type: 'number',
                description: 'Number of results to return (1-500, default: 50)',
                minimum: 1,
                maximum: 500,
              },
              verified_only: {
                type: 'boolean',
                description: 'Only return verified phishing URLs (default: true)',
              },
            },
            required: ['target'],
          },
        },
        {
          name: 'get_phish_details',
          description: 'Get detailed information about a specific phish by ID',
          inputSchema: {
            type: 'object',
            properties: {
              phish_id: {
                type: 'number',
                description: 'PhishTank phish ID number',
              },
            },
            required: ['phish_id'],
          },
        },
        {
          name: 'get_phish_stats',
          description: 'Get statistics about phishing trends and top targets',
          inputSchema: {
            type: 'object',
            properties: {
              days: {
                type: 'number',
                description: 'Number of days to analyze (1-30, default: 7)',
                minimum: 1,
                maximum: 30,
              },
              top_targets_limit: {
                type: 'number',
                description: 'Number of top targets to include (default: 10)',
                minimum: 1,
                maximum: 50,
              },
            },
          },
        },
        {
          name: 'search_phish_by_date',
          description: 'Search phishing URLs by submission date range',
          inputSchema: {
            type: 'object',
            properties: {
              start_date: {
                type: 'string',
                description: 'Start date in ISO format (YYYY-MM-DD)',
                pattern: '^\\d{4}-\\d{2}-\\d{2}$',
              },
              end_date: {
                type: 'string',
                description: 'End date in ISO format (YYYY-MM-DD)',
                pattern: '^\\d{4}-\\d{2}-\\d{2}$',
              },
              limit: {
                type: 'number',
                description: 'Number of results to return (1-500, default: 100)',
                minimum: 1,
                maximum: 500,
              },
            },
            required: ['start_date', 'end_date'],
          },
        },
      ],
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      try {
        switch (request.params.name) {
          case 'check_url':
            return await this.checkUrl(request.params.arguments);
          case 'check_multiple_urls':
            return await this.checkMultipleUrls(request.params.arguments);
          case 'get_recent_phish':
            return await this.getRecentPhish(request.params.arguments);
          case 'search_phish_by_target':
            return await this.searchPhishByTarget(request.params.arguments);
          case 'get_phish_details':
            return await this.getPhishDetails(request.params.arguments);
          case 'get_phish_stats':
            return await this.getPhishStats(request.params.arguments);
          case 'search_phish_by_date':
            return await this.searchPhishByDate(request.params.arguments);
          default:
            throw new McpError(
              ErrorCode.MethodNotFound,
              `Unknown tool: ${request.params.name}`
            );
        }
      } catch (error) {
        if (axios.isAxiosError(error)) {
          const statusCode = error.response?.status;
          
          if (statusCode === 509) {
            return {
              content: [{
                type: 'text',
                text: `Rate limit exceeded. Please try again later. Consider using an API key for higher limits.`
              }],
              isError: true,
            };
          }
          
          return {
            content: [{
              type: 'text',
              text: `PhishTank API error (${statusCode}): ${error.response?.data || error.message}`
            }],
            isError: true,
          };
        }
        
        throw error;
      }
    });
  }

  private async checkUrl(args: any) {
    const url = String(args?.url || '').trim();
    const format = args?.format || 'json';

    if (!url) {
      throw new McpError(ErrorCode.InvalidParams, 'URL parameter is required');
    }

    if (!this.isValidUrl(url)) {
      throw new McpError(ErrorCode.InvalidParams, 'Invalid URL format');
    }

    // Check cache first
    const cacheKey = `url_check:${url}`;
    const cached = this.cache.get<PhishTankUrlCheckResponse>(cacheKey);
    if (cached) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            cached: true,
            result: cached,
            summary: this.getUrlCheckSummary(cached)
          }, null, 2)
        }]
      };
    }

    // Rate limiting
    await this.enforceRateLimit();

    // Make API request
    const formData = new URLSearchParams();
    formData.append('url', url);
    formData.append('format', format);
    if (this.config.apiKey) {
      formData.append('app_key', this.config.apiKey);
    }

    const response = await this.axiosInstance.post(
      'http://checkurl.phishtank.com/checkurl/',
      formData,
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
      }
    );

    const result = response.data as PhishTankUrlCheckResponse;
    
    // Cache the result
    this.cache.set(cacheKey, result);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          result,
          rate_limit_info: this.extractRateLimitInfo(response.headers),
          summary: this.getUrlCheckSummary(result)
        }, null, 2)
      }]
    };
  }

  private async checkMultipleUrls(args: any) {
    const urls = args?.urls || [];
    const delay = Math.max(args?.delay || 1000, 500);

    if (!Array.isArray(urls) || urls.length === 0) {
      throw new McpError(ErrorCode.InvalidParams, 'URLs array is required');
    }

    if (urls.length > 50) {
      throw new McpError(ErrorCode.InvalidParams, 'Maximum 50 URLs allowed per batch');
    }

    const results = [];
    let processedCount = 0;

    for (const url of urls) {
      try {
        const result = await this.checkUrl({ url });
        results.push({
          url,
          success: true,
          data: JSON.parse(result.content[0].text)
        });
      } catch (error) {
        results.push({
          url,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }

      processedCount++;
      
      // Add delay between requests (except for the last one)
      if (processedCount < urls.length) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }

    const successCount = results.filter(r => r.success).length;
    const failureCount = results.length - successCount;

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          batch_results: results,
          summary: {
            total: urls.length,
            successful: successCount,
            failed: failureCount,
            delay_used: delay
          }
        }, null, 2)
      }]
    };
  }

  private async getRecentPhish(args: any) {
    const limit = Math.min(Number(args?.limit || 100), 1000);
    const includeOffline = Boolean(args?.include_offline);

    // Check cache for database
    const cacheKey = 'phishtank_database';
    let database = this.cache.get<PhishTankDatabase>(cacheKey);

    if (!database) {
      database = await this.downloadDatabase();
      this.cache.set(cacheKey, database, this.config.maxDatabaseAge / 1000);
    }

    let entries = database.entries || [];

    // Filter out offline entries if requested
    if (!includeOffline) {
      entries = entries.filter(entry => entry.online === 'yes');
    }

    // Sort by submission time (most recent first) and limit
    entries = entries
      .sort((a, b) => new Date(b.submission_time).getTime() - new Date(a.submission_time).getTime())
      .slice(0, limit);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          total_entries: database.meta?.total_entries || 0,
          filtered_entries: entries.length,
          include_offline: includeOffline,
          entries,
          summary: `Retrieved ${entries.length} recent phishing URLs${includeOffline ? ' (including offline)' : ' (online only)'}`
        }, null, 2)
      }]
    };
  }

  private async searchPhishByTarget(args: any) {
    const target = String(args?.target || '').trim().toLowerCase();
    const limit = Math.min(Number(args?.limit || 50), 500);
    const verifiedOnly = args?.verified_only !== false;

    if (!target) {
      throw new McpError(ErrorCode.InvalidParams, 'Target parameter is required');
    }

    // Get database
    const cacheKey = 'phishtank_database';
    let database = this.cache.get<PhishTankDatabase>(cacheKey);

    if (!database) {
      database = await this.downloadDatabase();
      this.cache.set(cacheKey, database, this.config.maxDatabaseAge / 1000);
    }

    let entries = database.entries || [];

    // Filter by target and verification status
    entries = entries.filter(entry => {
      const matchesTarget = entry.target?.toLowerCase().includes(target);
      const matchesVerified = !verifiedOnly || entry.verified === 'yes';
      return matchesTarget && matchesVerified;
    });

    // Sort by submission time and limit
    entries = entries
      .sort((a, b) => new Date(b.submission_time).getTime() - new Date(a.submission_time).getTime())
      .slice(0, limit);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          search_target: target,
          verified_only: verifiedOnly,
          matches_found: entries.length,
          entries,
          summary: `Found ${entries.length} phishing URLs targeting "${target}"${verifiedOnly ? ' (verified only)' : ''}`
        }, null, 2)
      }]
    };
  }

  private async getPhishDetails(args: any) {
    const phishId = Number(args?.phish_id);

    if (!phishId || phishId <= 0) {
      throw new McpError(ErrorCode.InvalidParams, 'Valid phish_id is required');
    }

    // Get database
    const cacheKey = 'phishtank_database';
    let database = this.cache.get<PhishTankDatabase>(cacheKey);

    if (!database) {
      database = await this.downloadDatabase();
      this.cache.set(cacheKey, database, this.config.maxDatabaseAge / 1000);
    }

    const entry = database.entries?.find(e => e.phish_id === phishId);

    if (!entry) {
      return {
        content: [{
          type: 'text',
          text: JSON.stringify({
            phish_id: phishId,
            found: false,
            summary: `Phish ID ${phishId} not found in database`
          }, null, 2)
        }]
      };
    }

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          phish_id: phishId,
          found: true,
          details: entry,
          summary: `Details for phish ID ${phishId}: ${entry.url} (Target: ${entry.target || 'Unknown'})`
        }, null, 2)
      }]
    };
  }

  private async getPhishStats(args: any) {
    const days = Math.min(Math.max(Number(args?.days || 7), 1), 30);
    const topTargetsLimit = Math.min(Number(args?.top_targets_limit || 10), 50);

    // Get database
    const cacheKey = 'phishtank_database';
    let database = this.cache.get<PhishTankDatabase>(cacheKey);

    if (!database) {
      database = await this.downloadDatabase();
      this.cache.set(cacheKey, database, this.config.maxDatabaseAge / 1000);
    }

    const entries = database.entries || [];
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    // Filter entries by date range
    const recentEntries = entries.filter(entry => 
      new Date(entry.submission_time) >= cutoffDate
    );

    // Calculate statistics
    const totalPhish = recentEntries.length;
    const totalVerified = recentEntries.filter(e => e.verified === 'yes').length;
    const totalOnline = recentEntries.filter(e => e.online === 'yes').length;

    // Count targets
    const targetCounts = new Map<string, number>();
    recentEntries.forEach(entry => {
      if (entry.target) {
        const target = entry.target;
        targetCounts.set(target, (targetCounts.get(target) || 0) + 1);
      }
    });

    const topTargets = Array.from(targetCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, topTargetsLimit)
      .map(([target, count]) => ({ target, count }));

    const stats: PhishTankStats = {
      total_phish: totalPhish,
      total_verified: totalVerified,
      total_online: totalOnline,
      top_targets: topTargets,
      recent_submissions: totalPhish,
      date_range: {
        from: cutoffDate.toISOString().split('T')[0],
        to: new Date().toISOString().split('T')[0]
      }
    };

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          statistics: stats,
          analysis_period_days: days,
          summary: `Analyzed ${totalPhish} phishing submissions over ${days} days. ${totalVerified} verified, ${totalOnline} currently online.`
        }, null, 2)
      }]
    };
  }

  private async searchPhishByDate(args: any) {
    const startDate = args?.start_date;
    const endDate = args?.end_date;
    const limit = Math.min(Number(args?.limit || 100), 500);

    if (!startDate || !endDate) {
      throw new McpError(ErrorCode.InvalidParams, 'Both start_date and end_date are required');
    }

    // Validate date format
    const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRegex.test(startDate) || !dateRegex.test(endDate)) {
      throw new McpError(ErrorCode.InvalidParams, 'Dates must be in YYYY-MM-DD format');
    }

    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setHours(23, 59, 59, 999); // Include full end date

    if (start > end) {
      throw new McpError(ErrorCode.InvalidParams, 'Start date must be before end date');
    }

    // Get database
    const cacheKey = 'phishtank_database';
    let database = this.cache.get<PhishTankDatabase>(cacheKey);

    if (!database) {
      database = await this.downloadDatabase();
      this.cache.set(cacheKey, database, this.config.maxDatabaseAge / 1000);
    }

    // Filter by date range
    const entries = (database.entries || [])
      .filter(entry => {
        const submissionDate = new Date(entry.submission_time);
        return submissionDate >= start && submissionDate <= end;
      })
      .sort((a, b) => new Date(b.submission_time).getTime() - new Date(a.submission_time).getTime())
      .slice(0, limit);

    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          date_range: {
            start: startDate,
            end: endDate
          },
          matches_found: entries.length,
          entries,
          summary: `Found ${entries.length} phishing URLs submitted between ${startDate} and ${endDate}`
        }, null, 2)
      }]
    };
  }

  private async downloadDatabase(): Promise<PhishTankDatabase> {
    const baseUrl = 'http://data.phishtank.com/data';
    const format = 'online-valid.json';
    const url = this.config.apiKey 
      ? `${baseUrl}/${this.config.apiKey}/${format}`
      : `${baseUrl}/${format}`;

    const response = await this.axiosInstance.get(url);
    
    // PhishTank returns an array directly for JSON format
    const entries = Array.isArray(response.data) ? response.data : [];
    
    return {
      meta: {
        total_entries: entries.length
      },
      entries
    };
  }

  private async enforceRateLimit(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastRequestTime;
    const minInterval = 60000 / this.config.rateLimitMax; // Convert to milliseconds per request

    if (timeSinceLastRequest < minInterval) {
      const waitTime = minInterval - timeSinceLastRequest;
      await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    this.lastRequestTime = Date.now();
  }

  private isValidUrl(url: string): boolean {
    try {
      new URL(url);
      return true;
    } catch {
      return false;
    }
  }

  private extractRateLimitInfo(headers: any): RateLimitInfo | undefined {
    const interval = headers['x-request-limit-interval'];
    const limit = headers['x-request-limit'];
    const count = headers['x-request-count'];

    if (interval && limit && count) {
      return {
        interval,
        limit: parseInt(limit),
        count: parseInt(count),
        remaining: parseInt(limit) - parseInt(count)
      };
    }
    return undefined;
  }

  private getUrlCheckSummary(response: PhishTankUrlCheckResponse): string {
    if (!response.results) {
      return 'Invalid response from PhishTank';
    }

    const { in_database, verified, valid, phish_id } = response.results;

    if (!in_database) {
      return 'URL not found in PhishTank database (likely safe)';
    }

    if (verified && valid) {
      return `⚠️ PHISHING DETECTED - Verified phishing URL (ID: ${phish_id})`;
    } else if (in_database) {
      return `URL found in database but not yet verified (ID: ${phish_id})`;
    }

    return 'URL status unclear';
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('PhishTank MCP server running on stdio');
  }
}

const server = new PhishTankServer();
server.run().catch(console.error);
