# PhishTank MCP Server

An MCP (Model Context Protocol) server that provides access to PhishTank, a collaborative clearing house for data and information about phishing on the Internet. PhishTank is operated by Cisco Talos Intelligence Group and provides real-time phishing URL verification and comprehensive phishing databases.

The server also offers optional **Google Safe Browsing** lookups as a second, complementary threat source. See [Why a second source?](#why-a-second-source) below.

## Features

- **URL Verification**: Check if URLs are in PhishTank's phishing database
- **Batch Processing**: Check multiple URLs with intelligent rate limiting
- **Database Access**: Access to comprehensive phishing URL database
- **Search & Filter**: Search phishing URLs by target, date, or verification status
- **Statistics**: Get phishing trends and target analysis
- **Caching**: Smart caching to reduce API calls and improve performance
- **Rate Limiting**: Respects PhishTank's rate limits with automatic throttling
- **Google Safe Browsing (optional)**: Cross-check URLs against Google's malware/phishing/unwanted-software database
- **Multi-Source Verdicts**: Combine PhishTank and Safe Browsing into a single verdict with clear per-source attribution

## Why a second source?

PhishTank has been showing signs of decline as a standalone data source:

- New user registration has been **closed since 2020**, limiting who can submit and verify phish.
- The service has been reported to be undergoing a ground-up rebuild, with uncertain timelines.
- PhishTank's own API surface (`checkurl` plus the bulk database download) is already fully covered by this server's original 7 tools — there isn't more PhishTank-specific ground to add.

Rather than add more tools against a shrinking data source, this server adds **Google Safe Browsing** (v4 Lookup API): a broad-coverage, real-time, industry-standard threat database with a free tier. The two sources use independent detection pipelines, so checking both gives more reliable cross-verification than either alone. PhishTank-only tools are unaffected and keep working exactly as before, with or without Safe Browsing configured.

## Available Tools

### 1. `check_url`
Check if a single URL is in PhishTank's phishing database.

**Parameters:**
- `url` (required): The URL to check (must include protocol)
- `format` (optional): Response format ('json', 'xml', 'php', default: 'json')

**Example:**
```json
{
  "url": "https://suspicious-site.com/login",
  "format": "json"
}
```

### 2. `check_multiple_urls`
Check multiple URLs with intelligent rate limiting.

**Parameters:**
- `urls` (required): Array of URLs to check (max 50)
- `delay` (optional): Delay between requests in milliseconds (500-10000, default: 1000)

**Example:**
```json
{
  "urls": [
    "https://example1.com",
    "https://example2.com"
  ],
  "delay": 1500
}
```

### 3. `get_recent_phish`
Get recent verified phishing URLs from the database.

**Parameters:**
- `limit` (optional): Number of entries to return (1-1000, default: 100)
- `include_offline` (optional): Include offline phishing URLs (default: false)

### 4. `search_phish_by_target`
Search phishing URLs by target company/brand.

**Parameters:**
- `target` (required): Target company or brand name (e.g., "PayPal", "Apple")
- `limit` (optional): Number of results (1-500, default: 50)
- `verified_only` (optional): Only return verified phishing URLs (default: true)

### 5. `get_phish_details`
Get detailed information about a specific phish by ID.

**Parameters:**
- `phish_id` (required): PhishTank phish ID number

### 6. `get_phish_stats`
Get statistics about phishing trends and top targets.

**Parameters:**
- `days` (optional): Number of days to analyze (1-30, default: 7)
- `top_targets_limit` (optional): Number of top targets to include (default: 10)

### 7. `search_phish_by_date`
Search phishing URLs by submission date range.

**Parameters:**
- `start_date` (required): Start date in YYYY-MM-DD format
- `end_date` (required): End date in YYYY-MM-DD format
- `limit` (optional): Number of results (1-500, default: 100)

### 8. `check_url_safe_browsing` (requires `GOOGLE_SAFE_BROWSING_API_KEY`)
Check a single URL against Google Safe Browsing for malware, social engineering (phishing), unwanted software, and potentially harmful application threats.

**Parameters:**
- `url` (required): The URL to check (must include protocol)

**Example:**
```json
{
  "url": "https://suspicious-site.com/login"
}
```

If `GOOGLE_SAFE_BROWSING_API_KEY` is not set, this tool returns a clear error explaining how to get one; it does not affect any other tool.

### 9. `check_url_multi_source`
Check a URL against **both** PhishTank and Google Safe Browsing in a single call, and return a combined verdict (`malicious`, `likely_safe`, `inconclusive`, or `unknown`) with the contribution of each source clearly labeled under `sources.phishtank` and `sources.safeBrowsing`.

**Parameters:**
- `url` (required): The URL to check (must include protocol)

**Example:**
```json
{
  "url": "https://suspicious-site.com/login"
}
```

If `GOOGLE_SAFE_BROWSING_API_KEY` is not configured, this tool still runs PhishTank's check; the `sources.safeBrowsing` field reports `checked: false` with an explanatory `error` instead of failing the whole call. This is the recommended tool when you want the most reliable single answer.

## Installation

### Prerequisites
- Node.js 18 or higher
- npm or yarn

### Install Dependencies
```bash
npm install
```

### Build the Server
```bash
npm run build
```

### Install Globally (Optional)
```bash
npm install -g .
```

## Configuration

The server can be configured using environment variables. Copy `.env.example` to `.env` and customize:

```bash
cp .env.example .env
```

### Environment Variables

- `PHISHTANK_API_KEY`: Optional API key for higher rate limits and database downloads
- `PHISHTANK_USER_AGENT`: Custom User-Agent string (recommended format: `phishtank/username`)
- `GOOGLE_SAFE_BROWSING_API_KEY`: Optional API key that enables `check_url_safe_browsing` and the Safe-Browsing half of `check_url_multi_source`. All PhishTank tools work without it.

### Getting a PhishTank API Key

1. Visit [PhishTank API Registration](https://phishtank.org/api_register.php)
2. Create an account or log in
3. Register your application to get an API key
4. Add the key to your `.env` file

**Benefits of API Key:**
- Higher rate limits (100 vs 10 requests per minute)
- Access to database downloads
- More reliable service

**Note:** as of this writing, PhishTank registration for *new* accounts has been closed since 2020, so this key may not be obtainable for new users — see [Why a second source?](#why-a-second-source).

### Getting a Google Safe Browsing API Key

1. Create or select a project in the [Google Cloud Console](https://console.cloud.google.com/)
2. Enable the **Safe Browsing API** for that project
3. Create an API key ([Credentials](https://console.cloud.google.com/apis/credentials)) and restrict it to the Safe Browsing API
4. Set it as `GOOGLE_SAFE_BROWSING_API_KEY` in your environment (or `.env` file)

The Safe Browsing API has a free tier and is documented at [developers.google.com/safe-browsing](https://developers.google.com/safe-browsing/v4/get-started). It is for non-commercial use; see Google's terms for commercial use cases (Web Risk API).

## Usage

### Running the Server
```bash
# Run directly
npm start

# Or if installed globally
phishtank-mcp-server

# Run with MCP Inspector for testing
npm run inspector
```

### Integration with MCP Clients

Add to your MCP client configuration:

```json
{
  "name": "phishtank",
  "command": "node",
  "args": ["path/to/phishtank-mcp-server/build/index.js"]
}
```

### Example Usage

#### Check a Suspicious URL
```javascript
// Using MCP client
const result = await client.use_tool('check_url', {
  url: 'https://suspicious-site.com/login'
});
```

#### Search for PayPal Phishing
```javascript
const phishingUrls = await client.use_tool('search_phish_by_target', {
  target: 'PayPal',
  limit: 20,
  verified_only: true
});
```

#### Get Recent Phishing Statistics
```javascript
const stats = await client.use_tool('get_phish_stats', {
  days: 7,
  top_targets_limit: 15
});
```

#### Cross-Check a URL Against Both Sources
```javascript
const verdict = await client.use_tool('check_url_multi_source', {
  url: 'https://suspicious-site.com/login'
});
// verdict.verdict: "malicious" | "likely_safe" | "inconclusive" | "unknown"
// verdict.sources.phishtank / verdict.sources.safeBrowsing: per-source detail
```

## Rate Limiting

The server automatically handles rate limiting:

- **Without API Key**: 10 requests per minute
- **With API Key**: 100 requests per minute
- **Automatic Throttling**: Requests are queued and spaced appropriately
- **Caching**: Results are cached to reduce API calls

## Caching

- **URL Checks**: Cached for 5 minutes (both PhishTank's `check_url` and Safe Browsing's `check_url_safe_browsing`)
- **Database Downloads**: Cached for 1 hour
- **Automatic Cleanup**: Cache is cleaned up automatically

## Error Handling

The server provides comprehensive error handling:

- **Rate Limit Exceeded**: Automatic retry with backoff
- **Invalid URLs**: Validation before API calls
- **Network Errors**: Proper error messages and recovery
- **API Errors**: Detailed error information from PhishTank or Google Safe Browsing, labeled by source
- **Missing Safe Browsing Key**: `check_url_safe_browsing` returns a clear, actionable error; `check_url_multi_source` instead skips that source and still returns the PhishTank result

## API Response Format

All tools return structured JSON responses (also exposed as MCP `structuredContent` matching each tool's `outputSchema`).

PhishTank-only tools, e.g. `check_url`:
```json
{
  "result": { /* Tool-specific data */ },
  "rate_limit_info": {
    "interval": "300 Seconds",
    "limit": 100,
    "count": 5,
    "remaining": 95
  },
  "summary": "Human-readable summary of the result"
}
```

`check_url_safe_browsing`:
```json
{
  "url": "https://suspicious-site.com/login",
  "threats_found": true,
  "matches": [
    { "threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL", "threat": { "url": "https://suspicious-site.com/login" } }
  ],
  "checked_at": "2026-09-19T00:00:00.000Z",
  "summary": "⚠️ THREAT DETECTED by Google Safe Browsing - SOCIAL_ENGINEERING"
}
```

`check_url_multi_source`, with each source's contribution clearly attributed:
```json
{
  "url": "https://suspicious-site.com/login",
  "sources": {
    "phishtank": { "checked": true, "available": true, "in_database": true, "verified": true, "phish_id": 12345 },
    "safeBrowsing": { "checked": true, "available": true, "threats_found": true, "matches": [ { "threatType": "SOCIAL_ENGINEERING", "..." : "..." } ] }
  },
  "verdict": "malicious",
  "summary": "⚠️ PHISHING/MALWARE DETECTED - flagged by: PhishTank (verified phish ID 12345) and Google Safe Browsing (SOCIAL_ENGINEERING)"
}
```

## Security Considerations

- **No API Key Required**: Basic PhishTank functionality works without any API key; Safe Browsing tools require `GOOGLE_SAFE_BROWSING_API_KEY` and fail cleanly (or are skipped, for the multi-source tool) without it
- **Rate Limiting**: Respects PhishTank's service limits
- **URL Validation**: All URLs are validated before processing
- **Error Handling**: Prevents information leakage in error messages

## Development

### Scripts
- `npm run build`: Compile TypeScript to JavaScript
- `npm run watch`: Watch for changes and rebuild
- `npm run inspector`: Run with MCP Inspector for testing

### Project Structure
```
phishtank-mcp-server/
├── src/
│   ├── index.ts                  # Main server implementation
│   └── types/
│       ├── phishtank-types.ts    # PhishTank TypeScript type definitions
│       └── safebrowsing-types.ts # Google Safe Browsing + multi-source type definitions
├── build/                        # Compiled JavaScript (auto-generated)
├── package.json
├── tsconfig.json
└── README.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Related Projects

- [URLhaus MCP Server](../urlhaus-server) - URLhaus malware URL database
- [OpenFDA MCP Server](../openfda-server) - FDA drug and device information
- [CIRCL CVE Search MCP Server](../circl-cve-search-server) - CVE vulnerability information

## Support

- **Issues**: [GitHub Issues](https://github.com/Cyreslab-AI/phishtank-mcp-server/issues)
- **Documentation**: [PhishTank API Documentation](https://phishtank.org/api_info.php)
- **Community**: [MCP Community](https://github.com/modelcontextprotocol)

## Acknowledgments

- [PhishTank](https://phishtank.org/) by Cisco Talos Intelligence Group
- [Model Context Protocol](https://github.com/modelcontextprotocol) by Anthropic
- All contributors and the cybersecurity community
