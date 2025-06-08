# PhishTank MCP Server

An MCP (Model Context Protocol) server that provides access to PhishTank, a collaborative clearing house for data and information about phishing on the Internet. PhishTank is operated by Cisco Talos Intelligence Group and provides real-time phishing URL verification and comprehensive phishing databases.

## Features

- **URL Verification**: Check if URLs are in PhishTank's phishing database
- **Batch Processing**: Check multiple URLs with intelligent rate limiting
- **Database Access**: Access to comprehensive phishing URL database
- **Search & Filter**: Search phishing URLs by target, date, or verification status
- **Statistics**: Get phishing trends and target analysis
- **Caching**: Smart caching to reduce API calls and improve performance
- **Rate Limiting**: Respects PhishTank's rate limits with automatic throttling

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

### Getting an API Key

1. Visit [PhishTank API Registration](https://phishtank.org/api_register.php)
2. Create an account or log in
3. Register your application to get an API key
4. Add the key to your `.env` file

**Benefits of API Key:**
- Higher rate limits (100 vs 10 requests per minute)
- Access to database downloads
- More reliable service

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

## Rate Limiting

The server automatically handles rate limiting:

- **Without API Key**: 10 requests per minute
- **With API Key**: 100 requests per minute
- **Automatic Throttling**: Requests are queued and spaced appropriately
- **Caching**: Results are cached to reduce API calls

## Caching

- **URL Checks**: Cached for 5 minutes
- **Database Downloads**: Cached for 1 hour
- **Automatic Cleanup**: Cache is cleaned up automatically

## Error Handling

The server provides comprehensive error handling:

- **Rate Limit Exceeded**: Automatic retry with backoff
- **Invalid URLs**: Validation before API calls
- **Network Errors**: Proper error messages and recovery
- **API Errors**: Detailed error information from PhishTank

## API Response Format

All tools return structured JSON responses with:

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

## Security Considerations

- **No API Key Required**: Basic functionality works without API key
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
│   ├── index.ts              # Main server implementation
│   └── types/
│       └── phishtank-types.ts # TypeScript type definitions
├── build/                    # Compiled JavaScript (auto-generated)
├── package.json
├── tsconfig.json
├── .env.example
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
