# InjectScan

Prompt-injection detection for AI agents (MCP server + x402 API). Safety check only.

InjectScan is a deterministic, documented rule engine. It returns a risk score (0-100), a verdict (`safe` / `suspicious` / `malicious`), the categories that fired, and every finding as a character span in your original text, so you can highlight or strip it. Use it on web pages, emails, documents, tool results and other agents' messages before your agent acts on them.

- **Hosted remote MCP:** `https://api.youraitools.co/injectscan/mcp` (Streamable HTTP)
- **Free tier:** 30 full scans/day per IP (tools `scan_text`, `scan_url`, `scan_tools`) on the remote MCP endpoint, then $0.003 USDC per scan over [x402](https://x402.org), in USDC on Base, Polygon, Arbitrum One or Solana. No account or API key.
- **Hosted API:** https://api.youraitools.co/injectscan (`GET|POST /v1/scan` ($0.003; send `text`, `url` or `tools`), free `GET|POST /v1/scan/preview` (text up to 2,000 characters, 10/min per IP))
- **Local stdio MCP server:** this repo. Starts with no key, no account and no npm registry package.
- **MCP Registry:** `co.youraitools/injectscan`
- **License:** MIT

## Use the hosted server (no install)

Claude Code:

```bash
claude mcp add --transport http injectscan https://api.youraitools.co/injectscan/mcp
```

Claude Desktop: Settings > Connectors > Add custom connector with the URL above, or in `claude_desktop_config.json`:

```json
{ "mcpServers": { "injectscan": { "command": "npx", "args": ["-y", "mcp-remote", "https://api.youraitools.co/injectscan/mcp"] } } }
```

Cursor (`~/.cursor/mcp.json`), or one click: [Add to Cursor](cursor://anysphere.cursor-deeplink/mcp/install?name=injectscan&config=eyJ1cmwiOiJodHRwczovL2FwaS55b3VyYWl0b29scy5jby9pbmplY3RzY2FuL21jcCJ9)

```json
{ "mcpServers": { "injectscan": { "url": "https://api.youraitools.co/injectscan/mcp" } } }
```

Each free result includes an `upgrade` field with the calls left today. Past the daily limit the tool returns a `payment_required` (402) result with the paid x402 URL.

## Self-host: run from source (no npm registry)

Requires Node.js 20+ (or Docker). The server has no runtime dependencies.

```bash
git clone https://github.com/Duffey234/injectscan.git
cd injectscan
npm ci --omit=dev
node src/mcp-stdio.js        # stdio MCP server (newline-delimited JSON-RPC 2.0)
```

No git? Download the source tarball from the mirror instead: `curl -sL https://agentgate-source.pages.dev/x402-prompt-injection-scan/x402-prompt-injection-scan.tar.gz | tar xz`.

MCP client config (use the absolute path of your checkout):

```json
{ "mcpServers": { "injectscan": { "command": "node", "args": ["/absolute/path/to/injectscan/src/mcp-stdio.js"] } } }
```

Claude Code: `claude mcp add injectscan -- node /absolute/path/to/injectscan/src/mcp-stdio.js`

Tool `scan_text` runs the same rule engine locally, up to 100,000 characters, fully offline: nothing leaves your machine. Page scans (`url`, visible + hidden HTML) and MCP tool-poisoning scans (`tools`) run on the hosted API.

### Docker

```bash
docker build -t injectscan-mcp .
docker run -i --rm injectscan-mcp
```

```json
{ "mcpServers": { "injectscan": { "command": "docker", "args": ["run", "-i", "--rm", "injectscan-mcp"] } } }
```

## Test

```bash
npm test        # full test suite (node:test, Node 20 and 22, no network, no key)
```

## Full source

The complete hosted service (Cloudflare Worker, x402 v2 + v1, remote MCP) is on the source mirror: https://agentgate-source.pages.dev/x402-prompt-injection-scan/

Built by [YourAITools](https://youraitools.co). Informational tooling, safety check only; no warranty.
