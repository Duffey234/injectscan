#!/usr/bin/env node
// InjectScan MCP server over stdio (newline-delimited JSON-RPC 2.0, no dependencies).
// Tool scan_text runs the same deterministic rule engine as the hosted API, locally. Free; nothing leaves your machine.
// Page scans (url=, visible + hidden HTML) and MCP tool-poisoning scans: hosted x402 API https://injectscan.agentgate.workers.dev
//   node src/mcp-stdio.js      (run from a source checkout: https://agentgate-source.pages.dev/x402-prompt-injection-scan/ ; bin: injectscan-mcp)
import { createInterface } from 'node:readline';
import { scanText } from './scanner.js';

export const VERSION = '0.1.4';
const MAX = 100000;
export const TOOL = {
  name: 'scan_text', title: 'Scan text for prompt injection',
  description: "Scans untrusted text for prompt injection before your agent reads or acts on it: web page text, emails, documents, tool results or another agent's message. A deterministic rule engine flags instruction overrides, jailbreak personas, system-prompt extraction, fake delimiters, exfiltration URLs, tool hijacking, hidden Unicode and encoded payloads. Free and local: no key, no network, nothing leaves your machine; up to 100,000 characters per call (split longer text). This server scans text only; to fetch and scan a URL (incl. hidden HTML) or check MCP tool definitions for poisoning, use scan_url / scan_tools on the hosted remote MCP https://api.youraitools.co/injectscan/mcp (free daily tier, then x402). Returns risk_score (0-100), verdict (safe | suspicious | malicious), flagged, categories[] {category, score, description}, findings[] {rule, category, start, end, text}, hidden-character counts and chars_scanned. Read-only safety signal, not a guarantee.",
  inputSchema: { type: 'object', properties: { text: { type: 'string', description: 'The untrusted text to scan, as one plain string (1-100,000 characters; longer input returns a bad_request error). Pass the content exactly as your agent would read it; offsets in findings refer to this string.' } }, required: ['text'] },
  annotations: { readOnlyHint: true, openWorldHint: false, idempotentHint: true },
};
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];

export async function handle(m) {
  if (!m || m.jsonrpc !== '2.0' || typeof m.method !== 'string') return { jsonrpc: '2.0', id: m?.id ?? null, error: { code: -32600, message: 'Invalid Request' } };
  const note = m.id === undefined || m.id === null;
  const ok = (result) => (note ? null : { jsonrpc: '2.0', id: m.id, result });
  switch (m.method) {
    case 'initialize':
      return ok({ protocolVersion: PROTOCOLS.includes(m.params?.protocolVersion) ? m.params.protocolVersion : '2025-06-18', capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'injectscan', title: 'InjectScan', version: VERSION }, instructions: 'scan_text scores untrusted content (web pages, emails, tool output) for prompt injection. Verdicts: "safe", "suspicious" (worth a review) or "malicious" (likely an attack).' });
    case 'ping': return ok({});
    case 'tools/list': return ok({ tools: [TOOL] });
    case 'tools/call': {
      if (m.params?.name !== 'scan_text') return note ? null : { jsonrpc: '2.0', id: m.id, error: { code: -32602, message: `Unknown tool: ${m.params?.name}` } };
      const text = m.params?.arguments?.text;
      if (typeof text !== 'string' || !text) return ok({ isError: true, content: [{ type: 'text', text: 'bad_request: "text" (string) is required' }] });
      if (text.length > MAX) return ok({ isError: true, content: [{ type: 'text', text: `bad_request: up to ${MAX} characters (got ${text.length})` }] });
      const r = scanText(text, { maxChars: MAX });
      const top = r.findings.slice(0, 8).map((f) => `- ${f.category} (${f.rule}) at ${f.start}-${f.end}: "${(f.text || '').slice(0, 80)}"`).join('\n');
      const summary = `InjectScan: ${r.verdict.toUpperCase()} (risk ${r.risk_score}/100)${r.categories.length ? `\nCategories: ${r.categories.map((x) => `${x.category} ${x.score}`).join(', ')}` : ''}${top ? `\nFindings:\n${top}` : ''}`;
      return ok({ content: [{ type: 'text', text: summary }], structuredContent: r, isError: false });
    }
    default:
      return m.method.startsWith('notifications/') || note ? null : { jsonrpc: '2.0', id: m.id, error: { code: -32601, message: `Method not found: ${m.method}` } };
  }
}

export function serve({ input = process.stdin, output = process.stdout } = {}) {
  const rl = createInterface({ input, crlfDelay: Infinity });
  const write = (o) => output.write(JSON.stringify(o) + '\n');
  rl.on('line', async (line) => {
    if (!line.trim()) return;
    let msg; try { msg = JSON.parse(line); } catch { return write({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }); }
    const batch = Array.isArray(msg);
    const replies = (await Promise.all((batch ? msg : [msg]).map(handle))).filter(Boolean);
    if (replies.length) write(batch ? replies : replies[0]);
  });
  return rl;
}

const self = process.argv[1] || '';
if (import.meta.url === `file://${self}` || /injectscan-mcp$|x402-prompt-injection-scan$/.test(self)) serve();
