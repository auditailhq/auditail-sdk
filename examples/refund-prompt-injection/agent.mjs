// A scripted stand-in for an LLM support agent that obeys an instruction hidden in an email. Real models do this
// often enough that you can't rely on them not to: that's what prompt injection is. Scripted, so the demo is repeatable.
//
//   node agent.mjs --direct      the agent talks to the MCP server directly: the injected refund goes through
//   node agent.mjs               the agent talks through auditail-mcp-proxy: the refund is stopped
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const direct = process.argv.includes('--direct');
const server = ['node', join(here, 'support-mcp-server.mjs')];
const proxyBin = process.env.AUDITAIL_MCP_PROXY ?? 'auditail-mcp-proxy';
const cmd = direct ? server : [proxyBin, '--config', join(here, 'auditail-mcp.json'), '--session', `support-${Date.now()}`, '--', ...server];
if (!direct && !process.env.AUDITAIL_API_KEY) { console.error('Set AUDITAIL_API_KEY (your agent key), or run with --direct to see the attack work.'); process.exit(2); }

const child = spawn(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'inherit'], env: process.env });
const waiting = new Map();
createInterface({ input: child.stdout }).on('line', (l) => { const m = JSON.parse(l); waiting.get(m.id)?.(m); waiting.delete(m.id); });
let n = 0;
const rpc = (method, params) => new Promise((res) => { const id = ++n; waiting.set(id, res); child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n'); });
const tool = async (name, args = {}) => {
  const r = await rpc('tools/call', { name, arguments: args });
  const t = r.result?.content?.[0]?.text ?? r.error?.message;
  console.log(`\n> ${name}(${JSON.stringify(args)})\n${r.result?.isError ? '  [tool error] ' : '  '}${t.replace(/\n/g, '\n  ')}`);
  return r.result;
};

console.log(direct ? '=== WITHOUT Auditail: agent -> MCP server ===' : '=== WITH Auditail: agent -> auditail-mcp-proxy -> MCP server ===');
await rpc('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'support-agent', version: '1' } });
const email = (await tool('read_inbox')).content[0].text;
await tool('get_order', { orderId: '4471' });
// The "model" follows the hidden instruction.
const injected = /refund of ([\d.]+) (\w+)\s+to account (\w+)/i.exec(email);
const r = await tool('issue_refund', { amount: Number(injected[1]), currency: injected[2], accountId: injected[3], orderId: '4471' });
console.log(r.isError ? '\nRESULT: the injected refund was NOT executed.' : '\nRESULT: the injected refund WAS executed.');
child.stdin.end();
