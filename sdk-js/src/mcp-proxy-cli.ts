#!/usr/bin/env node
/**
 * auditail-mcp-proxy: a stdio MCP proxy that asks Auditail before every tool call.
 *
 *   AUDITAIL_API_KEY=atl_live_... npx -p auditail-sdk auditail-mcp-proxy --config auditail-mcp.json -- npx -y some-mcp-server
 *
 * Messages are newline-delimited JSON-RPC (the MCP stdio transport). Only `tools/call` requests are inspected; everything
 * else is passed through unchanged in both directions. Logs go to stderr; stdout carries only protocol messages.
 */
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Auditail } from './index';
import { McpGuard, type McpGuardConfig } from './mcp';

type Msg = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> };

const USAGE = 'Usage: auditail-mcp-proxy [--config <file.json>] [--agent <id>] [--session <id>] -- <mcp server command> [args...]\n'
  + 'Needs AUDITAIL_API_KEY. Optional: AUDITAIL_BASE_URL, AUDITAIL_MCP_CONFIG, AUDITAIL_SESSION_ID.';

function main(): void {
  const argv = process.argv.slice(2);
  const sep = argv.indexOf('--');
  const own = sep >= 0 ? argv.slice(0, sep) : argv;
  const cmd = sep >= 0 ? argv.slice(sep + 1) : [];
  let configFile = process.env.AUDITAIL_MCP_CONFIG, agent: string | undefined, session = process.env.AUDITAIL_SESSION_ID;
  for (let i = 0; i < own.length; i++) {
    if (own[i] === '--config') configFile = own[++i];
    else if (own[i] === '--agent') agent = own[++i];
    else if (own[i] === '--session') session = own[++i];
    else { console.error(USAGE); process.exit(2); }
  }
  const apiKey = process.env.AUDITAIL_API_KEY;
  if (!cmd.length || !apiKey) { console.error(USAGE); process.exit(2); }

  const fileConfig: Partial<McpGuardConfig> = configFile ? JSON.parse(readFileSync(configFile, 'utf8')) : {};
  const config: McpGuardConfig = { ...fileConfig, agentId: agent ?? fileConfig.agentId ?? 'mcp-agent', ...(session ? { sessionId: session } : {}) };
  const auditail = new Auditail({
    apiKey, serverPolicy: true, logLevel: 'silent', ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}),
    onError: (e) => process.stderr.write(`[auditail-mcp-proxy] ${e.message}\n`),
  });
  const guard = new McpGuard(auditail, config);
  process.stderr.write(`[auditail-mcp-proxy] guarding "${cmd.join(' ')}" as agent ${config.agentId}, session ${guard.sessionId}\n`);

  const child = spawn(cmd[0], cmd.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });
  const toClient = (line: string) => process.stdout.write(line + '\n');
  const toServer = (line: string) => { if (child.stdin.writable) child.stdin.write(line + '\n'); };

  // Whole lines only, so our own replies never interleave with a partial line from the server.
  createInterface({ input: child.stdout, crlfDelay: Infinity }).on('line', toClient);

  const handle = async (m: Msg): Promise<void> => {
    try {
      const v = await guard.check((m.params ?? {}) as Record<string, unknown>);
      if (v.forward) toServer(JSON.stringify({ ...m, params: v.params }));
      else toClient(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: v.result }));
    } catch (e) {
      // Never forward a call that wasn't decided.
      toClient(JSON.stringify({ jsonrpc: '2.0', id: m.id, result: { content: [{ type: 'text', text: `Blocked by Auditail: the call could not be checked (${String((e as Error)?.message ?? e).slice(0, 200)}).` }], isError: true } }));
    }
  };
  const isCall = (m: unknown): m is Msg => !!m && typeof m === 'object' && (m as Msg).method === 'tools/call' && (m as Msg).id !== undefined && (m as Msg).id !== null;

  createInterface({ input: process.stdin, crlfDelay: Infinity })
    .on('line', (line) => {
      if (!line.trim()) return;
      let m: unknown;
      try { m = JSON.parse(line); } catch { return toServer(line); } // not ours to judge; the server answers parse errors
      if (isCall(m)) return void handle(m);
      // JSON-RPC batches (protocol 2025-03-26 only): forward as-is unless they contain a tool call, then split them.
      if (Array.isArray(m) && m.some(isCall)) { for (const x of m) isCall(x) ? void handle(x) : toServer(JSON.stringify(x)); return; }
      toServer(line);
    })
    .on('close', () => child.stdin.end());

  child.on('exit', (code, signal) => { auditail.flush().finally(() => process.exit(code ?? (signal ? 1 : 0))); });
  child.on('error', (e) => { process.stderr.write(`[auditail-mcp-proxy] could not start "${cmd[0]}": ${e.message}\n`); process.exit(1); });
  for (const s of ['SIGINT', 'SIGTERM'] as const) process.on(s, () => child.kill(s));
}

main();
