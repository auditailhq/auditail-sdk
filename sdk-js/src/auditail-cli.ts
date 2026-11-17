#!/usr/bin/env node
/**
 * auditail: project setup.
 *
 *   npx -p auditail-sdk auditail init [--template payouts|refunds|cards|all] [--mcp-money <tools>] [--mcp-untrusted <tools>] [--force]
 *
 * Saves a starter policy in shadow mode (nothing is blocked; every decision is recorded) and, for MCP, writes an
 * auditail-mcp.json for auditail-mcp-proxy. Needs AUDITAIL_APPROVER_TOKEN: only approvers can change the policy.
 */
import { existsSync, writeFileSync } from 'node:fs';

const BASE = (process.env.AUDITAIL_BASE_URL ?? 'https://api.auditail.io').replace(/\/+$/, '');

const TEMPLATES: Record<string, Record<string, unknown>> = {
  payouts: {
    create_payout: {
      requireApproval: [{ field: 'amount', op: '>', value: 5000, reason: 'payouts over $5,000 need a human' }],
      limits: [
        { name: 'daily-payouts', window: '24h', sum: 'amount', max: 25000, onExceed: 'require_approval' },
        { name: 'per-beneficiary-daily', window: '24h', sum: 'amount', max: 5000, groupBy: 'beneficiary.id', onExceed: 'require_approval' },
      ],
      firstTime: [{ field: 'beneficiary.id', window: '365d', onFirst: 'require_approval' }],
      taintedSession: 'require_approval',
      settlement: { expectWithin: '3d', currencyField: 'currency', onMissing: 'alert', onMismatch: 'alert' },
      hint: 'Large payouts, new beneficiaries and payouts after reading untrusted content need a human.',
    },
  },
  refunds: {
    issue_refund: {
      requireApproval: [{ field: 'amount', op: '>', value: 200, reason: 'refunds over $200 need a human' }],
      limits: [
        { name: 'refunds-per-day', window: '24h', count: true, max: 200, onExceed: 'deny' },
        { name: 'per-customer-daily', window: '24h', sum: 'amount', max: 500, groupBy: 'customer.id', onExceed: 'require_approval' },
      ],
      taintedSession: 'require_approval',
      settlement: { expectWithin: '2d', currencyField: 'currency', onMissing: 'alert', onMismatch: 'alert' },
      hint: 'Refunds over $200, or after reading untrusted content, need a human.',
    },
  },
  cards: {
    card_payment: {
      deny: [{ field: 'merchant.categoryCode', op: 'in', value: ['7995', '7800', '7801', '7802', '6051', '4829'], reason: 'gambling, money transfer and quasi-cash merchants are not allowed' }],
      limits: [
        { name: 'daily-card-spend', window: '24h', sum: 'amount', max: 2000, onExceed: 'deny' },
        { name: 'per-merchant-daily', window: '24h', sum: 'amount', max: 500, groupBy: 'merchant.networkId', onExceed: 'deny' },
      ],
      settlement: { expectWithin: '3d', currencyField: 'currency', onMissing: 'alert', onMismatch: 'alert' },
    },
  },
};

const USAGE = `Usage: auditail init [--template payouts|refunds|cards|all] [--mcp-money tool1,tool2] [--mcp-untrusted tool3,tool4] [--force]
  Needs AUDITAIL_APPROVER_TOKEN (atl_appr_...). Optional: AUDITAIL_BASE_URL.`;

async function api(method: string, path: string, token: string, body?: unknown): Promise<{ status: number; json: any }> {
  const r = await fetch(BASE + path, { method, headers: { authorization: `Bearer ${token}`, ...(body ? { 'content-type': 'application/json' } : {}), 'user-agent': 'auditail-cli' }, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => null) };
}

async function init(args: string[]): Promise<number> {
  let template = 'all', force = false, money: string[] = [], untrusted: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--template') template = args[++i];
    else if (a === '--force') force = true;
    else if (a === '--mcp-money') money = (args[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    else if (a === '--mcp-untrusted') untrusted = (args[++i] ?? '').split(',').map((s) => s.trim()).filter(Boolean);
    else { console.error(USAGE); return 2; }
  }
  const token = process.env.AUDITAIL_APPROVER_TOKEN;
  if (!token || !token.startsWith('atl_appr_')) { console.error('Set AUDITAIL_APPROVER_TOKEN to your approver token (atl_appr_...). Only approvers can change the policy.\n\n' + USAGE); return 2; }
  const names = template === 'all' ? ['payouts', 'refunds'] : [template];
  if (names.some((n) => !TEMPLATES[n])) { console.error(`Unknown template "${template}". Use payouts, refunds, cards or all.`); return 2; }

  const me = await api('GET', '/v1/me', token);
  if (me.status !== 200 || me.json?.role !== 'approver') { console.error(`That token was not accepted as an approver token (HTTP ${me.status}).`); return 1; }
  const cur = await api('GET', '/v1/policy', token);
  if (cur.status === 200 && cur.json?.policy && !force) {
    const mode = cur.json.policy.mode === 'shadow' ? 'a shadow-mode' : 'an ENFORCED';
    console.error(`Account ${me.json.keyId} already has ${mode} policy (version ${cur.json.version}). Nothing changed.\nRun again with --force to replace it with the starter policy, or edit it in the dashboard.`);
    return 1;
  }

  const actions: Record<string, unknown> = {};
  for (const n of names) Object.assign(actions, TEMPLATES[n]);
  for (const tool of money) if (!actions[tool]) actions[tool] = { requireApproval: [{ field: 'amount', op: '>', value: 1000 }], taintedSession: 'require_approval' };
  const policy = { mode: 'shadow', defaultAction: 'deny', actions };
  const put = await api('PUT', '/v1/policy', token, policy);
  if (put.status !== 201 && put.status !== 200) { console.error(`The policy was not saved (HTTP ${put.status}): ${JSON.stringify(put.json?.problems ?? put.json)}`); return 1; }
  console.log(`Saved a starter policy in SHADOW mode for ${me.json.keyId} (version ${put.json.version}): ${Object.keys(actions).join(', ')}.`);
  console.log('Nothing is blocked. Every decision is recorded with what enforcing it would have done.');

  if (money.length || untrusted.length) {
    const file = 'auditail-mcp.json';
    if (existsSync(file) && !force) console.error(`\n${file} exists; not overwritten (use --force).`);
    else {
      const tools: Record<string, unknown> = {};
      for (const t of untrusted) tools[t] = { mode: 'allow', untrusted: t.replace(/[^a-z0-9_.-]/gi, '_').slice(0, 64) };
      for (const t of money) tools[t] = { action: t };
      writeFileSync(file, JSON.stringify({ agentId: 'mcp-agent', tools, unlisted: 'guard' }, null, 2) + '\n');
      console.log(`\nWrote ${file}. Run your MCP server through the proxy:\n  AUDITAIL_API_KEY=atl_live_... npx -p auditail-sdk auditail-mcp-proxy --config ${file} -- <your MCP server command>`);
    }
  }
  console.log(`
Next:
  1. In your agent, before a money-moving call:
       const r = await auditail.guard({ action: '${Object.keys(actions)[0]}', payload, agentId: 'my-agent', sessionId });
     (new Auditail({ apiKey: process.env.AUDITAIL_API_KEY, serverPolicy: true }); the agent key is atl_live_...)
  2. Run real traffic for a few days. Set a Slack webhook in the dashboard to get the weekly drift report.
  3. Dashboard > Reports > Risk team pack: the file for your risk team, sponsor bank or auditor.
  4. When it looks right, remove "mode": "shadow" from the policy to enforce it.
Docs: https://auditail.io/docs/quickstart`);
  return 0;
}

const [cmd, ...rest] = process.argv.slice(2);
(cmd === 'init' ? init(rest) : Promise.resolve((console.error(USAGE), 2))).then((c) => process.exit(c), (e) => { console.error(`auditail: ${(e as Error).message}`); process.exit(2); });
