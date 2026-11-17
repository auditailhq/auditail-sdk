/**
 * Auditail for MCP: decide every `tools/call` before it reaches an MCP server.
 *
 * Use it two ways:
 *   - `auditail-mcp-proxy -- <server command>`: a stdio proxy in front of any MCP server, no code changes (see mcp-proxy-cli.ts).
 *   - `new McpGuard(auditail, config).check(params)`: in your own MCP server or client, before running a tool.
 *
 * Only `tools/call` is inspected. Everything else (initialize, tools/list, notifications, server-to-client requests of
 * older protocol versions) passes through unchanged, so it works with initialize-based and stateless protocol versions.
 */
import type { Auditail, GuardResult } from './index';

export interface McpToolRule {
  /** 'guard' (default): ask Auditail. 'allow': pass without a decision (read-only tools). 'deny': always block. */
  mode?: 'guard' | 'allow' | 'deny';
  /** Auditail action name used in your policy. Default: `mcp.<tool name>`. */
  action?: string;
  /**
   * Map payload fields to argument paths, e.g. { amount: 'amount', 'beneficiary.iban': 'to.iban' }. Default: the tool
   * arguments as they are.
   */
  payload?: Record<string, string>;
  /**
   * This tool returns outside content (email, web page, file). Calling it marks the session untrusted with this source
   * name, so later money-moving tools in the session need a human (policy `taintedSession`).
   */
  untrusted?: string;
  /** Where the arguments came from, if you know (e.g. 'user'). Never let the model choose it. */
  source?: string;
}

export interface McpGuardConfig {
  /** Agent id recorded with every decision. */
  agentId: string;
  /** Session for taint tracking. Default: one random id per McpGuard (per proxy process). */
  sessionId?: string;
  /** Rules per tool name. */
  tools?: Record<string, McpToolRule>;
  /** Tools without a rule: 'guard' (default, action `mcp.<name>`), 'allow' or 'deny'. */
  unlisted?: 'guard' | 'allow' | 'deny';
  /**
   * Block the tool call until a human decides. Default false: the call returns "needs approval" right away, and calling
   * the same tool with the same arguments again resumes that approval instead of opening a new one.
   */
  wait?: boolean;
  /** Add the signed receipt to the forwarded call as `_meta["io.auditail/receipt"]`. Default true. */
  injectReceipt?: boolean;
}

export type McpVerdict =
  | { forward: true; params: Record<string, unknown>; result?: undefined }
  | { forward: false; result: Record<string, unknown>; params?: undefined };

type Params = { name?: unknown; arguments?: unknown; _meta?: Record<string, unknown>; [k: string]: unknown };

const PENDING_TTL_MS = 24 * 3600_000;
const CONTINUATION_TTL_MS = 10 * 60_000;
const MAX_CACHE = 1000;

function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(',')}}`;
  return JSON.stringify(v ?? null);
}

function getPath(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((o, k) => (o && typeof o === 'object' ? (o as Record<string, unknown>)[k] : undefined), obj);
}

function setPath(obj: Record<string, unknown>, path: string, value: unknown): void {
  const keys = path.split('.');
  let o = obj;
  for (const k of keys.slice(0, -1)) o = (o[k] && typeof o[k] === 'object' ? o[k] : (o[k] = {})) as Record<string, unknown>;
  o[keys[keys.length - 1]] = value;
}

export class McpGuard {
  readonly sessionId: string;
  private readonly pending = new Map<string, { approvalId: string; at: number }>();
  private readonly allowed = new Map<string, number>();

  constructor(private readonly auditail: Auditail, private readonly config: McpGuardConfig) {
    if (!config?.agentId) throw new Error('[Auditail] McpGuard needs config.agentId');
    this.sessionId = config.sessionId ?? `mcp_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  }

  /** Decide a `tools/call` request's params. Forward `params` when `forward` is true; otherwise answer with `result`. */
  async check(params: Params): Promise<McpVerdict> {
    const name = typeof params?.name === 'string' ? params.name : '';
    const args = params?.arguments && typeof params.arguments === 'object' ? (params.arguments as Record<string, unknown>) : {};
    const newEra = !!params?._meta && Object.keys(params._meta).some((k) => k.startsWith('io.modelcontextprotocol/'));
    const rule: McpToolRule = this.config.tools?.[name] ?? { mode: this.config.unlisted ?? 'guard' };
    const block = (text: string) => ({ forward: false as const, result: { ...(newEra ? { resultType: 'complete' } : {}), content: [{ type: 'text', text }], isError: true } });

    if (rule.untrusted) {
      try {
        await this.auditail.markUntrusted(this.sessionId, rule.untrusted, `MCP tool ${name}`.slice(0, 300));
      } catch (e) {
        // Fail closed: if the taint can't be recorded, the content must not reach the agent.
        return block(`Blocked by Auditail: could not record that this session reads untrusted content (${String((e as Error)?.message ?? e).slice(0, 200)}). Retry later.`);
      }
    }
    const mode = rule.mode ?? 'guard';
    if (mode === 'allow') return { forward: true, params };
    if (mode === 'deny') return block(`Blocked by Auditail: the tool "${name}" is not allowed for this agent. Do not retry; tell the user.`);

    const action = rule.action ?? `mcp.${name}`;
    let payload: Record<string, unknown> = args;
    if (rule.payload) {
      payload = {};
      for (const [field, path] of Object.entries(rule.payload)) { const v = getPath(args, path); if (v !== undefined) setPath(payload, field, v); }
    }
    const key = `${name}\n${stable(args)}`;
    this.prune();

    // A continuation of a call already decided (multi round-trip input): don't decide it twice.
    const isContinuation = params.inputResponses !== undefined || params.requestState !== undefined;
    if (isContinuation && (this.allowed.get(key) ?? 0) > Date.now() - CONTINUATION_TTL_MS) return { forward: true, params };

    // The same call again while a human is deciding: resume that approval instead of opening another.
    const p = this.pending.get(key);
    if (p) {
      const r = await this.auditail.resume(p.approvalId);
      if (r.pending) return block(this.pendingText(p.approvalId));
      this.pending.delete(key);
      if (r.status === 'unavailable') return block(`Blocked by Auditail: could not read approval ${p.approvalId} (${r.reason}). Retry later.`);
      if (!r.approved) return block(`Blocked by Auditail (${r.code}): ${r.reason}. Do not retry unchanged; ask the user how to proceed.`);
      return this.forward(params, key, r.receipt);
    }

    const g: GuardResult = await this.auditail.guard({ action, payload, agentId: this.config.agentId, sessionId: this.sessionId, source: rule.source, wait: this.config.wait ?? false });
    if (g.approved) return this.forward(params, key, g.receipt);
    if (g.pending && g.approval?.id) {
      this.pending.set(key, { approvalId: g.approval.id, at: Date.now() });
      return block(this.pendingText(g.approval.id, g.reason));
    }
    return block(`Blocked by Auditail (${g.code}): ${g.reason ?? 'not allowed'}${g.hint ? ` ${g.hint}` : ''}`);
  }

  private forward(params: Params, key: string, receipt?: string): McpVerdict {
    this.allowed.set(key, Date.now());
    if (!receipt || this.config.injectReceipt === false) return { forward: true, params };
    return { forward: true, params: { ...params, _meta: { ...(params._meta ?? {}), 'io.auditail/receipt': receipt } } };
  }

  private pendingText(approvalId: string, reason?: string | null): string {
    return `Not executed: this needs human approval in Auditail (${approvalId})${reason ? `. ${reason.replace(/[.\s]+$/, '')}` : ''}. `
      + 'Tell the user it is waiting for approval. Once approved, call this tool again with exactly the same arguments; it will then run.';
  }

  private prune(): void {
    const now = Date.now();
    for (const [k, v] of this.pending) if (v.at < now - PENDING_TTL_MS) this.pending.delete(k);
    for (const [k, at] of this.allowed) if (at < now - CONTINUATION_TTL_MS) this.allowed.delete(k);
    while (this.pending.size > MAX_CACHE) this.pending.delete(this.pending.keys().next().value as string);
    while (this.allowed.size > MAX_CACHE) this.allowed.delete(this.allowed.keys().next().value as string);
  }
}
