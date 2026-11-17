/**
 * Auditail SDK
 * The security layer for autonomous AI agents.
 * Guardrails that block risky actions, plus a tamper-evident audit trail.
 *
 * https://auditail.io/docs
 */

export interface AuditailConfig {
  apiKey: string;
  /**
   * Log level for the SDK. Defaults to 'info'.
   */
  logLevel?: 'debug' | 'info' | 'warn' | 'error' | 'silent';
  /**
   * Your environment label — shows up in the dashboard. Defaults to 'production'.
   */
  environment?: string;
  /**
   * Base URL override — for private cloud deployments.
   */
  baseUrl?: string;
  /**
   * Payload keys whose values are replaced with "[REDACTED]" before an event is stored or sent.
   * Matching is case-insensitive and applies at any nesting depth. Rules still see the real payload.
   * Defaults cover common secrets (password, token, secret, apiKey, authorization, ssn, card...).
   */
  redactKeys?: string[];
  /** Set false to keep events local (no network). Useful for tests. Defaults to true. */
  ship?: boolean;
  /** How often queued events are flushed, in ms. Defaults to 1000. */
  flushIntervalMs?: number;
  /** Called when events could not be delivered (after retries) or were dropped. Never throws into your agent. */
  onError?: (error: Error) => void;
  /**
   * How long a human has to answer a `require_approval` rule before the action is denied automatically.
   * Defaults to 900 (15 minutes). A rule can override it with its own `approvalTimeoutSeconds`.
   */
  approvalTimeoutSeconds?: number;
  /**
   * Called as soon as an approval request is created, so you can notify people through any channel you like
   * (your own Slack bot, email, pager...). Dashboard and webhook notifications work without this.
   * Never throws into your agent.
   */
  onApprovalRequested?: (approval: Approval) => void;
  /**
   * Also enforce the server-side policy your approvers manage in Auditail: allowed actions (default-deny), spending
   * and rate limits, untrusted-source rules and approval thresholds. The agent cannot change that policy.
   * guard() then makes one network call per action, and denies if Auditail cannot be reached. Default false.
   */
  serverPolicy?: boolean;
  /**
   * How often to check the kill switch when rules run locally, in ms. Default 10000; 0 disables.
   * With serverPolicy the server enforces freezes on every action, so this only matters in local mode.
   */
  freezeCheckIntervalMs?: number;
}

/**
 * Stable reason codes on every GuardResult, for programs (and agents) to branch on.
 * Policy codes come from the server; rule codes come from rules in this process.
 */
export type GuardCode =
  | 'allowed' | 'approved_by_human'
  | 'rule_blocked' | 'rule_error'
  | 'approval_denied' | 'approval_expired' | 'approval_unavailable' | 'approval_pending'
  | 'no_policy' | 'action_not_allowed' | 'action_disabled' | 'policy_denied' | 'untrusted_source'
  | 'limit_exceeded' | 'invalid_payload' | 'policy_unavailable' | 'frozen' | 'first_time'
  | (string & {});

export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

/** A human-approval request as stored by Auditail. */
export interface Approval {
  id: string;
  status: ApprovalStatus;
  agentId: string;
  action: string;
  ruleName: string;
  reason: string | null;
  payload: Record<string, unknown>;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  decidedBy: string | null;
  comment: string | null;
  /** Signed receipt, present only when approved. */
  receipt?: string;
  intent?: string | null;
  userRequest?: string | null;
  source?: string | null;
  /** Why approval was required and current limit usage (policy-triggered approvals). */
  context?: { policyVersion?: number; reasons?: { outcome: string; code: string; reason: string }[]; limits?: LimitUsage[]; untrusted?: boolean } | null;
}

/** The approval outcome attached to a GuardResult. 'unavailable' means Auditail could not be reached (action denied). */
export interface GuardApproval {
  id: string;
  status: ApprovalStatus | 'unavailable';
  decidedBy?: string;
  comment?: string;
  /**
   * Signed proof that a human approved exactly this action and payload. Present only when approved.
   * Pass it to the system that executes the action, which checks it with `verifyReceipt()`.
   */
  receipt?: string;
}

export interface GuardOptions {
  /** The action the AI agent wants to perform */
  action: string;
  /** The data payload associated with the action */
  payload: Record<string, unknown>;
  /** Unique identifier for the agent performing the action */
  agentId: string;
  /** Optional: ID of the user or session that triggered this action */
  userId?: string;
  /** Optional: metadata tags for filtering in the dashboard */
  tags?: Record<string, string>;
  /**
   * For `require_approval` rules: set false to return immediately with `pending: true` instead of waiting for
   * the decision. Use `waitForApproval(result.approval.id)` later. Defaults to true (wait).
   */
  wait?: boolean;
  /**
   * Where this request's data came from, for example 'user', 'system', 'inbound_email', 'web_page', 'document'.
   * Set it in your integration code from what you fed the model; never let the model choose it. By default only
   * 'user' and 'system' are trusted, and policy decides what untrusted origins trigger.
   */
  source?: string;
  /** Per-field origins, e.g. { 'beneficiary.iban': 'inbound_email' }. Lets policy react only to sensitive fields. */
  fieldSources?: Record<string, string>;
  /** The agent's stated reason for this action. Shown to approvers and kept in the audit log. */
  intent?: string;
  /** The user's original request that led to this action. Shown to approvers. */
  userRequest?: string;
  /**
   * Your agent session or conversation id. Once the session has read untrusted data (markUntrusted(), or an action with an
   * untrusted source), money-moving actions in it need a human, per the policy's taintedSession setting.
   */
  sessionId?: string;
  /** Makes retries safe: the same key returns the original decision. With serverPolicy a key is generated per call if omitted. */
  idempotencyKey?: string;
  /** Pause/resume: your workflow's id for this request, echoed in the approval and its callback. */
  correlationId?: string;
  /** Pause/resume: HTTPS URL Auditail POSTs to (signed) when a human decides. Use with wait: false. */
  callbackUrl?: string;
}

/** What simulate() predicts. Nothing was recorded, reserved or sent for approval. */
export interface SimulateResult {
  dryRun: true;
  decision: 'allow' | 'deny' | 'require_approval' | 'unavailable';
  code: string;
  reason: string;
  hint?: string | null;
  policyVersion?: number;
  mode?: 'shadow';
  limits?: Array<Record<string, unknown>>;
  session?: { tainted: boolean; since: string };
}

/** What resume() returns for an approval: final once a human decided, otherwise still pending. */
export interface ResumeResult {
  status: ApprovalStatus | 'unavailable';
  approved: boolean;
  pending: boolean;
  code: string;
  reason: string;
  receipt?: string;
  approval?: GuardApproval & { correlationId?: string | null };
}

export type OutcomeStatus = 'settled' | 'failed' | 'reversed' | 'refunded' | 'voided';

export interface GuardResult {
  /** Whether the action is approved to proceed */
  approved: boolean;
  /** Unique ID for this audit event — store it for traceability */
  auditId: string;
  /** If denied, the reason from the matching guardrail rule */
  reason?: string;
  /** The guardrail rule that matched, if any */
  matchedRule?: string;
  /** Timestamp of the decision */
  timestamp: string;
  /** Time guard() took in milliseconds. Includes the wait when a human approval was required. */
  latencyMs: number;
  /** Present when a `require_approval` rule fired. */
  approval?: GuardApproval;
  /** True only when you passed `wait: false` and the request is still awaiting a human. The action is NOT approved yet. */
  pending?: boolean;
  /** Stable reason code. See GuardCode. */
  code: GuardCode;
  /** What the agent can do instead, when there is something useful to say (e.g. "4,000 amount left in this 24h window"). */
  hint?: string;
  /** Who made the final decision. */
  decidedBy: 'rule' | 'policy' | 'human';
  /**
   * Signed receipt for an allowed action: from a human approval, or from your server-side policy.
   * Pass it to the system that executes the action, which checks it with `verifyReceipt()`.
   */
  receipt?: string;
  /** Usage against each server-side limit this action counts toward (serverPolicy only). */
  limits?: LimitUsage[];
  /** Present when the server-side policy is in shadow mode: what would have happened if it were enforced. */
  shadow?: { wouldBe: 'allow' | 'deny' | 'require_approval'; code: string; reason: string };
}

export interface LimitUsage {
  limit: string; window: string; kind: 'sum' | 'count'; field: string | null;
  group: { by: string; value: string } | null;
  used: number; thisAction: number; max: number; remaining: number; text: string;
}

export interface GuardrailRule {
  /** Unique name for this rule */
  name: string;
  /** Human-readable description */
  description: string;
  /**
   * The condition that triggers a block.
   * Return true to BLOCK the action.
   */
  condition: (options: GuardOptions) => boolean | Promise<boolean>;
  /**
   * What to do when this rule matches.
   * - 'block': deny the action outright
   * - 'require_approval': pause until a human approves or denies it in the dashboard (or via your webhook).
   *   No answer before the timeout means denied.
   * - 'alert': allow but record the match
   */
  action: 'block' | 'require_approval' | 'alert';
  /** For 'require_approval': seconds a human has to respond (10 to 86400). Overrides the client default. */
  approvalTimeoutSeconds?: number;
  /** For 'require_approval': how long the signed receipt stays valid after approval (60 to 86400). Default 900. */
  receiptTtlSeconds?: number;
  /** Returned as `hint` when this rule blocks, so the agent knows what to do instead. */
  hint?: string;
  /** Returned as `code` when this rule blocks. Default 'rule_blocked'. */
  code?: string;
}

export interface AuditEvent {
  auditId: string;
  agentId: string;
  userId?: string;
  action: string;
  payload: Record<string, unknown>;
  approved: boolean;
  reason?: string;
  matchedRule?: string;
  tags?: Record<string, string>;
  timestamp: string;
  environment: string;
  sdkVersion: string;
  /** Set when the decision was made by a human approval. Auditail records those events itself. */
  approvalId?: string;
  code?: string;
  source?: string;
}

import { redact, redactSet } from './shared';
import { verifyReceipt, type PublicKeyInfo, type ReceiptClaims } from './verify';
export interface CheckReceiptOptions {
  /** The action you are about to execute. Required: a receipt for one action must not authorize another. */
  action: string;
  /** The payload you are about to execute. Required: compared with the approved payload's hash. */
  payload: Record<string, unknown>;
  /** Your account id (key_...). Default: looked up once with this client's key. */
  account?: string;
  agentId?: string;
  environment?: string;
  redactKeys?: string[];
  /** Pin public keys instead of fetching them from this client's baseUrl. */
  publicKeys?: PublicKeyInfo[];
  keysUrl?: string;
  /** Accept only receipts a human approved (not policy decisions). */
  requireHumanApproval?: boolean;
  /** Your own id for this execution (e.g. the payout id), so retries across restarts are safe. */
  requestId?: string;
}
export type CheckReceiptResult =
  | { ok: true; claims: ReceiptClaims; redeemedAt: string }
  | { ok: false; code: 'missing_receipt' | 'invalid_receipt' | 'already_redeemed' | 'receipt_expired' | 'unavailable' | string; reason: string };

/** Result of redeemReceipt(). When redeemed is false, do not execute the action. */
export type RedeemResult =
  | { redeemed: true; receiptId: string; action: string; agentId: string; approvedBy: string | null; redeemedAt: string; replayed?: boolean }
  | { redeemed: false; code: 'already_redeemed' | 'invalid_receipt' | 'receipt_expired' | 'unavailable' | string; message: string };

export { verifyReceipt, verifyCheckpoint, verifyEvidence, verifyReport, verifyBundle, extractPackReports, checkTimestamp, approvalStatement, timestampImprintInput, fetchPublicKeys, DEFAULT_KEYS_URL } from './verify';
export type { ReceiptClaims, CheckpointClaims, VerifyReceiptOptions, VerifyResult, PublicKeyInfo, Evidence, EvidenceEvent, EvidenceReport, BundleReport, TimestampInfo } from './verify';
export { generateApproverKey, importApproverKey, signApproval } from './approver';

const SDK_VERSION = '0.12.0';
const MAX_QUEUE = 10_000;
const MAX_BATCH = 50;
const MAX_DELIVERY_ATTEMPTS = 5;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

interface Decision {
  approved: boolean;
  code: GuardCode;
  decidedBy: 'rule' | 'policy' | 'human';
  reason?: string;
  hint?: string;
  matchedRule?: string;
  approval?: GuardApproval;
  pending?: boolean;
  receipt?: string;
  limits?: LimitUsage[];
  shadow?: { wouldBe: 'allow' | 'deny' | 'require_approval'; code: string; reason: string };
  /** The server recorded this decision in the audit log itself. */
  serverRecorded?: boolean;
  serverAuditId?: string;
}

interface PolicyResponse {
  decision: 'allow' | 'deny' | 'require_approval';
  decisionId: string;
  auditId?: string;
  code: string;
  reason: string;
  hint?: string | null;
  receipt?: string;
  limits?: LimitUsage[];
  approval?: Approval;
  shadow?: { wouldBe: 'allow' | 'deny' | 'require_approval'; code: string; reason: string };
}

/**
 * Auditail client. Instantiate once at app startup and reuse.
 *
 * @example
 * const auditail = new Auditail({ apiKey: 'your_key' });
 *
 * const result = await auditail.guard({
 *   action: 'send_email',
 *   payload: { to: 'client@example.com', body: 'Report attached.' },
 *   agentId: 'financial-bot-01',
 * });
 *
 * if (result.approved) {
 *   // Execute the action
 * }
 */
export class Auditail {
  private config: Required<AuditailConfig>;
  private rules: GuardrailRule[] = [];
  private auditLog: AuditEvent[] = [];
  private queue: AuditEvent[] = [];
  private redactSet: Set<string>;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private inflight: Promise<void> | null = null;
  private onError: (e: Error) => void;
  private freezes: { scope: 'all' | 'agent' | 'action'; target: string | null; reason: string; createdBy: string; createdAt: string }[] = [];
  private accountId: string | null = null;
  private freezeCheckedAt = 0;
  private freezeInflight: Promise<void> | null = null;

  constructor(config: AuditailConfig) {
    if (!config.apiKey) {
      throw new Error('[Auditail] No API key provided. Get your free API key at: https://auditail.io/waitlist');
    }

    this.config = {
      apiKey: config.apiKey,
      logLevel: config.logLevel ?? 'info',
      environment: config.environment ?? 'production',
      baseUrl: (config.baseUrl ?? 'https://api.auditail.io').replace(/\/+$/, ''),
      redactKeys: config.redactKeys ?? [],
      ship: config.ship ?? true,
      flushIntervalMs: config.flushIntervalMs ?? 1000,
      onError: config.onError ?? ((e) => this._log('error', e.message)),
      approvalTimeoutSeconds: config.approvalTimeoutSeconds ?? 900,
      onApprovalRequested: config.onApprovalRequested ?? (() => {}),
      serverPolicy: config.serverPolicy ?? false,
      freezeCheckIntervalMs: config.freezeCheckIntervalMs ?? 10_000,
    };
    this.onError = this.config.onError;
    this.redactSet = redactSet(this.config.redactKeys);
  }

  /**
   * Register a custom guardrail rule.
   * Rules are evaluated in the order they are added.
   */
  addRule(rule: GuardrailRule): this {
    this.rules.push(rule);
    this._log('debug', `Guardrail rule added: "${rule.name}"`);
    return this;
  }

  /**
   * Register multiple guardrail rules at once.
   */
  addRules(rules: GuardrailRule[]): this {
    rules.forEach((r) => this.addRule(r));
    return this;
  }

  /**
   * Evaluate an AI agent action against all registered guardrail rules
   * and record a tamper-evident audit event.
   *
   * This is the core method of the SDK.
   */
  async guard(options: GuardOptions): Promise<GuardResult> {
    const start = Date.now();
    const auditId = this._generateId();
    this._log('debug', `Evaluating action "${options.action}" for agent "${options.agentId}"`);

    let d: Decision = { approved: true, code: 'allowed', decidedBy: 'rule' };
    let approvalRule: GuardrailRule | undefined;

    // 0. Kill switch (local mode). With serverPolicy, the server enforces it on every call.
    if (!this.config.serverPolicy) {
      const f = await this._activeFreeze(options.agentId, options.action);
      if (f) {
        const what = f.scope === 'all' ? 'All agents are' : f.scope === 'agent' ? `Agent "${f.target}" is` : `Action "${f.target}" is`;
        d = { approved: false, code: 'frozen', decidedBy: 'policy', matchedRule: 'kill-switch',
          reason: `${what} frozen by ${f.createdBy} since ${f.createdAt}: ${f.reason}`,
          hint: 'Stop and tell the user. An approver must lift the freeze before this can run; retrying will not help.' };
      }
    }

    // 1. Local rules: instant, in-process.
    for (const rule of d.approved ? this.rules : []) {
      let triggered: boolean;
      try {
        triggered = await rule.condition(options);
      } catch (err) {
        // Fail closed: a rule that cannot be evaluated blocks the action outright. It never asks a human,
        // so a coding bug cannot page approvers or stall the agent until the approval times out.
        this._log('error', `Rule "${rule.name}" threw an error: ${err}. Failing closed (blocking action).`);
        d = { approved: false, code: 'rule_error', decidedBy: 'rule', matchedRule: rule.name,
          reason: `Blocked: rule "${rule.name}" could not be evaluated (${String((err as Error)?.message ?? err).slice(0, 200)}).`,
          hint: 'This is a bug in a guardrail rule, not something the agent can fix. Report it.' };
        break;
      }
      if (!triggered) continue;
      if (rule.action === 'block') {
        this._log('warn', `Action BLOCKED by rule "${rule.name}": ${rule.description}`);
        d = { approved: false, code: rule.code ?? 'rule_blocked', decidedBy: 'rule', matchedRule: rule.name, reason: rule.description, hint: rule.hint };
        break;
      }
      if (rule.action === 'require_approval') { approvalRule = rule; d.matchedRule = rule.name; break; }
      if (rule.action === 'alert') { this._log('warn', `ALERT fired by rule "${rule.name}": ${rule.description}`); d.matchedRule ??= rule.name; }
    }

    // 2. Server-side policy and/or human approval.
    if (d.approved) {
      if (this.config.serverPolicy) d = await this._policyFlow(options, approvalRule, d.matchedRule);
      else if (approvalRule) { this._log('warn', `Approval REQUIRED by rule "${approvalRule.name}": ${approvalRule.description}`); d = await this._approvalFlow(options, approvalRule); }
    }

    const latencyMs = Date.now() - start;
    const timestamp = new Date().toISOString();
    const event: AuditEvent = {
      auditId: d.serverAuditId ?? auditId,
      agentId: options.agentId,
      userId: options.userId,
      action: options.action,
      payload: redact(options.payload, this.redactSet) as Record<string, unknown>,
      approved: d.approved,
      reason: d.reason,
      matchedRule: d.matchedRule,
      tags: options.tags,
      timestamp,
      environment: this.config.environment,
      sdkVersion: SDK_VERSION,
      approvalId: d.approval?.id,
      code: d.code,
      source: options.source,
    };
    this.auditLog.push(event);
    this._log('info', `[${d.pending ? 'PENDING' : d.approved ? 'APPROVED' : 'BLOCKED'}] ${options.action} (${d.code}) | auditId: ${event.auditId} | ${latencyMs}ms`);

    // Decisions made by the server (policy, human approval) are recorded there. Everything else ships in the background.
    if (!d.serverRecorded) this._shipToApi(event);

    return {
      approved: d.approved, auditId: event.auditId, reason: d.reason, matchedRule: d.matchedRule, timestamp, latencyMs,
      code: d.code, decidedBy: d.decidedBy,
      ...(d.hint ? { hint: d.hint } : {}),
      ...(d.approval ? { approval: d.approval } : {}),
      ...(d.pending ? { pending: true } : {}),
      ...(d.receipt ? { receipt: d.receipt } : {}),
      ...(d.limits ? { limits: d.limits } : {}),
      ...(d.shadow ? { shadow: d.shadow } : {}),
    };
  }

  private async _policyFlow(options: GuardOptions, approvalRule: GuardrailRule | undefined, matchedRule: string | undefined): Promise<Decision> {
    const unavailable = (why: string): Decision => ({
      approved: false, code: 'policy_unavailable', decidedBy: 'policy', matchedRule,
      reason: `Server-side policy could not be checked (${why}); action denied.`,
      hint: 'Retry later. Actions are never allowed when the policy cannot be checked.',
    });
    if (!this.config.ship) return unavailable('shipping is disabled');
    const r = await this._api<PolicyResponse>('POST', '/v1/decide', {
      action: options.action,
      agentId: options.agentId,
      payload: redact(options.payload, this.redactSet),
      userId: options.userId,
      tags: options.tags,
      environment: this.config.environment,
      source: options.source,
      fieldSources: options.fieldSources,
      intent: options.intent,
      userRequest: options.userRequest,
      timeoutSeconds: approvalRule?.approvalTimeoutSeconds ?? this.config.approvalTimeoutSeconds,
      ...(approvalRule ? { requireApproval: { ruleName: approvalRule.name, reason: approvalRule.description } } : {}),
      sessionId: options.sessionId, correlationId: options.correlationId, callbackUrl: options.callbackUrl,
      // One key per guard() call: network retries inside this call can't open a second approval or count usage twice.
      idempotencyKey: options.idempotencyKey ?? 'gk_' + this._generateId().slice(4),
    });
    if (!r.ok) {
      this.onError(new Error(`Auditail policy check failed: ${r.error}`));
      return unavailable(r.status === 401 ? 'invalid API key' : 'Auditail could not be reached');
    }
    const p = r.value;
    const base = { decidedBy: 'policy' as const, serverRecorded: true, serverAuditId: p.auditId ?? p.decisionId, limits: p.limits ?? undefined };
    if (p.decision === 'allow') return { ...base, approved: true, code: p.code, reason: p.reason, receipt: p.receipt, matchedRule, ...(p.shadow ? { shadow: p.shadow } : {}) };
    if (p.decision === 'deny') return { ...base, approved: false, code: p.code, reason: p.reason, hint: p.hint ?? undefined, matchedRule: `policy:${p.code}` };

    // require_approval: the server already opened the request
    const a = p.approval!;
    this._log('warn', `Approval REQUIRED by policy (${p.code}): ${p.reason}`);
    try { this.config.onApprovalRequested(a); } catch (e) { this.onError(e instanceof Error ? e : new Error(String(e))); }
    if (options.wait === false) {
      return { ...base, approved: false, pending: true, code: 'approval_pending', reason: `${p.reason} Awaiting a human (${a.id}); not approved yet.`, hint: p.hint ?? undefined, approval: { id: a.id, status: 'pending' }, matchedRule: `policy:${p.code}` };
    }
    const final = await this.waitForApproval(a.id);
    return { ...this._finalFromApproval(final, `policy:${p.code}`, p.reason), serverAuditId: base.serverAuditId, limits: base.limits };
  }

  private _finalFromApproval(final: GuardApproval, matchedRule: string, why: string): Decision {
    const by = final.decidedBy ? ` by ${final.decidedBy}` : '';
    const note = final.comment ? `: ${final.comment}` : '';
    const common = { decidedBy: 'human' as const, serverRecorded: true, approval: final, matchedRule };
    switch (final.status) {
      case 'approved': return { ...common, approved: true, code: 'approved_by_human', reason: `Approved${by}${note}`, receipt: final.receipt };
      case 'denied': return { ...common, approved: false, code: 'approval_denied', reason: `Denied${by}${note}`, hint: 'A human rejected this action. Do not retry it unchanged; ask the user how to proceed.' };
      case 'expired': return { ...common, approved: false, code: 'approval_expired', reason: 'Approval expired without a decision; action denied.', hint: 'Nobody responded in time. Ask the user to get it approved, then retry.' };
      default: return { ...common, decidedBy: 'policy', serverRecorded: false, approved: false, code: 'approval_unavailable', reason: `${why} The decision could not be confirmed; action denied.`, hint: 'Retry later.' };
    }
  }

  // ---------------------------------------------------------------------------
  // Human approval
  // ---------------------------------------------------------------------------

  /**
   * Wait for a pending approval (created by a `require_approval` rule with `wait: false`) to be decided.
   * Resolves with the final status. Never throws. If Auditail cannot be reached until the deadline the status is
   * 'unavailable', which you must treat as denied.
   */
  async waitForApproval(approvalId: string, opts: { timeoutMs?: number } = {}): Promise<GuardApproval> {
    const started = Date.now();
    let deadline = opts.timeoutMs !== undefined ? started + opts.timeoutMs : Number.POSITIVE_INFINITY;
    for (let i = 0; ; i++) {
      const r = await this._api<Approval>('GET', `/v1/approvals/${encodeURIComponent(approvalId)}`);
      if (r.ok) {
        const a = r.value;
        if (a.status !== 'pending') return { id: a.id, status: a.status, decidedBy: a.decidedBy ?? undefined, comment: a.comment ?? undefined, ...(a.receipt ? { receipt: a.receipt } : {}) };
        // the server expires it at expiresAt; allow a short grace period for the final answer to be readable
        deadline = Math.min(deadline, Date.parse(a.expiresAt) + 15_000);
      } else if (r.status === 401 || r.status === 403 || r.status === 404) {
        this.onError(new Error(`Auditail could not read approval ${approvalId}: ${r.error}`));
        return { id: approvalId, status: 'unavailable' };
      }
      if (Date.now() >= deadline) return { id: approvalId, status: 'unavailable' };
      const base = Date.now() - started < 60_000 ? 2000 : 5000;
      await sleep(base * (0.8 + Math.random() * 0.4));
    }
  }

  /**
   * A signed checkpoint of your audit log's current state. Store it anywhere you control (a ticket, a git
   * commit, your own database): if the log is ever rewritten, `auditail-verify --checkpoint` will show it.
   * Returns null if the log is empty or Auditail cannot be reached.
   */
  async checkpoint(): Promise<string | null> {
    const r = await this._api<{ checkpoint: string }>('GET', '/v1/checkpoint');
    return r.ok ? r.value.checkpoint : null;
  }

  private async _activeFreeze(agentId: string, action: string) {
    const every = this.config.freezeCheckIntervalMs;
    if (every > 0 && this.config.ship && Date.now() - this.freezeCheckedAt > every) {
      // Refresh in the background; the first check waits up to 1.5s so a fresh process honors an existing freeze.
      const first = this.freezeCheckedAt === 0;
      this.freezeInflight ??= this._api<{ active: { scope: 'all' | 'agent' | 'action'; target: string | null; reason: string; createdBy: string; createdAt: string }[] }>('GET', '/v1/freeze')
        .then((r) => { if (r.ok) { this.freezes = r.value.active; this.freezeCheckedAt = Date.now(); } })
        .finally(() => { this.freezeInflight = null; });
      if (first) await Promise.race([this.freezeInflight, sleep(1500)]);
    }
    return this.freezes.find((f) => f.scope === 'all' || (f.scope === 'agent' && f.target === agentId) || (f.scope === 'action' && f.target === action)) ?? null;
  }

  private async _approvalFlow(options: GuardOptions, rule: GuardrailRule): Promise<Decision> {
    const denied = (why: string, id = ''): Decision => ({
      approved: false, code: 'approval_unavailable', decidedBy: 'rule', matchedRule: rule.name,
      reason: `Approval required by "${rule.name}" but ${why}; action denied.`,
      hint: 'Retry later. Actions that need approval never proceed without one.',
      approval: { id, status: 'unavailable' },
    });
    if (!this.config.ship) return denied('approvals need a connection to Auditail (shipping is disabled)');

    const created = await this._api<Approval>('POST', '/v1/approvals', {
      agentId: options.agentId,
      action: options.action,
      ruleName: rule.name,
      reason: rule.description,
      payload: redact(options.payload, this.redactSet),
      userId: options.userId,
      tags: options.tags,
      environment: this.config.environment,
      timeoutSeconds: rule.approvalTimeoutSeconds ?? this.config.approvalTimeoutSeconds,
      receiptTtlSeconds: rule.receiptTtlSeconds,
      intent: options.intent,
      userRequest: options.userRequest,
      source: options.source,
      correlationId: options.correlationId,
      callbackUrl: options.callbackUrl,
      // Network retries inside this call return the same approval instead of opening a second one.
      idempotencyKey: options.idempotencyKey ?? 'gk_' + this._generateId().slice(4),
    });
    if (!created.ok) {
      if (created.status === 423) {
        let reason = 'Agents are frozen.';
        try { reason = (JSON.parse(created.error.replace(/^HTTP \d+ /, '')) as { error: { message: string } }).error.message; } catch { /* keep default */ }
        return { approved: false, code: 'frozen', decidedBy: 'policy', matchedRule: 'kill-switch', reason,
          hint: 'Stop and tell the user. An approver must lift the freeze before this can run; retrying will not help.' };
      }
      this.onError(new Error(`Auditail could not create the approval request: ${created.error}`));
      return denied('Auditail could not be reached');
    }
    const a = created.value;
    this._log('info', `Approval ${a.id} requested; waiting for a human (expires ${a.expiresAt})`);
    try { this.config.onApprovalRequested(a); } catch (e) { this.onError(e instanceof Error ? e : new Error(String(e))); }

    if (options.wait === false) {
      return { approved: false, pending: true, code: 'approval_pending', decidedBy: 'rule', serverRecorded: true, matchedRule: rule.name,
        reason: `Awaiting human approval (${a.id}); not approved yet.`, approval: { id: a.id, status: 'pending' } };
    }
    const final = await this.waitForApproval(a.id);
    const out = this._finalFromApproval(final, rule.name, `Approval required by "${rule.name}".`);
    return final.status === 'unavailable' ? denied('the decision could not be confirmed', a.id) : out;
  }

  /**
   * Dry run: what would the policy decide for this action right now? Nothing is recorded, reserved or sent for approval.
   * Use it to plan multi-step work within bounds. It's a prediction, not a reservation: guard() still decides.
   */
  async simulate(options: GuardOptions): Promise<SimulateResult> {
    // A separate path, so a server without dry runs answers 404 instead of making a real decision.
    const r = await this._api<SimulateResult>('POST', '/v1/decide/dry-run', {
      action: options.action, agentId: options.agentId, payload: redact(options.payload, this.redactSet), userId: options.userId,
      environment: this.config.environment, source: options.source, fieldSources: options.fieldSources, sessionId: options.sessionId, dryRun: true,
    });
    if (!r.ok) return { dryRun: true, decision: 'unavailable', code: 'policy_unavailable', reason: `Auditail could not be reached: ${r.error}` };
    return r.value;
  }

  /**
   * What may this agent do, and how much budget is left? Read-only: allowed actions, approval thresholds, first-time rules,
   * and remaining limits (pass `action` and `payload` to see per-beneficiary or per-currency budgets). Policy can disable it.
   */
  async getCapabilities(opts: { agentId?: string; action?: string; payload?: Record<string, unknown>; sessionId?: string } = {}): Promise<Record<string, unknown>> {
    const r = await this._api<Record<string, unknown>>('POST', '/v1/capabilities', opts);
    if (!r.ok) throw new Error(`Auditail capabilities unavailable: ${r.error}`);
    return r.value;
  }

  /**
   * Mark a session as having read untrusted content (an inbound email, a web page, an uploaded PDF). From then on,
   * money-moving actions in this session need a human (per policy), until it expires (24 h) or an approver clears it.
   */
  async markUntrusted(sessionId: string, source: string, note?: string): Promise<{ tainted: boolean; since?: string; expiresAt?: string }> {
    const r = await this._api<{ tainted: boolean; since?: string; expiresAt?: string }>('POST', `/v1/sessions/${encodeURIComponent(sessionId)}/taint`, { source, note });
    if (!r.ok) throw new Error(`Auditail could not record the taint: ${r.error}`);
    return r.value;
  }

  /**
   * Pause/resume: check an approval once, without waiting. Call it when your workflow wakes up (callback, signal or event).
   * When approved, the result carries the signed receipt to execute with.
   */
  async resume(approvalId: string): Promise<ResumeResult> {
    const r = await this._api<GuardApproval & { correlationId?: string | null }>('GET', `/v1/approvals/${encodeURIComponent(approvalId)}`);
    if (!r.ok) return { status: 'unavailable', approved: false, pending: false, code: 'approval_unavailable', reason: `Could not read the approval: ${r.error}` };
    const a = r.value;
    if (a.status === 'pending') return { status: 'pending', approved: false, pending: true, code: 'approval_pending', reason: 'Still waiting for a human.', approval: a };
    const d = this._finalFromApproval(a, 'approval', '');
    return { status: a.status, approved: d.approved, pending: false, code: d.code ?? a.status, reason: d.reason ?? '', receipt: a.receipt, approval: a };
  }

  /**
   * Record what happened after authorization: 'settled', 'failed', 'reversed', 'refunded' or 'voided', linked to the decision
   * (auditId or receipt). Use `compensates` to link a refund or reversal decision to the original. Reports made with an approver
   * token are trusted: 'failed' and 'voided' give the budget back. Agent reports are recorded only.
   */
  async reportOutcome(target: { auditId?: string; receipt?: string }, outcome: { status: OutcomeStatus; externalTxId?: string; amount?: number; currency?: string; reason?: string; compensates?: string }):
    Promise<{ id: string; trusted: boolean; releasedUsage: boolean; duplicate?: boolean }> {
    const r = await this._api<{ id: string; trusted: boolean; releasedUsage: boolean; duplicate?: boolean }>('POST', '/v1/outcomes', { ...target, ...outcome });
    if (!r.ok) throw new Error(`Auditail could not record the outcome: ${r.error}`);
    return r.value;
  }

  /**
   * One call for the service that executes an action: verifies the receipt (account, action, exact payload, expiry,
   * signature) and redeems it so it can't be used twice. Returns { ok: true } only when it's safe to execute.
   *
   *   const check = await auditail.checkReceipt(req.headers['x-auditail-receipt'], { action: 'create_payout', payload });
   *   if (!check.ok) return res.status(403).json({ error: check.reason });
   */
  async checkReceipt(receipt: string | null | undefined, opts: CheckReceiptOptions): Promise<CheckReceiptResult> {
    if (!receipt) return { ok: false, code: 'missing_receipt', reason: 'No Auditail receipt was provided.' };
    let account = opts.account ?? this.accountId;
    if (!account) {
      const me = await this._api<{ keyId: string }>('GET', '/v1/me');
      if (!me.ok) return { ok: false, code: 'unavailable', reason: `Could not reach Auditail to identify the account: ${me.error}` };
      account = this.accountId = me.value.keyId;
    }
    const v = await verifyReceipt(receipt, {
      account, action: opts.action, payload: opts.payload, agentId: opts.agentId, environment: opts.environment,
      redactKeys: opts.redactKeys ?? this.config.redactKeys, publicKeys: opts.publicKeys,
      keysUrl: opts.keysUrl ?? `${this.config.baseUrl}/.well-known/auditail-keys.json`, requireHumanApproval: opts.requireHumanApproval,
    });
    if (!v.valid) return { ok: false, code: 'invalid_receipt', reason: v.reason ?? 'invalid receipt' };
    const r = await this.redeemReceipt(receipt, { action: opts.action, requestId: opts.requestId });
    if (!r.redeemed) return { ok: false, code: r.code, reason: r.message };
    return { ok: true, claims: v.claims!, redeemedAt: r.redeemedAt };
  }

  /**
   * Marks a receipt as used, so the action it approves runs at most once. Call it in the service that executes the
   * action, after verifyReceipt() has checked the payload. Retries reuse the same request id, so they are safe.
   *
   *   const r = await auditail.redeemReceipt(receipt, { action: 'create_payout' });
   *   if (!r.redeemed) throw new Error(`Refusing payout: ${r.message}`);
   */
  async redeemReceipt(receipt: string, opts: { action?: string; requestId?: string } = {}): Promise<RedeemResult> {
    const requestId = opts.requestId ?? 'rdm_' + this._generateId().slice(4);
    const r = await this._api<{ redeemed: true; receiptId: string; action: string; agentId: string; approvedBy: string | null; redeemedAt: string }>(
      'POST', '/v1/receipts/redeem', { receipt, action: opts.action, requestId });
    if (r.ok) return { ...r.value, redeemed: true };
    let code = 'unavailable', message = r.error;
    try { const j = JSON.parse(r.error.replace(/^HTTP \d+ /, '')) as { error?: { code?: string; message?: string } }; code = j.error?.code ?? code; message = j.error?.message ?? message; } catch { /* network error */ }
    return { redeemed: false, code, message };
  }

  private async _api<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<
    { ok: true; value: T } | { ok: false; status: number; error: string }
  > {
    let lastError = 'network error';
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(`${this.config.baseUrl}${path}`, {
          method,
          headers: {
            ...(body ? { 'content-type': 'application/json' } : {}),
            authorization: `Bearer ${this.config.apiKey}`,
            'user-agent': `auditail-js/${SDK_VERSION}`,
          },
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(10_000),
        });
        if (res.ok) return { ok: true, value: (await res.json()) as T };
        const detail = await res.text().catch(() => '');
        if (res.status < 500 && res.status !== 429) return { ok: false, status: res.status, error: `HTTP ${res.status} ${detail.slice(0, 1000)}` };
        lastError = `HTTP ${res.status}`;
      } catch (e) {
        lastError = String((e as Error)?.message ?? e);
      }
      if (attempt < 3) await sleep(Math.random() * 400 * attempt);
    }
    return { ok: false, status: 0, error: lastError };
  }

  /**
   * Returns all audit events recorded in this session.
   * For the persistent, tamper-evident log across processes, use the dashboard at https://app.auditail.io.
   */
  getAuditLog(): AuditEvent[] {
    return [...this.auditLog];
  }

  /**
   * Pre-built guardrail rules for common AI agent security scenarios.
   */
  static rules = {
    /**
     * Block emails to external domains.
     * Pass internalDomains to configure which domains are allowed.
     * @example Auditail.rules.noExternalEmail({ internalDomains: ['acme.com'] })
     */
    noExternalEmail(opts?: { internalDomains?: string[] }): GuardrailRule {
      const domains = opts?.internalDomains ?? [];
      return {
        name: 'no-external-email',
        description: 'Blocked: sending email to an external domain is not permitted.',
        condition: (options) => {
          if (domains.length === 0) return false; // not configured, skip
          const to = options.payload?.to as string | undefined;
          if (!to) return false;
          return !domains.some((d) => to.endsWith(`@${d}`));
        },
        action: 'block',
      };
    },

    /**
     * Block destructive SQL operations (DELETE, DROP TABLE, TRUNCATE).
     */
    noDataDeletion(): GuardrailRule {
      return {
        name: 'no-data-deletion',
        description: 'Blocked: destructive data operations (DELETE, DROP, TRUNCATE) are not permitted.',
        condition: (opts) => {
          const query = (opts.payload?.query as string | undefined)?.toUpperCase() ?? '';
          return ['DELETE', 'DROP TABLE', 'TRUNCATE'].some((kw) => query.includes(kw));
        },
        action: 'block',
      };
    },

    /**
     * Alert when the agent makes an outbound HTTP request.
     */
    noExternalApiCalls(): GuardrailRule {
      return {
        name: 'no-external-api-calls',
        description: 'Alert: agent is making a call to an external API.',
        condition: (opts) => opts.action === 'http_request',
        action: 'alert',
      };
    },
  };

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private _generateId(): string {
    if (typeof crypto !== 'undefined' && crypto.randomUUID) {
      return `aeg_${crypto.randomUUID().replace(/-/g, '').slice(0, 16)}`;
    }
    // Fallback for older environments
    return `aeg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
  }

  private _log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void {
    const levels = ['debug', 'info', 'warn', 'error', 'silent'];
    const configured = levels.indexOf(this.config.logLevel);
    const current = levels.indexOf(level);
    if (current < configured) return;

    const prefix = '[Auditail]';
    if (level === 'warn') console.warn(`${prefix} ⚠️  ${message}`);
    else if (level === 'error') console.error(`${prefix} ❌  ${message}`);
    else console.log(`${prefix} ${message}`);
  }

  private _shipToApi(event: AuditEvent): void {
    if (!this.config.ship) return;
    if (this.queue.length >= MAX_QUEUE) {
      this.queue.shift();
      this.onError(new Error(`Auditail queue full (${MAX_QUEUE}); dropped oldest event`));
    }
    this.queue.push(event);
    if (this.queue.length >= MAX_BATCH) void this.flush();
    else this._schedule();
  }

  private _schedule(): void {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, this.config.flushIntervalMs);
    // Never keep the host process alive just to flush; call flush()/shutdown() before exit.
    (this.timer as { unref?: () => void }).unref?.();
  }

  /**
   * Deliver all queued events now. Resolves when the queue is empty or delivery has failed.
   * Never rejects. Call (and await) this before a serverless function returns or the process exits.
   */
  async flush(): Promise<void> {
    if (this.inflight) await this.inflight;
    if (this.queue.length === 0) return;
    this.inflight = this._drain().finally(() => { this.inflight = null; });
    await this.inflight;
  }

  /** Flush and stop background timers. */
  async shutdown(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    await this.flush();
  }

  private async _drain(): Promise<void> {
    while (this.queue.length > 0) {
      const batch = this.queue.slice(0, MAX_BATCH);
      const delivered = await this._deliver(batch);
      if (!delivered) return; // keep remaining events queued; next flush retries
      const done = new Set(batch); // remove by identity: the queue may have shifted (overflow) mid-flight
      this.queue = this.queue.filter((e) => !done.has(e));
    }
  }

  private async _deliver(batch: AuditEvent[]): Promise<boolean> {
    for (let attempt = 1; attempt <= MAX_DELIVERY_ATTEMPTS; attempt++) {
      try {
        const res = await fetch(`${this.config.baseUrl}/v1/events`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${this.config.apiKey}`,
            'user-agent': `auditail-js/${SDK_VERSION}`,
          },
          body: JSON.stringify({ events: batch }),
        });
        if (res.ok) return true;
        if (res.status >= 400 && res.status < 500 && res.status !== 429) {
          // Permanent failure (bad key, invalid event): retrying cannot help. Drop and report.
          const detail = await res.text().catch(() => '');
          this.onError(new Error(`Auditail rejected ${batch.length} event(s): HTTP ${res.status} ${detail.slice(0, 200)}`));
          return true;
        }
      } catch {
        // network error: fall through to retry
      }
      if (attempt < MAX_DELIVERY_ATTEMPTS) await sleep(Math.random() * Math.min(250 * 2 ** attempt, 4000));
    }
    this.onError(new Error(`Auditail could not deliver ${batch.length} event(s); will retry on next flush`));
    return false;
  }
}

export default Auditail;
