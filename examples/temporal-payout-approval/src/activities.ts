import { Context } from '@temporalio/activity';
import { Auditail } from 'auditail-sdk';
import type { Payout } from './workflows';

const auditail = new Auditail({
  apiKey: process.env.AUDITAIL_API_KEY!, serverPolicy: true, logLevel: 'warn',
  ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}),
});
const CALLBACK_URL = `${process.env.PUBLIC_URL ?? 'http://localhost:3000'}/auditail/callback`;

export async function requestDecision(payout: Payout, workflowId: string) {
  const info = Context.current().info;
  const r = await auditail.guard({
    action: 'create_payout', payload: payout as unknown as Record<string, unknown>, agentId: 'payout-agent', wait: false,
    correlationId: workflowId, callbackUrl: CALLBACK_URL,
    // The same across Temporal's activity retries: a retry gets the original decision, not a second approval.
    idempotencyKey: `${workflowId}-${info.activityId}`,
  });
  return { approved: r.approved, pending: r.pending, approvalId: r.approval?.id ?? null, receipt: r.receipt ?? null, reason: r.reason ?? null };
}

export async function readDecision(approvalId: string) {
  const r = await auditail.resume(approvalId);
  if (r.status === 'unavailable') throw new Error(r.reason); // let Temporal retry
  return { approved: r.approved, receipt: r.receipt ?? null, reason: r.reason };
}

/** Your payment client. Pass the receipt so the payout service can check it (checkReceipt) before paying. */
export async function executePayout(payout: Payout, receipt: string) {
  console.log(`[payouts] PAID ${payout.amount} ${payout.currency} to ${payout.beneficiary.id} (receipt ${receipt.slice(0, 18)}...)`);
  return { paymentId: `po_${Date.now()}` };
}

export async function reportOutcome(receipt: string, paymentId: string) {
  // From an agent key this is recorded only; provider events or an approver token make it trusted (see the docs).
  await auditail.reportOutcome({ receipt }, { status: 'settled', externalTxId: paymentId });
}
