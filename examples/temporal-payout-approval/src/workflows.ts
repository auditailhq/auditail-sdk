// Deterministic workflow code: no network calls here. Auditail is called from activities.
import { condition, defineSignal, proxyActivities, setHandler, workflowInfo } from '@temporalio/workflow';
import type * as activities from './activities';

const { requestDecision, readDecision, executePayout, reportOutcome } = proxyActivities<typeof activities>({
  startToCloseTimeout: '1 minute',
  retry: { maximumAttempts: 5 },
});

/** Sent by the callback handler when Auditail says a human decided. */
export const approvalDecided = defineSignal<[string]>('approvalDecided');

export interface Payout { amount: number; currency: string; beneficiary: { id: string }; invoice?: string }

export async function payoutWorkflow(payout: Payout): Promise<{ status: string; paymentId?: string; reason?: string }> {
  let decided = false;
  setHandler(approvalDecided, () => { decided = true; });

  const d = await requestDecision(payout, workflowInfo().workflowId);
  let receipt = d.receipt;
  if (!d.approved) {
    if (!d.pending || !d.approvalId) return { status: 'blocked', reason: d.reason ?? undefined };
    // Durable wait: the worker can restart; Temporal keeps the workflow until the signal or the timeout.
    const signalled = await condition(() => decided, '24 hours');
    const final = await readDecision(d.approvalId); // read it from Auditail, don't trust the signal alone
    if (!final.approved) return { status: signalled ? 'not_approved' : 'timed_out', reason: final.reason ?? undefined };
    receipt = final.receipt;
  }
  const paid = await executePayout(payout, receipt!);
  await reportOutcome(receipt!, paid.paymentId);
  return { status: 'paid', paymentId: paid.paymentId };
}
