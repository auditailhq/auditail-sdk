// Guarded tools for the Vercel AI SDK: every money-moving tool asks Auditail first, and the model is told why when
// the answer is no, so it can explain or ask the user instead of retrying.
//
//   AUDITAIL_API_KEY=atl_live_... OPENAI_API_KEY=sk-... node agent.mjs "Refund order 4471 ($48) and order 9120 ($640)"
//   AUDITAIL_API_KEY=atl_live_... node agent.mjs        (no OPENAI_API_KEY: a scripted mock model makes the same calls)
import { generateText, tool, stepCountIs } from 'ai';
import { z } from 'zod';
import { Auditail } from 'auditail-sdk';

const auditail = new Auditail({ apiKey: process.env.AUDITAIL_API_KEY, serverPolicy: true, logLevel: 'silent',
  ...(process.env.AUDITAIL_BASE_URL ? { baseUrl: process.env.AUDITAIL_BASE_URL } : {}) });
const sessionId = `chat-${Date.now()}`;

/** Wraps a tool's execute: Auditail decides, the receipt goes to your payment client, the model gets the reason. */
function guarded(action, execute) {
  return async (input) => {
    const r = await auditail.guard({ action, payload: input, agentId: 'support-agent', sessionId, wait: false });
    if (r.approved) return execute(input, r.receipt);
    if (r.pending) return { status: 'waiting_for_approval', approvalId: r.approval.id, message: `Not done yet: a person must approve this (${r.reason}). Tell the user.` };
    return { status: 'not_allowed', code: r.code, message: `${r.reason}${r.hint ? ` ${r.hint}` : ''} Do not retry; tell the user.` };
  };
}

const tools = {
  issue_refund: tool({
    description: 'Refund a customer for an order',
    inputSchema: z.object({ orderId: z.string(), amount: z.number(), currency: z.string().default('USD'), customer: z.object({ id: z.string() }) }),
    execute: guarded('issue_refund', async (input, receipt) => {
      // your payment client; the refund service checks the receipt with checkReceipt() before paying
      console.log(`[payments] REFUNDED ${input.amount} ${input.currency} for ${input.orderId} (receipt ${receipt.slice(0, 18)}...)`);
      return { status: 'refunded', refundId: `re_${Date.now()}` };
    }),
  }),
};

async function model() {
  if (process.env.OPENAI_API_KEY) return (await import('@ai-sdk/openai')).openai(process.env.OPENAI_MODEL ?? 'gpt-4.1-mini');
  // No API key: a scripted model that calls the tool twice, then answers. Same tool path as a real model.
  const { MockLanguageModelV4 } = await import('ai/test');
  const usage = { inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 10, text: 10, reasoning: 0 } };
  const call = (id, input) => ({ type: 'tool-call', toolCallId: id, toolName: 'issue_refund', input: JSON.stringify(input) });
  return new MockLanguageModelV4({ doGenerate: [
    { content: [call('c1', { orderId: '4471', amount: 48, currency: 'USD', customer: { id: 'cus_jordan' } }), call('c2', { orderId: '9120', amount: 640, currency: 'USD', customer: { id: 'cus_ali' } })],
      finishReason: { unified: 'tool-calls', raw: 'tool_calls' }, usage, warnings: [] },
    { content: [{ type: 'text', text: 'Order 4471 is refunded. The $640 refund for order 9120 needs a person to approve it first; I will let you know.' }],
      finishReason: { unified: 'stop', raw: 'stop' }, usage, warnings: [] },
  ] });
}

const result = await generateText({
  model: await model(), tools, stopWhen: stepCountIs(4),
  prompt: process.argv[2] ?? 'Refund order 4471 ($48, customer cus_jordan) and order 9120 ($640, customer cus_ali).',
});
for (const step of result.steps) for (const r of step.toolResults) console.log(`tool ${r.toolName}(${JSON.stringify(r.input)}) -> ${JSON.stringify(r.output)}`);
console.log(`\nassistant: ${result.text}`);
