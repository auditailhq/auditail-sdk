/**
 * Auditail SDK — Quick Example
 * Run: npx ts-node src/example.ts
 */

import { Auditail } from './index';

async function main() {
  // 1. Initialize the client
  const auditail = new Auditail({
    apiKey: 'auditail_demo_key_123',
    environment: 'staging',
  });

  // 2. Register guardrail rules
  auditail
    .addRule(Auditail.rules.noExternalEmail({ internalDomains: ["yourdomain.com"] }))
    .addRule(Auditail.rules.noDataDeletion())
    .addRule(Auditail.rules.noExternalApiCalls());

  // 3. Test: approved action (internal email)
  console.log('\n--- Test 1: Internal email (should be APPROVED) ---');
  const result1 = await auditail.guard({
    action: 'send_email',
    payload: { to: 'teammate@yourdomain.com', subject: 'Weekly Report', body: 'See attached.' },
    agentId: 'report-bot-01',
  });
  console.log('Result:', result1);

  // 4. Test: blocked action (external email)
  console.log('\n--- Test 2: External email (should be BLOCKED) ---');
  const result2 = await auditail.guard({
    action: 'send_email',
    payload: { to: 'client@externalco.com', subject: 'Invoice', body: 'Please find your invoice.' },
    agentId: 'billing-bot-01',
    userId: 'user_42',
  });
  console.log('Result:', result2);

  // 5. Test: blocked action (database deletion)
  console.log('\n--- Test 3: DB deletion (should be BLOCKED) ---');
  const result3 = await auditail.guard({
    action: 'execute_query',
    payload: { query: 'DELETE FROM users WHERE last_login < NOW() - INTERVAL 1 YEAR' },
    agentId: 'db-cleanup-bot',
    tags: { team: 'data-engineering' },
  });
  console.log('Result:', result3);

  // 6. Print the full in-memory audit log
  console.log('\n--- Audit Log ---');
  console.log(JSON.stringify(auditail.getAuditLog(), null, 2));
}

main().catch(console.error);
