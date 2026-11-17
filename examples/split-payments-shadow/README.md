# Split payments, found in shadow mode

An AP agent pays a $14,700 invoice as three payouts of $4,900, $4,850 and $4,950, just under the $5,000 approval
threshold, to a vendor it has never paid. Each payment passes a per-payment rule. Together they're the classic
split ("structuring") pattern a risk team looks for first.

This example runs the policy in **shadow mode**: nothing is blocked, everything is recorded, and the shadow drift
report shows what enforcing it would have caught.

```bash
npm install
AUDITAIL_API_KEY=atl_live_... AUDITAIL_APPROVER_TOKEN=atl_appr_... npm start
```

Use a test account: the script replaces the account's policy with [`policy.json`](./policy.json).

```
payout  1200 USD to ben_acme           allowed  routine
payout  3400 USD to ben_northwind      allowed  routine
payout  4900 USD to ben_new_vendor_77  allowed  (enforced, this would be: require_approval, first_time)  invoice INV-8812, part 1
payout  4850 USD to ben_new_vendor_77  allowed  invoice INV-8812, part 2
payout  4950 USD to ben_new_vendor_77  allowed  invoice INV-8812, part 3

Shadow drift report:
  - 1 possible split payment pattern(s): several payments just under an approval threshold to the same recipient within 24 hours.
  * 3 x create_payout to beneficiary.id=ben_new_vendor_77: 14700 total, threshold 5000

Wrote risk-pack.html. Open it and print to PDF; check it with: npx -p auditail-sdk auditail-verify risk-pack.html
```

## What it shows

- **Per-payment rules miss splits.** Only the first payment trips anything (`first_time`: a new vendor). After that the vendor is known, and each payment is under $5,000.
- **The shadow drift report finds the pattern:** 2 or more payments of the same action to the same recipient within 24 hours, each between 70% and 100% of an approval threshold, together above it.
- **The fix, once you enforce:** a limit per recipient, for example `{ "name": "per-vendor-daily", "window": "24h", "sum": "amount", "max": 5000, "groupBy": "beneficiary.id", "onExceed": "require_approval" }`. Then the second payment to the same vendor in a day goes to a human, however it's split.
- **The hand-off:** `risk-pack.html` is what you send to risk, finance or your sponsor bank. The signed reports are inside it, so they can check it themselves.

More: [shadow drift report](https://auditail.io/docs/guides/kill-switch-and-reports#the-shadow-drift-report), [limits](https://auditail.io/docs/guides/policies#2-limits-over-time).
