# Roadmap and commercial validation

## Community MVP

Implemented: single-domain public configuration checks, Italian/English UI, local history and comparison, honest unknown/error handling, HTML/JSON evidence reports, CLI, security boundaries and offline automated tests. The code is prepared for GitHub; publishing remains a separate founder decision.

## Validation before adding SaaS

1. Select three to five SMEs or IT providers with written authorization for their domains. Run the MVP with them, observe whether they understand warnings and can identify the first action.
2. Have a mail/hosting administrator review a sample of findings for technical accuracy and false positives. Record unknown-check rates and reasons on authorized targets.
3. Measure time to first actionable finding, report comprehension, remediation completed after seven days, and willingness to pay for recurring review or assistance. Do not substitute a high health score for customer outcomes.
4. Offer a founder-delivered assessment/remediation walkthrough before building payment infrastructure. Ask which repeated task would justify a monthly fee and at what budget.
5. Prioritize only the most requested repeat workflow. Monitoring and report branding are hypotheses, not validated demand.

## Deferred improvements

- Full sender-context SPF evaluation, advanced syntax/macros and complete lookup/void/fan-out semantics.
- Broader DMARC discovery semantics and external report authorization checks.
- DKIM cryptographic key validation and authorized message-level signing/alignment verification.
- Effective CAA inheritance, DNSSEC validation and revocation/CT checks.
- Optional carefully bounded GET/header behavior comparison, additional paths or multiple IP samples.
- Native branded PDF generation; current HTML works with browser print-to-PDF.
- Retention management, encrypted storage and schema migrations when contracts evolve.

## Potential Pro/service modules

Multi-domain monitoring, scheduled reassessments, alerts, historical trends, report branding, MSP workflows, organizations, team accounts and commercial support. Keep the working community engine complete. Add separate service adapters only when a validated need appears.

## Required before hosted multi-user deployment

Ownership challenges, authentication, tenant isolation, encrypted secrets, per-user and per-target rate limits, isolated egress, job execution quotas, safe cancellation, retention policy, privacy review, security testing and monitoring. Payments and commercial licensing should follow actual demand and explicit founder approval. Do not publish this localhost application directly as a public scanner.
