# Roadmap and commercial readiness

## v0.2: reliability review of the community MVP

The single-domain engine, Streamlit UI, SQLite history, CLI and renderer remain in place. v0.2 adds security regressions/corrections, evidence minimization, parser fixes, stable comparisons, save-retry/recovery UX, explicit inconclusive report sections, clean installation and an advisory gate. See `TECHNICAL_AUDIT_V02.md` and `VALIDATION.md` for executed work.

The repository is public at [LucaTortoriello/CyberCheck](https://github.com/LucaTortoriello/CyberCheck). Review branches/draft PRs do not approve a release, deployment or paid service.

## Commercial readiness assessment

Suitable for developer-controlled local evaluation and interviews about the report workflow. It is not yet a validated managed security product: no owned/authorized domain is available, so independent live comparisons and administrator review remain pending. Full current RFC 9989 support is a priority gap; v0.2's legacy profile is explicitly scoped. The optional health score must accompany coverage and actual findings.

Before a paid pilot, independently verify an authorized domain and have its mail/hosting administrator review remediation relevance. Hosted multi-user deployment has further unsatisfied gates. Neither willingness to pay nor market demand follows from completion of code.

## Reusable commercial architecture

| Capability | Reusable components | Additional work / boundary |
|---|---|---|
| Scheduled monitoring | Engine, budgets, SQLite | Separate scheduler adapter, per-domain authorization, overlap prevention, global quotas, retention/cancellation. |
| Certificate alerts | TLS validity evidence and statuses | Renewal-aware thresholds, alert state/deduplication and recovery; Unknown must not become a false expiry incident. |
| Configuration changes | Stable IDs and normalized comparison | Distinguish configuration, coverage and methodology changes; administrator review before risk labels. |
| Multiple domains | Domain-indexed storage, single-domain engine | Thin authorized inventory and bounded queue; multiple rows are not tenant isolation. |
| Branded reports | Escaped HTML and bilingual text | Safe branding inputs, permission for customer details and print acceptance checks; preserve evidence/disclaimers. |
| MSP workflows | Core/report pipeline and history | Organizations, access control, isolation and support only after demand; do not expose this localhost UI publicly. |

Keep orchestration/notifications outside check interpretation. Do not add a generic plugin system, billing, tenants or cloud authentication until a concrete need is validated. AGPL obligations depend on the actual integration; see `LICENSING.md` rather than assuming proprietary modules are automatically permitted.

## Proposed v0.3: staged work for a solo developer

1. **Standards and live correctness first.** Migrate and test bounded RFC 9989 discovery/interpretation, historic pct, np/psd/t and legacy-receiver differences. Obtain an authorized domain, follow `REAL_WORLD_VALIDATION.md` and review false positives before automation.
2. **Validate the report workflow.** Interview three to five authorized SMEs/IT providers. Measure time to useful action, understanding of warnings/unknowns, corrections after a week and stated budget for recurring help. Offer founder-led walkthroughs before payments.
3. **Only if requested: bounded local monitoring.** Begin with a few authorized domains, no overlapping runs, certificate alerts and stable change summaries. Keep notification credentials local/excluded from reports. Define global quotas and deduplication first.
4. **Branding/support before large SaaS.** Add customer report branding and operational support if pilots request them. Determine whether customers need hosting or an MSP-operated local tool.

These are ordered decision gates, not simultaneous commitments or fixed-date estimates. Keep the community core complete. Docker is deferred: the clean-venv route is verified; Desktop adds a VM, networking/trust-store differences and another support surface.

## Later technical candidates

Full SPF sender/macros/void/MX-PTR evaluation; cryptographic DKIM/message alignment; inherited CAA, DNSSEC and revocation/CT; carefully bounded GET/multi-endpoint comparisons; retention/encryption and explicit migrations. Browser print-to-PDF remains sufficient without a validated native-rendering need.

## Required before hosted multi-user deployment

Ownership challenges, authentication, tenant isolation, secrets handling, global/per-user/per-target quotas, isolated egress, cancellation, retention/privacy review, security testing and monitoring. Local test success does not satisfy those gates. Deployments, paid services, licensing changes and releases require explicit approval; do not merge into main automatically.
