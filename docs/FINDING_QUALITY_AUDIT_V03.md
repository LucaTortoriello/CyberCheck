# v0.3 finding-quality audit

Audit before implementation, 2026-11-16. Baseline: `origin/main` at
`87a1483` (includes the explicitly authorized HEAD → GET fallback).
Baseline offline suite: **222 passed**. No live target was assessed.

## Principal findings and proposed corrections

1. Missing SPF/DMARC are medium-severity warnings even when mail use is unknown.
   The explanations are partly conditional, but default actions still prescribe
   publication and assume a sender inventory. Keep the observations as warnings,
   use informational severity without context, and condition actions on sending,
   anti-impersonation goals and DNS control.
2. Missing MX/CAA are already informational warnings, but the MX action prescribes
   null MX for every non-receiver. Make null MX an option after checking routing
   and control. Keep exact-name scope, implicit routing and CAA inheritance visible.
3. Findings lack an explicit applicability representation. Use a reserved object
   inside the existing free-form evidence dictionary, plus optional user-declared
   sending/receiving/DNS-control context. Unknown stays unknown; do not infer
   ownership from platform names, suffixes, NS, MX or certificates.
4. HSTS/nosniff passes add to the score while missing headers are excluded warnings:
   this can dilute confirmed failures. Exclude optional headers entirely in new
   assessments. Keep the existing ratio, require applicable findings in the new
   explicitly versioned scoring profile, and preserve historical flags/formulas.
5. Generic TLS/HTTP remediation can advise changes even on passing or inconclusive
   checks. Supply check-specific review/verification actions, preserve the limited
   handshake/response interpretation, and never prescribe protocol enumeration as
   something already performed.
6. The dashboard attention list includes informational warnings. Keep all detail
   and counts, but reserve priority actions for noninformational concerns that
   are not explicitly inapplicable. Show applicability beside each finding.
7. DMARC absence evidence drops the first query when organizational fallback is
   used and can suggest current-standard absence despite legacy discovery. Retain
   both queries and label the discovery boundary. Modern np/psd/t markers must
   remain inconclusive even when legacy-only validation would reject pct.

## Complete finding inventory at baseline

P/W/F/U/E/NA = Passed/Warning/Failed/Unknown/Error/Not applicable.
Severity: I/L/M/H = informational/low/medium/high. Scores below describe the
baseline; W/U/E/NA never enter the denominator. Applicability/actionability are
unknown unless evidence or user context establishes them. A provider may need to
perform changes; publication/access does not prove user control.

| Identifier | Baseline status/severity and trigger | Assumptions, false positives / false negatives, risk wording | Applicability and realistic action | Baseline score → proposal |
|---|---|---|---|---|
| `dns.records` | P/I completed A/AAAA/NS/MX/CAA inventory; U/I lookup failure/NXDOMAIN | P means inventory completed, not all records required. Missing NS at a child name and absent AAAA are normal; no delegation/DNSSEC/IPv6 reachability validation. | Inventory applies; review relevant records with administrator, never create NS/AAAA just to clear a result. | No → unchanged |
| `dns.mx` | P/I MX or null MX; W/I absent; F/M null MX plus another MX; U/I DNS failure | Missing MX need not break mail: implicit A/AAAA may apply. MX presence does not prove delivery; null MX concerns receiving, not sending. | Receiving context is optional; malformed published routing remains observed. Review inbound requirements and DNS authority before changes. | Conflict only → gate by applicability in new profile |
| `dns.caa` | P/I exact-name record; W/I absence; U/I lookup failure | Effective policy may come from parent/CNAME; present syntax/issuer policy not validated. No inferred vulnerability or missing effective policy. | Optional issuance restriction; review hierarchy and renewal with DNS/certificate operator. Unknown relevance is valid. | No → unchanged |
| `email.spf` | W/M absence; F/M multiple/syntax; F/H `+all`; W/L neutral; U/I macros/error; P/I supported syntax | Sending usage and sender identities unknown. No SPF inheritance. DNS syntax is not real-message authentication; limited grammar/macros and sender paths can miss errors. `+all` is permissive, not proof of exploitation. | Sending context changes operational relevance; non-senders may still benefit from anti-spoofing policies. Never blindly publish `-all` or flatten. | Multiple records only → retain candidate, gate applicability |
| `email.spf_lookups` | W/L >10 static terms; U/I incomplete dependencies/macros/cycle; P/I estimate within bound | Static traversal is not runtime permerror: short circuiting, void lookups, MX/PTR fan-out untested. | Relevant to sending; ask mail administrator to test representative sender paths. | No → unchanged |
| `email.dmarc` | W/M absence; F/M legacy syntax; W/L monitoring/partial; U/I modern tags/error; P/I requested enforcement | Legacy exact/organizational lookup can miss modern DNS tree-walk policy; enforcement request does not prove alignment or receiver compliance. Monitoring may be deliberate. Modern tags checked too late after legacy validation. | Conditional on mail/anti-impersonation goals and DNS control. Preserve inherited sp and avoid duplicate child policies. | Syntax failure only → gate applicability; modern markers stay U |
| `email.dmarc_reporting` | P/I supported mailto rua; W/I absent/unsupported | Presence does not verify ownership, delivery, external permission or privacy suitability; absence is not authentication failure. | Optional monitoring; use only if useful and permitted, review privacy. | No → unchanged |
| `email.dkim[:selector]` | U/I no selector/key/error; F/M malformed tags/key encoding; W/M revoked; P/I base64 key | No-selector does not mean disabled. Other selectors may work; RSA structure, signing, rotation and alignment untested. Revocation may be intended. | Sending context; obtain exact selector and authorized message evidence, no guessing. No need to rotate an intentionally retired key merely for a warning. | No → unchanged |
| `tls.connection` | P/I verified handshake; U/I any failure | One endpoint/time/trust store; no full application availability or complete TLS audit. | Applies to tested HTTPS endpoint; investigate inconclusive failures with operator. | No → unchanged |
| `tls.chain` | P/I local trust accepted; F/H proven chain verification failure; U/I other failure | Local trust/clock can differ; no revocation/CT. Unknown dimensions are not failed. | Review leaf/intermediates/local trust; never disable verification. | P/F → unchanged, explicit applicability |
| `tls.hostname` | P/I name accepted; F/H proven mismatch; U/I other failure | Limited to requested SNI, selected IP and time; no all-host inventory. | Verify SAN and virtual host with TLS operator. | P/F → unchanged, explicit applicability |
| `tls.validity` | P/I valid ≥30 days; W/L valid <30; F/H verified invalid period; U/I other failure | Short certificate lifetime/automated renewal may be intentional; local clock affects result. | Check renewal before expiry; failed validity is a specific verification result. | P/F, warning excluded → unchanged |
| `tls.protocol` | P/I negotiated 1.2/1.3; U/I other/failed handshake | A modern negotiation does not prove obsolete protocols disabled or cipher security. | Applies only to negotiated protocol; broader support remains untested. | Modern negotiation P → unchanged limited criterion |
| `http.https` | P/I any verified HTTPS HTTP response; U/I failure | 501 still establishes connectivity, not working application. | Review observed connection/method and uncertainty; do not infer absent HTTPS. | No → unchanged |
| `http.application` | P/I final 2xx for stated method; U/I otherwise | HEAD may differ from GET. 2xx not full functional availability; errors not automatically vulnerabilities. | Explicitly authorized GET only after HTTPS HEAD 405/501; no expanded requests. | No → unchanged |
| `http.redirect` | P/I verified HTTPS upgrade; W/L plaintext 2xx; U/I ambiguous/blocked/failure | Port 80 can intentionally be closed; redirects can be path-specific. First request can remain plaintext even with upgrade. | Review canonical routing with web operator; no forced port-80 opening after timeout. | No → unchanged |
| `headers.hsts` | P/I supported positive max-age; W/L missing/disabled/malformed; U/I ineligible response | Optional browser hardening; no preload or all-path validation. Rollout/includeSubDomains can disrupt services. | Browser HTML evidence supports relevance; unknown content stays conditional. Test limited rollout with operator. | P only → no scoring |
| `headers.nosniff` | P/I recognized value; W/L otherwise; U/I ineligible response | MIME correctness still required; no browser execution tested. | Hardening at app/proxy if relevant, test resource loading. | P only → no scoring |
| `headers.referrer` | P/I restrictive recognized last fallback; W/L otherwise; U/I ineligible | Browser defaults may suffice; actual sensitive URL leakage not demonstrated. | Conditional privacy choice; avoid secrets in URLs and test policy. | No → unchanged |
| `headers.csp` | P/I enforcing header present; W/L absent; NA/I non-HTML; U/I unknown type/ineligible | Any header can pass presence criterion without useful protection; meta policies uninspected. No proof of injection. | HTML hardening; inventory resources and test report-only before enforcement. | No → unchanged |
| `headers.permissions` | P/I header present; W/I absent; NA/I non-HTML; U/I unknown type/ineligible | Semantics/defaults/features untested; missing optional header is not evidence of feature abuse. | Relevance unknown without required feature inventory; restrict only unused features after testing. | No → unchanged |
| `headers.framing` | P/I recognized restrictive CSP or XFO; W/L otherwise; NA/I non-HTML; U/I unknown type/ineligible | Limited source grammar can miss valid policies; intended embedding and interactive actions unknown. A wildcard hostname is not necessarily a narrow allowlist. | Conditional on embedding needs/interactive content; do not ban legitimate embedding automatically. | No → unchanged |
| `engine.error[:module]` | E/I unexpected module exception | No conclusion for failed module; other evidence retained. | Resolve local execution issue and retry; not a security finding. | No → unchanged |

## Additional classification correction confirmed during implementation

SPF `+all` is syntactically valid and permissive. Without a declared configuration
requirement, classifying it Failed/High overstates what was proven. New results
use Warning/Medium, retain the exact policy and qualifier evidence, and ask the
operator to confirm intent. Confirmed supported syntax errors still use Failed.
Historical findings retain the original classification.

## Implementation boundaries and compatibility plan

- Keep schema version 1 and the existing statuses. Add only optional keys within
  `metadata` and free-form `evidence`; existing finding fields remain unchanged.
- `evidence.applicability` carries state, basis and bilingual reason. Applicability
  describes contextual relevance, independently of a measured criterion's status.
  Explicit non-sending does not prove absence of spoofing risk. Raw evidence and
  malformed published-policy results remain available even if operationally NA.
- New run metadata identifies user declarations as unverified and selects a new
  scoring profile; old payloads without that profile retain the original ratio,
  flags and eligibility. No migration or automatic rescan/reclassification.
- Preserve GET authorization, SSRF/DNS rebinding, TLS verification, redirects,
  budgets, timeouts and evidence redaction. Do not modify network transports.
- Deterministic regressions cover the 16 requested scenarios, both languages,
  context-independent raw evidence, report parity and historical SQLite/JSON.

## Reference basis

- [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html): implicit routing and null MX.
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659.html): optional CAA and hierarchy.
- [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html): SPF scope and sending identities.
- [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html): current DMARC discovery boundary.

These references support interpretation limits, not an expansion of implemented
protocol validation. Full current DMARC discovery remains outside this change.
