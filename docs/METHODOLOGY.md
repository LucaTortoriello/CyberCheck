# Methodology, scoring and known limitations

## Scope

CyberCheck observes publicly resolvable DNS and the root web endpoint of one input hostname. It makes one TLS handshake and bounded HTTP HEAD requests, with explicitly authorized HTTPS GET fallback after HEAD 405/501. These are low-impact active requests, not purely passive intelligence. The app does not verify asset ownership beyond a mandatory user declaration.

## Email and DNS

SPF detects policy absence, multiple records, common definite syntax problems, invalid IP-family/network tokens, supported A/MX dual-CIDR/PTR syntax and a permissive `+all` fallback for otherwise unmatched senders. A syntactically valid `+all` is a medium-severity permissiveness Warning, not a syntax Failed result or proof of exploitation. A valid `~all` can be appropriate during rollout; `-all` is not imposed. Unknown modifiers are ignored, including repeated/empty extensions. DNS-only includes/redirects can use `_spf` labels. Sender-dependent macros remain inconclusive, including macros containing an equals-sign delimiter; no macro-driven target expansion is performed. Common syntax passing is not full SPF validity. A static traversal counts potential include/redirect/a/mx/ptr/exists terms up to bounded depth and flags paths exceeding ten. Short-circuit sender evaluation means this is a warning, not a proven runtime permerror. Void lookup counts, MX/PTR fan-out, sender-IP evaluation and include success semantics are not fully implemented. Dependency failures remain unknown for complexity. SPF findings are excluded from the score except explicitly modeled determinate cases such as multiple policies.

DMARC checks the exact `_dmarc` name, then falls back to the organizational domain for absent exact-name DMARC. The bundled public suffix snapshot avoids runtime list downloads. An inherited `sp` policy is respected. The parser checks required tag ordering, duplicate tags, p/sp, alignment modes and the RFC 7489 pct range. `p=none` is monitoring, not a critical vulnerability. Publication and a mailto reporting destination do not prove alignment, report delivery, external-report authorization or receiver behavior. Only supported tags receive semantic validation. Modern np/psd/t markers take precedence over legacy-profile errors: legacy syntax diagnostics remain evidence, but the policy result is Unknown. Discovery evidence retains the exact-name and organizational queries, including errors, and marks inheritance only when a policy was found. An absent legacy result does not establish absence under current-standard discovery. Public-suffix-domain-specific policies and newer DMARC discovery extensions are not implemented.

**DMARC standards boundary:** RFC 9989, published in May 2026, supersedes RFC 7489. v0.3 preserves the existing **legacy RFC 7489** discovery/validation profile and explicitly labels that scope in finding text/evidence; legacy syntax/percentage results are not a statement of full current-standard conformance. np/psd/t markers leave the primary policy check Unknown and unscored. Current-standard DNS tree walk and testing semantics remain deferred beyond this finding-quality release; modern receivers can ignore historic pct and use different policy discovery. Do not automatically change a valid modern policy solely because of a legacy-profile finding. Validate against the owner's intended receiver behavior. Version-tag whitespace is recognized so an exact policy is not accidentally skipped in favor of an inherited one.

DKIM is unknown without a supplied selector. Only those selectors are queried. An absent key does not establish that all DKIM signing is disabled. A published base64 key is an observation, not cryptographic key validation or verified signature use; RSA structure/bit length, service/granularity restrictions, selector rotation and signing alignment require message-level evidence. Empty p= is a revoked selector, not a domain-wide conclusion.

DNS inventory records A/AAAA, NS, MX and CAA at the input name. NXDOMAIN does not yield a Passed inventory or a security vulnerability: affected checks remain Unknown. A missing exact-name NS can be normal for a non-apex hostname. Missing MX can fall back to implicit A/AAAA routing; null MX declares no inbound mail and must not coexist with other MX. CAA absence is informational and parent/CNAME inheritance and issuance authorization are not evaluated. The recursive resolver may cache answers; DNSSEC chain validation, authoritative consistency and mail server connectivity are outside scope.

## TLS

The standard library verifies a single selected public IP on port 443 using the requested SNI/hostname and the local trust store. A successful handshake supplies certificate issuer, validity dates, days remaining, protocol and cipher. Expiry within thirty days is a renewal warning; short-lived certificates may renew more frequently by design. A certificate verification failure marks only the proven dimension failed (hostname, validity or chain). Other dimensions remain unknown; no second insecure handshake is made to collect unverified evidence. Local clock/trust configuration can affect results. Revocation, CT, supported-version enumeration and cipher suites are not tested. Negotiating TLS 1.3 does not establish that TLS 1.0 is disabled.

## HTTP and browser headers

HTTP and HTTPS start with HEAD. After HTTPS HEAD 405/501, an explicitly enabled GET fallback can retrieve headers; it is disabled by default because GET can cause application side effects. It starts at the final HEAD URL and retains HTTPS, scope, public-IP, pinning and TLS verification controls on every hop. HEAD and GET share the redirect allowance, request budgets and deadline. No retries, credentials, cookies, Range header or body-stream reads are used; bodies may still be sent or partially buffered with headers and are discarded. HTTPS connectivity is recorded separately from the application response: a final 2xx response meets the limited application-response criterion, while non-2xx or failed requests leave availability Unknown. The final successful 2xx HTTPS HEAD or authorized GET response is used for browser-header checks; CDN geography, caches, virtual hosts, application paths and GET behavior can differ. An arbitrary HTTP error, unreachable port 80, blocked redirect or time limit is inconclusive, not proof of a transport vulnerability. A successful HTTP response without HTTPS upgrade is a low-severity warning. Redirects outside the organizational domain or to non-public destinations are blocked and unknown.

HSTS uses the first response field, one positive numeric max-age, balanced quoting and unique directives; large decimal strings do not undergo unbounded integer conversion. This is not preload validation. CSP presence does not establish effectiveness and report-only is not enforcement. HTML meta policy is not inspected. CSP frame-ancestors is considered as an alternative to valid DENY/SAMEORIGIN X-Frame-Options; the first duplicate directive wins within each policy, and multiple enforcing policies are considered together. Source-expression interpretation is deliberately limited, not full browser policy emulation. CSP/framing/Permissions-Policy are not applicable for known non-HTML content and unknown for untyped content. Permissions-Policy restrictions are not semantically validated. Referrer policy accounts for recognized fallback tokens and browser defaults. Missing headers are contextual warnings, never automatically critical or proof of exploitation.

## Findings and optional score

Every finding contains a UUID, stable check ID, bilingual name/explanation/impact/remediation, category, status, severity, evidence, UTC timestamp, references and an explicit scoring flag. Unknown, Error and Not applicable are never failures.

The score is `100 * passed / (passed + failed)` restricted to checks marked scoreable and whose current status is Passed or Failed. It is rounded to one decimal place; no denominator means no score. Warning, Unknown, Error and Not applicable are excluded. For new v0.3 runs, metadata selects scoring profile `context-v1`: eligibility additionally requires applicability `applicable`. Scoreable dimensions remain certificate chain, hostname, validity and negotiated modern protocol, plus selected determinate policy errors when applicable. All optional browser headers, including passing HSTS/nosniff, are excluded to prevent optional passes from diluting confirmed failures. Unknown applicability and explicitly inapplicable criteria are excluded; the result status itself is preserved. New-run scoreable flags persist these exclusions for older schema-v1 consumers. Presence-only checks and contextual policy preferences remain unscored. Near-expiry warnings are excluded. Coverage (evaluated and excluded counts) must accompany the number.

This simple score is a diagnostic summary, can be high despite unscored warnings, and is neither a probability of compromise nor an organization-wide rating. Unknown results can change the denominator between assessments. Compare actual findings, declared context, applicability, evaluated criteria and scoring profile before comparing scores. Historical runs without context-v1 retain the original eligibility/flags and formula, including any historical HSTS/nosniff passes; they are never reannotated or rescored with the new rules. No historical score is silently rewritten, and a cross-profile score change alone is not a security regression. The dashboard and HTML score are opt-in; JSON always includes the formula and computed coverage for machine consumers.

## Technical references

- [SPF: RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)
- [DMARC behavior implemented: RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)
- [Current DMARC standard, not fully implemented: RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989)
- [DKIM: RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)
- [Null MX: RFC 7505](https://www.rfc-editor.org/rfc/rfc7505)
- [CAA: RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)
- [TLS verification: Python ssl documentation](https://docs.python.org/3/library/ssl.html)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)


## Context and schema-v1 compatibility (v0.3)

Observation is the measured record/response/handshake. A finding interprets only
that evidence against a stated criterion. Applicability describes relevance to the
stated service use, independently of status; severity describes the supported
importance, not proven exploitability. A recommendation is a conditional next step
for the responsible administrator, not an instruction to change every missing
optional record.

The optional `AssessmentContext` accepts `sends_email`, `receives_email` and
`controls_dns` as True/False/None, exposed as yes/no/unknown in CLI and dashboard.
It never changes queries, raw evidence, authorization, fallback behavior or budgets.
Metadata records context as user-declared and not independently verified. DNS
control affects action ownership only; it never proves mail use or applicability.
There are no provider-name or shared-hosting ownership heuristics.

Email/MX applicability follows declared sending/receiving respectively, defaulting
to Unknown. A non-sending declaration makes the operational sending criterion NA,
not the domain immune to spoofing: protective SPF/DMARC policy can remain relevant.
SPF envelope/HELO, DMARC author and DKIM signing identities may differ and are not
verified here. MX does not establish a sending identity. No selectors keeps DKIM
Unknown even with declared sending. Missing SPF/DMARC stay Warning, informational
by default or low when sending is declared; errors in published supported syntax
can still be Failed even with unknown or NA operational relevance.

CAA relevance remains conditional because effective policy is not evaluated.
Missing exact-name NS or AAAA is recorded in inventory without a requirement to
publish them. TLS/HTTP applicability covers the tested endpoint/criterion only.
For eligible HTML responses HSTS/nosniff/CSP have applicable optional hardening
criteria; permissions, framing and referrer relevance remain unknown without
feature, embedding or privacy requirements. Known non-HTML document checks remain
NA; ineligible HTTP responses leave header applicability Unknown. Presence-only
passes never assert policy effectiveness.

No mandatory model fields change. Schema version 1 and SQLite user_version 1 stay:

- `metadata.context`: declaration fields, source, independently_verified=false.
- `metadata.scoring_profile`: `context-v1` for new engine runs.
- `evidence.applicability`: state (`applicable`, `not_applicable`, `unknown`),
  basis (`user_declared`, `observed_scope`, `observed_response`,
  `observed_content_type`, `unknown`) and bilingual reason (`en`, `it`).
- JSON summary additionally includes `priority_finding_ids`; existing counts and
  confirmed/inconclusive IDs retain raw status semantics.

Old readers accept these free-form dictionary additions. Stored scoreable flags
make new-run eligibility consistent even for the original ratio implementation;
older interfaces cannot explain the new applicability/profile and should be
updated for interpretation. Loading old payloads does not inject these keys.
Historical missing applicability is displayed as Unknown without changing source
payloads or old score eligibility. Exports retain the original status/evidence
apart from the existing web-data minimization. HTML/dashboard priority actions
omit informational and explicitly inapplicable results, while counts and full
finding details retain them. Failed criteria still appear in the confirmed list
with applicability, even if no operational action is prioritized.
