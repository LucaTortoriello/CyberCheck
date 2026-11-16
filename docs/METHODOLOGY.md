# Methodology, scoring and known limitations

## Scope

CyberCheck observes publicly resolvable DNS and the root web endpoint of one input hostname. It makes one TLS handshake and bounded HTTP HEAD requests, with explicitly authorized HTTPS GET fallback after HEAD 405/501. These are low-impact active requests, not purely passive intelligence. The app does not verify asset ownership beyond a mandatory user declaration.

## Email and DNS

SPF detects policy absence, multiple records, common definite syntax problems, invalid IP-family/network tokens, supported A/MX dual-CIDR/PTR syntax and a permissive `+all` fallback for otherwise unmatched senders. A valid `~all` can be appropriate during rollout; `-all` is not imposed. Unknown modifiers are ignored, including repeated/empty extensions. DNS-only includes/redirects can use `_spf` labels. Sender-dependent macros remain inconclusive, including macros containing an equals-sign delimiter; no macro-driven target expansion is performed. Common syntax passing is not full SPF validity. A static traversal counts potential include/redirect/a/mx/ptr/exists terms up to bounded depth and flags paths exceeding ten. Short-circuit sender evaluation means this is a warning, not a proven runtime permerror. Void lookup counts, MX/PTR fan-out, sender-IP evaluation and include success semantics are not fully implemented. Dependency failures remain unknown for complexity. SPF findings are excluded from the score except explicitly modeled determinate cases such as multiple policies.

DMARC checks the exact `_dmarc` name, then falls back to the organizational domain for absent exact-name DMARC. The bundled public suffix snapshot avoids runtime list downloads. An inherited `sp` policy is respected. The parser checks required tag ordering, duplicate tags, p/sp, alignment modes and the RFC 7489 pct range. `p=none` is monitoring, not a critical vulnerability. Publication and a mailto reporting destination do not prove alignment, report delivery, external-report authorization or receiver behavior. Only supported tags receive semantic validation. Public-suffix-domain-specific policies and newer DMARC discovery extensions are not implemented.

**DMARC standards boundary:** RFC 9989, published in May 2026, supersedes RFC 7489. v0.2 preserves the existing **legacy RFC 7489** discovery/validation profile and explicitly labels that scope in finding text/evidence; legacy syntax/percentage results are not a statement of full current-standard conformance. np/psd/t markers leave the primary policy check Unknown and unscored. Current-standard DNS tree walk and testing semantics are deferred to v0.3; modern receivers can ignore historic pct and use different policy discovery. Do not automatically change a valid modern policy solely because of a legacy-profile finding. Validate against the owner's intended receiver behavior. Version-tag whitespace is recognized so an exact policy is not accidentally skipped in favor of an inherited one.

DKIM is unknown without a supplied selector. Only those selectors are queried. An absent key does not establish that all DKIM signing is disabled. A published base64 key is an observation, not cryptographic key validation or verified signature use; RSA structure/bit length, service/granularity restrictions, selector rotation and signing alignment require message-level evidence. Empty p= is a revoked selector, not a domain-wide conclusion.

DNS inventory records A/AAAA, NS, MX and CAA at the input name. NXDOMAIN does not yield a Passed inventory or a security vulnerability: affected checks remain Unknown. A missing exact-name NS can be normal for a non-apex hostname. Missing MX can fall back to implicit A/AAAA routing; null MX declares no inbound mail and must not coexist with other MX. CAA absence is informational and parent/CNAME inheritance and issuance authorization are not evaluated. The recursive resolver may cache answers; DNSSEC chain validation, authoritative consistency and mail server connectivity are outside scope.

## TLS

The standard library verifies a single selected public IP on port 443 using the requested SNI/hostname and the local trust store. A successful handshake supplies certificate issuer, validity dates, days remaining, protocol and cipher. Expiry within thirty days is a renewal warning; short-lived certificates may renew more frequently by design. A certificate verification failure marks only the proven dimension failed (hostname, validity or chain). Other dimensions remain unknown; no second insecure handshake is made to collect unverified evidence. Local clock/trust configuration can affect results. Revocation, CT, supported-version enumeration and cipher suites are not tested. Negotiating TLS 1.3 does not establish that TLS 1.0 is disabled.

## HTTP and browser headers

HTTP and HTTPS start with HEAD. After HTTPS HEAD 405/501, an explicitly enabled GET fallback can retrieve headers; it is disabled by default because GET can cause application side effects. It starts at the final HEAD URL and retains HTTPS, scope, public-IP, pinning and TLS verification controls on every hop. HEAD and GET share the redirect allowance, request budgets and deadline. No retries, credentials, cookies, Range header or body-stream reads are used; bodies may still be sent or partially buffered with headers and are discarded. HTTPS connectivity is recorded separately from the application response: a final 2xx response meets the limited application-response criterion, while non-2xx or failed requests leave availability Unknown. The final successful 2xx HTTPS HEAD or authorized GET response is used for browser-header checks; CDN geography, caches, virtual hosts, application paths and GET behavior can differ. An arbitrary HTTP error, unreachable port 80, blocked redirect or time limit is inconclusive, not proof of a transport vulnerability. A successful HTTP response without HTTPS upgrade is a low-severity warning. Redirects outside the organizational domain or to non-public destinations are blocked and unknown.

HSTS uses the first response field, one positive numeric max-age, balanced quoting and unique directives; large decimal strings do not undergo unbounded integer conversion. This is not preload validation. CSP presence does not establish effectiveness and report-only is not enforcement. HTML meta policy is not inspected. CSP frame-ancestors is considered as an alternative to valid DENY/SAMEORIGIN X-Frame-Options; the first duplicate directive wins within each policy, and multiple enforcing policies are considered together. Source-expression interpretation is deliberately limited, not full browser policy emulation. CSP/framing/Permissions-Policy are not applicable for known non-HTML content and unknown for untyped content. Permissions-Policy restrictions are not semantically validated. Referrer policy accounts for recognized fallback tokens and browser defaults. Missing headers are contextual warnings, never automatically critical or proof of exploitation.

## Findings and optional score

Every finding contains a UUID, stable check ID, bilingual name/explanation/impact/remediation, category, status, severity, evidence, UTC timestamp, references and an explicit scoring flag. Unknown, Error and Not applicable are never failures.

The score is `100 * passed / (passed + failed)` restricted to checks marked scoreable and whose current status is Passed or Failed. It is rounded to one decimal place; no denominator means no score. Warning, Unknown, Error and Not applicable are excluded. Current scoreable dimensions include certificate chain, hostname, validity and negotiated modern protocol; HSTS activation and nosniff criteria; and selected determinate policy errors. Presence-only checks and contextual policy preferences remain unscored. Near-expiry warnings are excluded. Coverage (evaluated and excluded counts) must accompany the number.

This simple score is a diagnostic summary, can be high despite unscored warnings, and is neither a probability of compromise nor an organization-wide rating. Unknown results can change the denominator between assessments. Compare actual findings and coverage before comparing scores. The dashboard and HTML score are opt-in; JSON always includes the formula and computed coverage for machine consumers.

## Technical references

- [SPF: RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)
- [DMARC behavior implemented: RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)
- [Current DMARC standard, not fully implemented: RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989)
- [DKIM: RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)
- [Null MX: RFC 7505](https://www.rfc-editor.org/rfc/rfc7505)
- [CAA: RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)
- [TLS verification: Python ssl documentation](https://docs.python.org/3/library/ssl.html)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
