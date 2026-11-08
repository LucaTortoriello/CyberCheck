# Methodology, scoring and known limitations

## Scope

CyberCheck observes publicly resolvable DNS and the root web endpoint of one input hostname. It makes one TLS handshake and bounded HTTP HEAD requests. These are low-impact active requests, not purely passive intelligence. The app does not verify asset ownership beyond a mandatory user declaration.

## Email and DNS

SPF detects policy absence, multiple records, common definite syntax problems, invalid IP-family/network tokens and an unrestricted `+all`. A valid `~all` can be appropriate during rollout; `-all` is not imposed. Common syntax passing is not full SPF validity. A static traversal counts potential include/redirect/a/mx/ptr/exists terms up to a bounded depth and flags potential paths exceeding ten. Short-circuit sender evaluation means this is a warning, not a proven runtime permerror. Macro expansion, every A/MX/PTR CIDR grammar variant, void lookup counts, MX/PTR address fan-out, sender-IP evaluation and include success semantics are not fully implemented. Dependency lookup failures remain unknown for the complexity check. SPF findings are excluded from the score except explicitly modeled determinate cases such as multiple policies.

DMARC checks the exact `_dmarc` name, then falls back to the organizational domain for absent exact-name DMARC. The bundled public suffix snapshot avoids runtime list downloads. An inherited `sp` policy is respected. The parser checks required tag ordering, duplicate tags, p/sp, alignment modes and the RFC 7489 pct range. `p=none` is monitoring, not a critical vulnerability. Publication and a mailto reporting destination do not prove alignment, report delivery, external-report authorization or receiver behavior. Only supported tags receive semantic validation. Public-suffix-domain-specific policies and newer DMARC discovery extensions are not implemented.

DKIM is unknown without a supplied selector. Only those selectors are queried. An absent key does not establish that all DKIM signing is disabled. A published base64 key is an observation, not cryptographic key validation or verified signature use; RSA structure/bit length, service/granularity restrictions, selector rotation and signing alignment require message-level evidence. Empty p= is a revoked selector, not a domain-wide conclusion.

DNS inventory records A/AAAA, NS, MX and CAA at the input name. A missing exact-name NS can be normal for a non-apex hostname. Missing MX can fall back to implicit A/AAAA routing; null MX declares no inbound mail and must not coexist with other MX. CAA absence is informational and parent/CNAME inheritance and issuance authorization are not evaluated. The recursive resolver may cache answers; DNSSEC chain validation, authoritative consistency and mail server connectivity are outside scope.

## TLS

The standard library verifies a single selected public IP on port 443 using the requested SNI/hostname and the local trust store. A successful handshake supplies certificate issuer, validity dates, days remaining, protocol and cipher. Expiry within thirty days is a renewal warning; short-lived certificates may renew more frequently by design. A certificate verification failure marks only the proven dimension failed (hostname, validity or chain). Other dimensions remain unknown; no second insecure handshake is made to collect unverified evidence. Local clock/trust configuration can affect results. Revocation, CT, supported-version enumeration and cipher suites are not tested. Negotiating TLS 1.3 does not establish that TLS 1.0 is disabled.

## HTTP and browser headers

HTTP and HTTPS use HEAD only, with no GET fallback or HTML body inspection. A server that rejects HEAD can leave header checks unknown. The final successful 2xx HTTPS HEAD response is used for browser-header checks; CDN geography, caches, virtual hosts, application paths and GET behavior can differ. An arbitrary HTTP error, unreachable port 80, blocked redirect or time limit is inconclusive, not proof of a transport vulnerability. A successful HTTP response without HTTPS upgrade is a low-severity warning. Redirects outside the organizational domain or to non-public destinations are blocked and unknown.

HSTS is checked for one positive numeric max-age; this is not preload validation. CSP presence does not establish its effectiveness and report-only is not enforcement. HTML meta policy is not inspected. CSP frame-ancestors is considered as an alternative to valid DENY/SAMEORIGIN X-Frame-Options; the first repeated directive is inspected. CSP/framing/Permissions-Policy are not applicable for known non-HTML content and unknown for untyped content. Permissions-Policy restrictions are not semantically validated. Referrer policy accounts for recognized fallback tokens and browser defaults. Missing headers are contextual warnings, never automatically critical or proof of exploitation.

## Findings and optional score

Every finding contains a UUID, stable check ID, bilingual name/explanation/impact/remediation, category, status, severity, evidence, UTC timestamp, references and an explicit scoring flag. Unknown, Error and Not applicable are never failures.

The score is `100 * passed / (passed + failed)` restricted to checks marked scoreable and whose current status is Passed or Failed. It is rounded to one decimal place; no denominator means no score. Warning, Unknown, Error and Not applicable are excluded. Current scoreable dimensions include certificate chain, hostname, validity and negotiated modern protocol; HSTS activation and nosniff criteria; and selected determinate policy errors. Presence-only checks and contextual policy preferences remain unscored. Near-expiry warnings are excluded. Coverage (evaluated and excluded counts) must accompany the number.

This simple score is a diagnostic summary, can be high despite unscored warnings, and is neither a probability of compromise nor an organization-wide rating. Unknown results can change the denominator between assessments. Compare actual findings and coverage before comparing scores. The dashboard and HTML score are opt-in; JSON always includes the formula and computed coverage for machine consumers.

## Technical references

- [SPF: RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)
- [DMARC behavior implemented: RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)
- [DKIM: RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)
- [Null MX: RFC 7505](https://www.rfc-editor.org/rfc/rfc7505)
- [CAA: RFC 8659](https://www.rfc-editor.org/rfc/rfc8659)
- [TLS verification: Python ssl documentation](https://docs.python.org/3/library/ssl.html)
- [OWASP Secure Headers](https://owasp.org/www-project-secure-headers/)
