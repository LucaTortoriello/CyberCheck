# Real-world validation procedure and status

**Status on 2026-11-09: not run.** The developer explicitly confirmed that they do not currently own a domain. No alternative third-party target was authorized. No live DNS/TLS/HTTP assessment, false-positive rate or real-world accuracy claim is recorded for v0.2. The existing examples are synthetic and labeled accordingly.

This does not block offline engineering review. It does block claiming that domain behavior and remediation have been independently validated in a customer environment. Do not replace this status with a successful result until the steps below are actually executed with authorization.

## Preconditions

1. Obtain a domain owned by the developer or explicit written authorization from its owner. Include the exact hostname, allowed related redirects, low-impact DNS/TLS/HTTP checks and any supplied DKIM selectors.
2. Confirm that the hostname resolves only to permitted public addresses. Confirm the legitimate web/mail services and the intended SPF/DMARC policy with their administrator.
3. Use the release branch, a clean environment and the documented dependency lock. Record the commit, OS, Python, OpenSSL, curl, resolver and trust-store configuration.
4. Store raw evidence under `exports/real-world-validation/`, excluded from Git, with owner-only permissions. Raw curl output can contain cookies; do not publish it. The tool's own exports now omit cookies and redact URL queries, but paths and DNS can remain sensitive.

## Run the application

The following commands are a template, **not executed validation**. Replace placeholders only after authorization:

```sh
source .venv/bin/activate
export CYBERCHECK_VALIDATION_DOMAIN='your-authorized-domain.tld'
umask 077
cybercheck "$CYBERCHECK_VALIDATION_DOMAIN" --authorized --language en --output exports/real-world-validation
```

Add `--selectors selector1,selector2` only if the provider supplies those selectors. Never infer signing from a guessed or absent selector. Record the assessment ID, UTC timestamps, chosen IP, final URL, redirects, lookup/request counts and every incomplete check.

## Independently compare DNS

Use the same configured resolver first, recording TTLs and timestamps:

```sh
dig "$CYBERCHECK_VALIDATION_DOMAIN" TXT +noall +answer
dig "_dmarc.$CYBERCHECK_VALIDATION_DOMAIN" TXT +noall +answer
dig "$CYBERCHECK_VALIDATION_DOMAIN" A +noall +answer
dig "$CYBERCHECK_VALIDATION_DOMAIN" AAAA +noall +answer
dig "$CYBERCHECK_VALIDATION_DOMAIN" NS +noall +answer
dig "$CYBERCHECK_VALIDATION_DOMAIN" MX +noall +answer
dig "$CYBERCHECK_VALIDATION_DOMAIN" CAA +noall +answer
```

Concatenate the character strings within each TXT record, but do not merge separate TXT records. Check multiple SPF records, qualifiers, supported CIDRs and the first `all`. For includes/redirects, compare only explicit dependency names; `_spf` service labels are legitimate DNS names. Static lookup counts are not proof of sender-specific runtime failure.

Check the exact DMARC name and the legacy organizational-domain fallback recorded in the evidence. v0.2 explicitly implements the older RFC 7489 PSL/pct profile; [RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989) defines newer discovery/testing behavior. Do not treat a v0.2 legacy result as current-standard receiver simulation. Records with np/psd/t are inconclusive. A discrepancy caused by current-standard tree-walk discovery is a documented limitation, not evidence that the owner's valid configuration must be changed.

If a selector is supplied, query exactly `SELECTOR._domainkey.DOMAIN`. Compare the returned key tags, revoked/absent state and published base64 data. To validate signing/alignment, inspect an owner-authorized real message's DKIM-Signature and Authentication-Results; this additional message-level activity is outside the domain-only engine.

## Independently compare TLS and HTTP

Copy the **validated public IP from the tool's TLS evidence** into `CYBERCHECK_VALIDATION_IP`. Compare the same endpoint, rather than allowing a second DNS lookup to select a different CDN server. Do not use a private IP or disable certificate verification.

```sh
export CYBERCHECK_VALIDATION_IP='PUBLIC_IP_FROM_THE_REPORT'
```

Use OpenSSL 3 with a bounded subprocess. This template uses argument arrays, original hostname verification/SNI and the selected IP; it does not invoke a shell or probe other ports:

```sh
python - <<'PY'
import os
import subprocess
from cybercheck.core.validation import normalize_domain, public_ip

domain = normalize_domain(os.environ['CYBERCHECK_VALIDATION_DOMAIN'])
address = public_ip(os.environ['CYBERCHECK_VALIDATION_IP'])
endpoint = f'[{address}]:443' if ':' in address else f'{address}:443'
result = subprocess.run(
    ['openssl', 's_client', '-connect', endpoint, '-servername', domain,
     '-verify_hostname', domain, '-verify_return_error', '-showcerts'],
    input='', text=True, capture_output=True, timeout=10, check=False,
)
print(result.stdout)
print(result.stderr)
print('OpenSSL exit:', result.returncode)
PY
```

Verify the installed OpenSSL supports those options before running; macOS may ship LibreSSL under the same command name. If necessary select an installed Homebrew OpenSSL 3 binary explicitly. Compare issuer, SANs, notBefore/notAfter, chain result and negotiated version. Local trust-store differences, not a target defect, can explain differing results. Negotiating a modern version does not prove that older versions are disabled.

For headers, use curl HEAD with strict connect/total timeouts, no proxy and explicit IP pinning. `--resolve` accepts IPv6 in brackets; set `CYBERCHECK_CURL_IP` to that representation when needed:

```sh
export CYBERCHECK_CURL_IP="$CYBERCHECK_VALIDATION_IP"
curl --head --connect-timeout 5 --max-time 10 --noproxy '*' --proto '=https' \
  --resolve "$CYBERCHECK_VALIDATION_DOMAIN:443:$CYBERCHECK_CURL_IP" \
  "https://$CYBERCHECK_VALIDATION_DOMAIN/"
curl --head --connect-timeout 5 --max-time 10 --noproxy '*' --proto '=http' \
  --resolve "$CYBERCHECK_VALIDATION_DOMAIN:80:$CYBERCHECK_CURL_IP" \
  "http://$CYBERCHECK_VALIDATION_DOMAIN/"
```

Do not add automatic `-L` following. Inspect each Location, confirm ownership/scope, resolve it and validate all A/AAAA addresses before comparing another hop. Stop on cross-organizational redirects, nonstandard ports, non-public destinations, exhausted limits or a downgrade after any HTTPS hop. Record those cases as blocked/inconclusive. If HEAD is rejected, record that limitation; a GET observation is a separate manual result and must not silently replace the engine's HEAD evidence.

For HSTS process the first header field and validate its directives. For CSP consider all enforcing policies together; report-only is not enforcement. Review browser policy relevance with the application administrator before recommending a change.

## Discrepancy log and acceptance

| Area | Tool observation | Independent observation | Explanation / false positive or negative | Resolution |
|---|---|---|---|---|
| SPF / dependencies | Not run | Not run | Authorization/domain unavailable | Pending |
| DMARC / inheritance | Not run | Not run | Legacy/current-standard scope must be distinguished | Pending |
| Explicit DKIM selector | Not run | Not run | No selector supplied | Pending |
| TLS / certificate | Not run | Not run | Authorization/domain unavailable | Pending |
| HTTP / redirect / headers | Not run | Not run | Authorization/domain unavailable | Pending |
| Remediation relevance | Not run | Not run | Requires owner/mail/hosting administrator review | Pending |

For every discrepancy, first compare the same IP, method, hostname, UTC interval, resolver and trust store. Preserve unknowns; never recategorize a timeout or blocked request as a vulnerability. Turn confirmed implementation defects into mocked regression tests, with sensitive live details removed. Obtain the owner's review of remediation advice and record their acceptance or correction. Publishing the result or any raw evidence requires separate approval.
