# Assessment comparison methodology (v0.4)

`comparison-v1` is a pure function of two saved assessments. It runs no network
checks, calls no external service and writes no assessment or database record.
It matches exact `check_id` values; titles, UUIDs and localized wording do not
identify a criterion. Domains must match exactly as normalized by the engine.
Reversed known start times are rejected; missing/malformed/naive timestamps
reduce comparability. Duplicate check IDs are ambiguous, never silently merged.

## Independent dimensions and categories

Each finding comparison records observation change, status/severity changes,
applicability state/basis/availability, declared context, score eligibility/profile,
and check methodology. Engine-version changes are also visible separately.
`differences` contains field paths, each side's presence and each recorded value;
missing fields and explicit nulls/empty record sets are distinct.

The summary contains nonexclusive counts **per finding**, not vulnerabilities or
independent underlying causes:

- **New concern:** an earlier Passed criterion becomes a noninformational
  Warning/Failed concern, with different measured evidence under comparable rules,
  context and scope. Explicit inapplicability does not qualify as a concern.
- **Resolved concern:** the reverse, with an actual observed change and a later
  Passed criterion. It does not certify the service as secure.
- **Persistent concern:** comparable, supported concerns for the same criterion
  on both sides. The causes need not be identical; observations may also change.
- **Unchanged:** supported observations and interpretation are equivalent within
  the supported projection. A renewal with two Passed results is instead a
  changed observation, with the concern lifecycle unchanged.
- **Changed observation:** shared measured fields differ. This alone does not
  establish a target configuration change, security improvement or regression.
- **Evaluation changed:** equivalent observations receive different interpretation,
  or context/applicability/score treatment/methodology changes. Separate dimensions
  also show status/severity changes when observations change simultaneously.
- **Inconclusive:** lifecycle cannot be established reliably. Unknown/Error/NA,
  missing/new checks, duplicate IDs, insufficient evidence and incompatible scopes
  never establish new/resolved concerns. Becoming measurable after Unknown does
  not establish when a concern arose.

For example, the same certificate can cross an expiry-warning threshold as time
passes. The classification changes while the measured certificate is unchanged;
this is an evaluation change, not proof of a certificate replacement.

## Comparability rules

Findings and the whole pair each have Comparable / Partially comparable / Not
comparable, with bilingual reason codes. There are no confidence percentages.

No unique matched observation, unsupported checks or wholly missing measurements
are not comparable. Known measurements with incomplete fields, different scope,
methodology, profile or relevant context are partially comparable. Available
common measured fields can still be displayed as changed, while lifecycle remains
inconclusive. An overall partially comparable pair can contain individual fully
comparable criteria and a limited valid score comparison.

- Known metadata versions `0.2.0` map to `checks-v0.2`; `0.3.0` and `0.4.0` map to
  `checks-v0.3`. Explicit recognized methodology IDs take precedence. Unknown or
  malformed versions/IDs do not establish equivalent rules. This mapping describes
  the reviewed releases; version labels are not code-integrity attestations and
  cannot reconstruct unrecorded private modifications.
- New v0.4 runs record `methodology_version: checks-v0.3`. Checking rules remain
  unchanged; extra raw-header evidence is measurement bookkeeping.
- Context is the three recorded sending/receiving/DNS-control declarations, always
  treated as unverified. Missing historical context is not explicit Unknown.
  Relevant DNS/email context changes qualify their comparisons; changes are also
  visible at pair level. Unrelated email context does not reclassify an unchanged
  TLS observation; the pair-level context change remains visible and qualifies
  score comparisons. Applicability state, basis and recorded availability are
  independent of raw observations and can reduce comparability.
- Different DKIM selector sets qualify the whole pair. Each selector matches only
  its own exact ID; adding/removing a selector is coverage, never automatic lifecycle.
- Different or unrecorded HEAD/GET methods, GET authorization, response content type,
  status or endpoint qualify relevant web comparisons. Final redirect destinations
  are observations: when complete redirect chains establish the same initial HTTP
  URL/IP, that initial request defines scope for the redirect criterion. A changed
  initial endpoint reduces comparability. Missing hop fields are not fabricated;
  an additional hop in a fully recorded chain is an actual sequence difference.
- Different HTTP client versions also qualify web comparisons: the versioned
  User-Agent can change the returned response even if checking rules are identical.
- Redacted URL query values cannot establish equal hidden parameters. Queries
  remain redacted and those comparisons are qualified. Paths remain visible and
  can themselves contain sensitive information, as with existing exports.

## Evidence field selection

Only the following supported projections enter comparisons and exports. There is
no generic dump of historical evidence into a comparison report.

| Finding family | Included measured fields | Qualification / excluded fields |
|---|---|---|
| DNS inventory | Per A/AAAA/NS/MX/CAA: query name, type, state and valid records | Every required query must be completed for full comparability. Failed lookup records are not measured absence. |
| MX/CAA | Query name/type/state and records | Exact-name measurements only; no new inheritance/delivery inference. |
| SPF/DMARC | Query name/type/state and protocol records selected from raw TXT answers | Unrelated TXT tokens, parser tags/errors/effective policy, legacy/current-standard prose and added discovery diagnostics do not establish a target configuration delta. The underlying assessment retains them. |
| DKIM selector | Exact selector ID, query name/type/state and published public-key record strings | No-selector findings lack a measured selector comparison. No semantic/cryptographic signing evaluation is added. |
| TLS | Hostname, port, selected IP, issuer, validity dates, SAN coverage, protocol, cipher and verification code when recorded | Valid dates/endpoint fields are required for supported certificate comparison; a failed handshake with no certificate is incomplete. Countdown, scope prose, trust-store descriptions and arbitrary error messages are excluded. |
| HTTP | Redacted URL, method, status, selected IP, relevant header map, content type, hop count and ordered hop URL/status/method/IP fields | Cookies/arbitrary headers and bodies are excluded. Scope/method/response differences are qualified. |
| Browser headers | URL, method, status, content type, optional recorded IP and relevant raw field values | New `observed_headers` preserves multiple fields and their order. Historical scalar `header_value` supports single-header checks only. Parser-rendered framing strings cannot reconstruct original CSP/XFO. |
| SPF complexity / engine errors / unknown future IDs | No invented technical projection | Derived lookup estimates or execution errors cannot establish equivalent raw policy configuration. Comparisons stay inconclusive. |

DNS record sets are sorted and deduplicated; SAN order/JSON tuple-versus-list noise
is normalized. DNS query-state differences alone are operational metadata, not a
configuration delta: supported filtered policy absence can be equivalent despite
unrelated TXT publication. HTTP hop order and duplicate-header order are preserved.
Record/header strings are compared as recorded; there is no full semantic DNS,
SPF, DMARC, CSP or browser emulation. Per-request nonces, routing, caches, selected
backends and sampling can change observations without an administrator edit.

Assessment/finding UUIDs, timestamps, counters, durations, report-generation times,
certificate days remaining, explanations, remediation, applicability prose and
derived parser diagnostics do not count as measured configuration changes.
Applicability state/basis is compared separately. Fields not previously recorded
cannot be recovered. Equivalence always refers to the limited supported projection.

## Score compatibility

Each side uses the existing `Assessment.health` calculation and saved flags; no
historical score is recalculated under new assessment rules or persisted again.
The report exposes no numerical delta unless:

1. Both known scoring profiles and check methodologies match.
2. Complete recorded context and selector coverage match.
3. The nonempty evaluated check-ID sets, applicability and eligibility match.
4. Supporting scored findings are individually comparable, with numerical scores.

Equal totals with different IDs are insufficient. Unknowns/warnings changing the
denominator also invalidate the comparison. GET authorization alone need not
invalidate a TLS-only score if its actual evaluated criteria remain comparable;
relevant web comparisons still carry their own limits. Valid differences are
limited diagnostics, never probabilities or overall security ratings. Legacy v0.2
scores and context-v1 scores are explicitly incompatible. Missing historical
metadata does not get silently filled with current settings.

## Storage, API and export compatibility

SQLite `user_version=1`, assessment schema 1 and all existing finding/status fields
remain. New assessment metadata/evidence keys are additive. Existing assessment
HTML/JSON renderers retain their formats. The old `storage.sqlite.compare()` list
adapter retains familiar previous/current status/severity and evidence-change
keys; it now returns measured/evaluation differences with qualifiers, and enforces
chronological order. Use `compare_assessments()` for complete unchanged/persistent
results and pair-level compatibility.

Comparison exports are a separate schema-1 object with
`report_type: assessment_comparison`, `comparison_version: comparison-v1`, source
IDs/dates/versions/context/profile, summary, scoring and detailed projections.
JSON retains both languages; HTML selects Italian or English with autoescaping,
offline styles and the existing report restrictions. Source payloads are never
written, and raw bodies/secrets in arbitrary historical fields are never copied.
Known synthetic inputs keep a visible synthetic label.

## Worked fictional pair

The [Italian guide](GUIDA_ITALIANA.md#confrontare-due-assessment-in-v04) describes
the October/November fictional pair. Run:

```sh
python scripts/generate_comparison_example.py
```

It creates [English HTML](examples/comparison.en.html), [Italian HTML](examples/comparison.it.html)
and [bilingual JSON](examples/comparison.json) without connections. Certificate
metadata is expressly fictional; no actual certificate is collected or generated.
SPF, DMARC and CSP criteria resolve with measured changes; two TLS observations
change without automatically improving posture; referrer remains a conditional
concern; historical framing remains inconclusive because raw fields are missing.
Category counts overlap by design.
