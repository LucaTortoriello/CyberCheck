# Security policy

CyberCheck 0.2 is a local, single-user configuration assessment MVP. It is not a hardened hosted scanning service. Keep it bound to 127.0.0.1 and assess only owned or explicitly authorized assets. The v0.2 code review and advisory scan are documented in `docs/TECHNICAL_AUDIT_V02.md` and `docs/VALIDATION.md`; they are not a third-party certification.

## Report a vulnerability

Do not publish exploit details, internal hostnames, customer data or tokens in a public issue. The repository is public at https://github.com/LucaTortoriello/CyberCheck. Its maintainer should enable GitHub private vulnerability reporting and provide a maintained private contact; this audit does not assume that either has been configured. Use the private reporting option if available, otherwise ask the maintainer for a private contact using a non-sensitive message.

Include the affected version, minimal reproduction using fixtures or your own authorized domain, expected behavior, observed behavior and security impact. Do not probe unrelated hosts or demonstrate exploitation against third parties. No response-time or bounty commitment is implied.

## Areas requiring review

- Domain/URL normalization, non-public address rejection and pinned IP/SNI handling.
- Redirect scope and port validation, deadlines, header limits and request budgets.
- HTML/report escaping and handling of untrusted DNS/header evidence.
- Local file permissions, report retention and any future public hosting changes.
- Dependencies and future schema/authentication changes.

Network failures, unknown checks and blocked requests must remain distinct from vulnerabilities. Authorization is a mandatory declaration, not proof of ownership. OS networking, local DNS resolver, routing and trust store are trusted. VPN/NAT behavior requires deployment-level egress controls for a future service.

No secrets are required. Keep `.env`, Streamlit secrets, databases, exports and real customer evidence out of Git. Review dependency updates and run offline tests before release.

## v0.1 evidence and upgrade handling

v0.1 could retain Set-Cookie and full redirect query values in web findings. v0.2 minimizes newly collected evidence and redacts web data when rendering old history in the UI or exporting it. It preserves existing database payloads rather than silently rewriting audit history. Old databases, reports and backups may still contain the original values; review their handling and any prior sharing. Paths and public DNS records can remain sensitive even after web redaction.

v0.2 blocks downgrades after any HTTPS hop, including HTTP-started chains; rejects additional reserved/scoped destinations; closes a connected transport if the TLS-upgrade deadline expires; and creates exports privately without overwriting existing paths. Regression tests cover these cases. Parent directories, OS routing, the resolver and trust store remain trusted.
