# Security policy

CyberCheck 0.1 is a local, single-user configuration assessment MVP. It is not a hardened hosted scanning service. Keep it bound to 127.0.0.1 and assess only owned or explicitly authorized assets.

## Report a vulnerability

Do not publish exploit details, internal hostnames, customer data or tokens in a public issue. When this repository is published, its maintainer should enable GitHub private vulnerability reporting and provide a maintained private contact. This local project has no public disclosure channel yet. Until one exists, ask the maintainer for a private contact using a non-sensitive message.

Include the affected version, minimal reproduction using fixtures or your own authorized domain, expected behavior, observed behavior and security impact. Do not probe unrelated hosts or demonstrate exploitation against third parties. No response-time or bounty commitment is implied.

## Areas requiring review

- Domain/URL normalization, non-public address rejection and pinned IP/SNI handling.
- Redirect scope and port validation, deadlines, header limits and request budgets.
- HTML/report escaping and handling of untrusted DNS/header evidence.
- Local file permissions, report retention and any future public hosting changes.
- Dependencies and future schema/authentication changes.

Network failures, unknown checks and blocked requests must remain distinct from vulnerabilities. Authorization is a mandatory declaration, not proof of ownership. OS networking, local DNS resolver, routing and trust store are trusted. VPN/NAT behavior requires deployment-level egress controls for a future service.

No secrets are required. Keep `.env`, Streamlit secrets, databases, exports and real customer evidence out of Git. Review dependency updates and run offline tests before release.
