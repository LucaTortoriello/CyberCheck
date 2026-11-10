# Community licensing and future commercial offerings

The existing public repository uses **GNU AGPL v3 or later**, with the full text in `LICENSE`. v0.2 preserves that file and the `AGPL-3.0-or-later` declaration unchanged; this audit does not approve or implement a different license. Third-party dependencies retain their own licenses.

AGPL is appropriate when a founder wants a fully functional community engine while encouraging reciprocal availability of covered modifications. Section 13 addresses source offers for modified versions used through a network. The exact scope of obligations depends on the covered work and integration. **AGPL permits commercial activity**: a competitor may host or resell the software while complying with its obligations. It does not require payment to the original founder and does not protect the business model from competition.

MIT is an alternative if maximum distribution and easy proprietary integration are the priority. It permits reuse, sublicensing and sale under its notice conditions and does not require publication of modifications. Apache-2.0 adds an explicit patent grant and more conditions, while remaining permissive. Neither prevents competing services.

Commercial validation should initially focus on managed workflows, monitoring, support, custom branding and operational convenience. Do not depend on a license to prevent competition. Keep future service orchestration separate from the community engine and review how any proprietary component interacts with AGPL-covered code before distribution. Dual licensing requires the necessary rights from every relevant copyright holder; accepting outside contributions without an appropriate agreement can complicate that strategy. Decide contribution rights before pursuing dual licensing, rather than assuming all contributions belong to the founder.

No enterprise restrictions, field-of-use prohibition or artificial limits are applied to the community MVP. No trademark or customer rights are granted beyond the actual license. The repository is public at [LucaTortoriello/CyberCheck](https://github.com/LucaTortoriello/CyberCheck); no paid service is provisioned by this release work.

These are planning considerations, not a definitive legal opinion. Before offering proprietary integrations, alternate commercial licenses or a hosted service, review the actual technical relationship, dependency licenses, source-offer obligations and contributor rights with appropriate legal advice. Separating directories or processes alone does not settle whether code is a covered combined work. Do not promise that a future Pro module is automatically exempt from AGPL obligations.

Primary sources: [GNU AGPL v3](https://www.gnu.org/licenses/agpl-3.0.html), [GNU AGPL FAQ](https://www.gnu.org/licenses/why-affero-gpl.html), [OSI MIT](https://opensource.org/license/mit), [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
