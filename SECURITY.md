# Security Policy

Guard Score / Verified Changes is a security tool, so we hold ourselves to the standard we ask of others. This document covers **(1) how to report a vulnerability in Guard Score itself** and **(2) how we handle security issues we find in other people's software** (e.g. during benchmarking or the ecosystem study).

## 1. Reporting a vulnerability in Guard Score

If you find a security issue in the Verified Changes / Guard Score tools, the website, or the badge service, please report it privately — do not open a public issue for it.

- **Email:** [SECURITY EMAIL, e.g. security@yourdomain]
- **Or:** open a GitHub private security advisory at https://github.com/Tunceroo/guardscore/security/advisories/new
- Please include: what you found, how to reproduce it, and the impact. If you have a proof-of-concept, include it.

**What to expect:**
- We aim to acknowledge within **3 business days**.
- We aim to give an initial assessment within **10 business days**.
- We will keep you updated, credit you if you wish once a fix ships, and let you know when the issue is resolved.
- Please give us a reasonable time to fix the issue before any public disclosure (we target **90 days**, sooner for low-complexity fixes).

**Safe harbor.** If you make a good-faith effort to follow this policy — you only test against your own installation or our official demo, you do not access or destroy others' data, you do not degrade the service, and you report promptly and privately — we will not pursue or support legal action against you for that research.

**Out of scope:** volumetric denial-of-service, social engineering of our team or users, findings that require a compromised machine you already control, and reports from automated scanners without a demonstrated, exploitable impact.

## 2. How we handle vulnerabilities we find in others' software

When Guard Score's development, benchmarking, or the ecosystem study identifies a real, exploitable security issue in someone else's application:

- We **never publish the identity of a vulnerable application** or any data from it. Public write-ups use aggregate statistics and anonymized patterns only.
- Where a finding maps to a live, exploitable deployment, we **privately disclose it to the maintainer first**, with the specific issue and a suggested fix, and give a reasonable grace period (target **30–90 days**) before any aggregate publication.
- We only analyze lawfully, publicly available artifacts (e.g. public repositories), and we run deep checks only against **private copies built from those public files**, never against anyone's live systems.
- If a maintainer asks to be excluded, we honor it.

Full protocol: see [`docs/ecosystem-study.md`](docs/ecosystem-study.md).

## Supported versions

Until a 1.0 release, security fixes are applied to the latest published version. Please run the latest version before reporting.

---

*Replace the bracketed contact fields before publishing. This policy is provided in good faith and is not a contract; nothing here waives rights except the good-faith safe harbor described above.*
