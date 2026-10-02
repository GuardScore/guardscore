# Privacy Policy — Guard Score / Verified Changes

**Effective date:** 2026-09-28
**Who we are:** [LEGAL ENTITY OR YOUR NAME] ("we", "us"), operator of the Guard Score website ([WEBSITE URL, e.g. https://ideon.market]) and publisher of the Verified Changes / Guard Score open-source tools.

> Not legal advice. This template reflects how the product works today (a local command-line tool and a browser-only web scanner, with no user accounts). Have a lawyer review it before you rely on it, and update it the moment you add analytics, accounts, or any server that stores user input.

## The short version

Guard Score is built so your data stays with you. The command-line tool runs entirely on your machine. The website scanner runs entirely in your browser. **We do not receive, store, or transmit your database schema, rules, source code, or scan results.** We have no user accounts and we do not sell data.

## The command-line tool (`verified-changes` / `npx verified-changes`)

- Runs locally on your computer or CI. Your migrations, rules, schema, and results never leave the machine it runs on.
- It reports **counts and findings, not your data** — it does not exfiltrate row data.
- It contains **no telemetry, analytics, or "phone-home"** of any kind. It makes no network calls except the package manager download when you install it.
- Any files it writes (e.g. a results directory, a signed receipt) stay on your machine.

## The website (the Guard Score front door and badge)

- **The scanner runs in your browser.** When you paste schema or rules into the page, the analysis happens locally in the page's JavaScript. The pasted content is **not sent to our servers.**
- **We set no tracking or advertising cookies.** The page may store a single non-identifying preference (your light/dark theme choice) in your browser's local storage; it never leaves your browser and identifies nothing.
- **Hosting logs.** The site and the Guard Score badge image are served by our hosting provider ([HOSTING PROVIDER, e.g. Vercel]). Like any web host, the provider automatically records standard technical request logs (e.g. IP address, timestamp, user-agent, requested URL) to deliver the page and protect against abuse. We use these only for operating and securing the service, and they are subject to the provider's own privacy terms. We do not combine them with any other data to identify you.
- **The badge.** When a Guard Score badge is displayed (e.g. in a README), the viewer's browser requests the badge image from our host, which produces the same kind of standard request log described above. The badge encodes only a numeric score you chose to display; we do not track who views it.
- **Analytics.** We currently use **no third-party analytics.** [If you add analytics later, name the provider here and what it collects, and update the cookie section.]

## What we do NOT collect

- No accounts, names, passwords, or profiles.
- No database schemas, rules, source code, secrets, or scan results.
- No payment information (there is nothing to buy).
- No advertising identifiers; we run no ad networks.

## Third parties

- **Hosting/CDN:** [HOSTING PROVIDER] delivers the website and badge and keeps standard server logs (see above).
- **Package registry:** when you install the tool, [npm] delivers the package under its own terms.
- We do not share data with anyone else because we do not collect it.

## Your rights

Because we do not hold personal data about you, there is generally nothing for us to access, correct, or delete. If you believe our hosting logs contain your information and you want to ask about it, contact us at [CONTACT EMAIL]. Depending on where you live (e.g. EEA/UK under GDPR, California under CCPA/CPRA), you may have rights over personal data; we will honor applicable requests to the extent any such data exists.

## Children

The service is not directed to children under 13 (or the minimum age in your jurisdiction) and we do not knowingly collect their data.

## Changes

We may update this policy as the product evolves (in particular, when a hosted/account-based product launches, which will collect and store data and require a fuller policy). We will change the effective date above when we do.

## Contact

Questions about privacy: [CONTACT EMAIL].
