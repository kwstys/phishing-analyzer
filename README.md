# PhishScope

An offline-first phishing email analyzer. Feed it a suspicious email and get back a
report with a risk score, the evidence behind each finding, and a list of IOCs.

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

[中文说明](README.zh-CN.md)

**Early stage. The repo is scaffolding right now — it can't analyze anything yet.**

## The problem

Triaging a reported phishing email by hand means reading the headers, checking whether
the sender really is who they claim to be, and judging the links and attachments.
That's 5–15 minutes per email, and it depends a lot on how experienced the analyst is.

## Goals

- Parse `.eml` files and pasted raw email
- Look for header forgery: display name impersonating a brand, Reply-To not matching From…
- Read `Authentication-Results` and report what SPF / DKIM / DMARC actually said
- Compare link text against the real href, the classic phishing giveaway
- Check attachments: extension vs real file type, embedded macros

The goal is to end up with a 0–100 score and the evidence for every point deducted,
instead of dumping raw signals on the user to interpret.

Chinese-language phishing is a big part of the target: Chinese lure phrases, Chinese
brand impersonation, Chinese free-mail domains. Most existing tools are English-only.

## Design constraints

- **Offline by default.** No email content leaves the machine.
- **Attachments are never executed or opened.** Static, byte-level inspection only.

## Usage

Not implemented yet. The intended interface:

```
phishscope analyze suspicious.eml
phishscope analyze --stdin
```

## Status

- [x] Repo and tooling
- [ ] Email parsing
- [ ] Detection rules
- [ ] Scoring and reports

## Disclaimer

A triage aid, not an oracle. The final call is a human's. Only analyze email you are
authorised to handle.

## License

[MIT](LICENSE) © 2026 kwstys
