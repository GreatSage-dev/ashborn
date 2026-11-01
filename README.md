# ASHBORN

### The Shadow Monarch of Bug Hunting. AI probes and exploits are guilty until proven in the Blast Chamber.

[![License: MIT](https://img.shields.io/badge/license-MIT-black.svg)](LICENSE)
[![Tests: 5/5 Passing](https://img.shields.io/badge/tests-5%2F5%20passing-2FA46A.svg)](src/ashborn.test.ts)
[![Blast Chamber: Deterministic](https://img.shields.io/badge/verification-zero--mock%20chamber-5BA4FF.svg)](src/chamber/blast_chamber.ts)
[![HackerOne Ready](https://img.shields.io/badge/HackerOne-Submission%20Ready-E24329.svg)](src/reporter/markdown_receipt.ts)

[ **Architecture** ](#the-4-layer-architecture) · [ **Why It Exists** ](#the-crisis-in-bug-bounties) · [ **Watch It Refuse** ](#watch-it-refuse-the-anti-slop-proof) · [ **Verify in 5 Seconds** ](#verify-it-yourself-in-5-seconds) · [ **The Honest Table** ](#the-honest-table)

---

## The Crisis in Bug Bounties

A security triager opens HackerOne or Immunefi.

Forty AI-generated bug reports arrived overnight.  
Each report is three pages of beautiful prose written by ChatGPT.  
**Every single one is a hallucination.**

This is already breaking the crowdsourced security industry:
- On January 31, 2026, Daniel Stenberg suspended curl's seven-year bug bounty after valid reports plummeted below 5% under an avalanche of LLM hallucinations ([curl PR #20312](https://github.com/curl/curl/pull/20312)).
- Triage teams now issue immediate platform bans and reputation penalties to researchers who submit unverified AI guesses.

Amateurs ask an LLM to *"find bugs."*  
**Ashborn uses AI solely as a scout, and puts an unforgiving, deterministic Blast Chamber in front of every single claim.**

---

## The 4-Layer Architecture

```
Target Scope (URL / JS Bundle / API Spec)
   │
   ▼
[ LAYER 1: FAST SCOUT ]          Extracts unlinked internal /api/ routes from JS bundles in <10ms
   │
   ▼
[ LAYER 2: SHADOW STRIKER ]      Generates dual-token IDOR & JWT signature bypass payloads
   │
   ▼
[ LAYER 3: BLAST CHAMBER ]       Runs candidate curl in an isolated runner.
                                 RULE: If HTTP !== 200 or victim data did NOT leak ──► KILLED (<5ms)
   │
   ▼
[ LAYER 4: CRYPTO RECEIPT ]      Only confirmed leaks mint a SHA-256 seal & HackerOne Markdown report
```

---

## Watch It Refuse: The Anti-Slop Proof

The power of Ashborn is not how many bugs it claims to find; it is **how many fake claims it refuses to report.**

| Test Case | What Was Probed | What Happened | Verdict | Result |
|:----------|:----------------|:--------------|:--------|:-------|
| **Target A: Vulnerable IDOR** | Attacker token requesting `/api/v1/invoices/inv_991` | Server returned HTTP 200 containing victim SSN | `CONFIRMED_VULNERABILITY` | **Receipt Minted** (85.72 ms) |
| **Target B: Secure Profile** | Attacker token requesting `/api/v1/users/admin/profile` | Server returned HTTP 403 Forbidden | `REFUTED_SAFE` | **Silently Discarded** (0 false alarms) |
| **Target C: Static Asset** | Bundle contains `/static/logo.png` | Scout filters out non-API assets | `FILTERED_OUT` | **Zero Requests Sent** (0 ms) |
| **Target D: Missing Secret** | Server returned HTTP 200 without private data match | Data assertion failed | `REFUTED_SAFE` | **Silently Discarded** (1.2 ms) |

---

## 15-Second Split Screen

| The Naive AI Spammer (Status Quo) | Ashborn (The Shadow Monarch) |
|:-----------------------------------|:-----------------------------|
| Asks an LLM: *"Does this code have a bug?"* | Uses AI only to parse routes; code never grades itself. |
| Submits 50 speculative reports to HackerOne. | Submits **zero** reports unless verified in a sandbox. |
| Triagers waste 3 hours reading hallucinated fluff. | Triagers receive a 1-line runnable `curl` and a SHA-256 seal. |
| **Outcome: Account banned for AI spam ($0 earned).** | **Outcome: Instantly triaged and paid.** |

---

## The Golden Law (King's Court Heritage)

> **"AI understands the world. Deterministic code decides who goes where."**

- **What AI Does:** Ingests client-side JavaScript bundles and identifies parameter boundaries (`user_id`, `invoice_id`).
- **What Deterministic Code Does:** Transmits the HTTP packet, verifies the response byte differential, and asserts that the private fingerprint was extracted.
- **The Absolute Mandate:** An LLM is never allowed to say a bug exists. Only a live execution in the Blast Chamber holding a clean exit code and verified payload can mint a receipt.

---

## Verify It Yourself in 5 Seconds

```bash
git clone <repo-url>
cd "Bug bounty"

# 1. Run all 5 deterministic system tests (Zero-Mock)
npm test

# 2. Run the live end-to-end CLI demonstration
npm run demo
```

---

## The Honest Table

**Real, and checked by runnable test code (`npm test` passes with code 0)**
- Fast regex-based client-side JavaScript bundle route extraction (`BundleExtractor`).
- Dual-Token cross-tenant probe generation (`IdorStriker`).
- JWT `alg: none` and signature-stripping mutator (`JwtMutator`).
- Ephemeral Blast Chamber with timeout control, WAF detection, and byte-leak verification (`BlastChamber`).
- Cryptographic SHA-256 sealed receipt and HackerOne Markdown report generation (`ReportGenerator`).

**Next Roadmap Horizons**
- Headless Chromium runner via Playwright for DOM-based XSS verification.
- Out-of-Band (OAST) listener integration for Blind SSRF verification.
- Direct HackerOne / Bugcrowd API submission pipe.

---

## Heritage

Named after **Ashborn**, the Shadow Monarch from *Solo Leveling*—the master of the shadow soldiers who turns the battlefield into his domain.

MIT License © 2026 Ashborn Research
