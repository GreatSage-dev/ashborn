# ASHBORN® DESIGN SYSTEM (DESIGN.md)
### Swiss Brutalist Editorial & High-Precision Tactical Workbench
**Reference Calibration:** Neiden® (`neiden.framer.media`)

---

## 1. Visual Identity & Core Direction
Ashborn combines two distinct but unified registers:
1. **Persuade Register (Landing Page):** High-contrast **Swiss/Brutalist Editorial** inspired by Neiden®. Alternating full-bleed bands of deep obsidian (`#111111`), editorial alabaster paper (`#f4f4f1`), and electric crimson (`#f02b42`). Defined by exposed `1px` architectural grid hairlines, corner intersection nodes (`■`), bilingual English/Japanese section kickers (`[ AB® — SECTION / 日本語 ]`), massive edge-to-edge geometric display typography (`ashborn®`), diagonal handwritten crimson script overlays (*"less noise. pure proof."*), and chamfered (`45°` top-left cut) high-velocity editorial photography.
2. **Operate Register (The Cockpit):** A high-density, zero-slop **Tactical Security Workbench**. Strict categorical hierarchy (`01 Recon & Intercept`, `02 Offensive Strikers`, `03 Intelligence & Proofs`), tabular monospace data alignment, and an integrated horizontal telemetry ledger (eliminating generic 4-card stat rows and pastel icon boxes).

---

## 2. Color Tokens (`:root`)

| Token | Value | Role |
| :--- | :--- | :--- |
| `--bg-obsidian` | `#111111` | Primary dark editorial canvas & sidebar shell |
| `--bg-obsidian-2` | `#181818` | Elevated dark module surface |
| `--bg-obsidian-3` | `#222222` | Interactive dark hover / input surface |
| `--bg-paper` | `#f4f4f1` | Alabaster Swiss paper band & Cockpit main canvas |
| `--bg-surface` | `#ffffff` | Crisp white card, header, & active workbench surface |
| `--bg-subtle` | `#eaeae5` | Secondary recessed surface on light bands |
| `--crimson` | `#f02b42` | Signature electric crimson (script accents, `▶▶▶▶` markers, `01.` badges) |
| `--crimson-soft` | `rgba(240, 43, 66, 0.10)` | Subtle crimson tint for active states & alerts |
| `--ink` | `#0d0d0d` | Primary typography on light surfaces |
| `--ink-secondary` | `#4a4a46` | Body copy & descriptions on light surfaces |
| `--muted` | `#787872` | Captions, kickers, & metadata on light surfaces |
| `--ink-light` | `#ffffff` | Primary typography on obsidian surfaces |
| `--ink-light-sec` | `rgba(255, 255, 255, 0.70)` | Secondary body copy on obsidian surfaces |
| `--ink-light-muted` | `rgba(255, 255, 255, 0.44)` | Muted metadata & Japanese sub-labels on obsidian |
| `--line` | `rgba(13, 13, 13, 0.10)` | `1px` Swiss architectural grid hairline (light mode) |
| `--line-strong` | `rgba(13, 13, 13, 0.20)` | Emphasized border (light mode) |
| `--line-dark` | `rgba(255, 255, 255, 0.11)` | `1px` Swiss architectural grid hairline (dark mode) |
| `--success` | `#0d9668` | Verified safe / connected CDP telemetry |
| `--danger` | `#e11d48` | Confirmed vulnerability / governor block |

---

## 3. Typography & Hierarchy

* **Display & Wordmark (`--font-display`):** `'Syne'`, `'Plus Jakarta Sans'`, sans-serif (`700`–`800` weight, `-0.04em` tracking, `0.92` line-height).
* **UI & Editorial Body (`--font-body`):** `'DM Sans'`, system-ui, sans-serif (`400`, `500`, `600`, `700`).
* **Signature Handwritten Script (`--font-script`):** `'Caveat'`, cursive (`600` weight, `--crimson` `#f02b42`, layered diagonally across hero and footer wordmarks).
* **Technical Telemetry (`--font-mono`):** `'JetBrains Mono'`, `'IBM Plex Mono'`, monospace (`font-variant-numeric: tabular-nums` mandatory on all counters, latencies, hashes, and HTTP status codes).

---

## 4. Layout & Motion Rules
1. **Exposed Hairline Grid:** Outer container framed by `1px` vertical guide rails (`max-width: 1360px`) with `5px × 5px` square intersection nodes (`■`).
2. **Chamfered Editorial Photography:** Wide horizontal editorial images use `clip-path: polygon(44px 0, 100% 0, 100% 100%, 0 100%, 0 44px)` with high-contrast monochrome/motion-blur grading.
3. **Zero AI-Slop Mandate:** No 4-cards stacked side-by-side, no purple/blue neon gradients, no pastel icon squares, no `transition: all`.
4. **Tactile Physics:** Custom easing `--ease-out: cubic-bezier(0.23, 1, 0.32, 1)`, button press feedback `:active { transform: scale(0.97) }`, and full `prefers-reduced-motion: reduce` compliance.
