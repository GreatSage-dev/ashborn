# ASHBORN DESIGN SYSTEM (DESIGN.md)
*Synthesized and adapted from Kingsway (thedezignking.com) under the "Steal Like An Artist" protocol.*

---

## 1. The Core Aesthetic: Archival Editorial x Sovereign Monarch

Rather than the generic neon-purple dark mode that screams "AI template", Ashborn adopts Kingsway's **warm archival editorial aesthetic**: high-grade bone paper surfaces, deep midnight ink, crisp hairline gridlines, and burnished royal amber accents.

---

## 2. Design Tokens

### Color Palette

```css
:root {
  /* Surfaces */
  --surface: #fcfcfa;          /* Warm archival bone / eggshell */
  --surface-2: #f6f5f1;        /* Muted card surface */
  --surface-glass: rgba(252, 252, 250, 0.85);

  /* Inks */
  --ink: #17152e;              /* Deep midnight royal navy (headings & primary text) */
  --muted: #686579;            /* Refined slate-violet (body & subtext) */
  --line: #e7e5de;             /* Subtle hairline borders */

  /* Accents */
  --accent: #bc7c33;           /* Royal ochre / burnished gold amber */
  --accent-soft: #f3e8d4;      /* Soft amber tint (pills & highlights) */
  --accent-hover: #a26928;     /* Darkened amber for tactile button hover */

  /* Semantic Verifiers */
  --success: #2e7d32;          /* Verified receipt emerald */
  --success-soft: #e8f5e9;
  --danger: #c62828;           /* Blocked destructive route crimson */
  --danger-soft: #ffebee;
}
```

---

## 3. Typography Hierarchy

| Role | Font Family | Size / Weight | Tracking | Case |
|:---|:---|:---|:---|:---|
| **Kicker / Pill** | `IBM Plex Mono`, monospace | `11px` / `500` | `+0.25em` | `UPPERCASE` |
| **Hero Title** | `Hanken Grotesk`, sans-serif | `48px–56px` / `500` | `-0.02em` | Normal |
| **Section Title** | `Hanken Grotesk`, sans-serif | `36px–44px` / `500` | `-0.015em` | Normal |
| **Card Heading** | `Hanken Grotesk`, sans-serif | `20px` / `600` | `0` | Normal |
| **Body Text** | `Hanken Grotesk`, sans-serif | `16px` / `400` | `0` | Normal |
| **Code / Hash / Telemetry** | `IBM Plex Mono`, monospace | `13px` / `400` | `0` | Normal |

---

## 4. Iconic Visual Motifs (Stolen from Kingsway)

1. **The Central Dotted Spine:**
   - A vertical dotted amber hairline (`border-l-2 border-dotted border-[#bc7c33]/40`) that visually stitches sections together, punctuated by amber anchor nodes.
2. **Pill Buttons with Generous Padding:**
   - `rounded-full px-7 py-3 text-sm font-medium transition-all duration-200`
   - Primary: `--accent` background with white ink.
   - Secondary: `--ink` background with white ink.
   - Outline: `--line` border with `--ink` text.
3. **The Crown Glyph (Monarch Motif):**
   - Subtle geometric crown SVG icon at 20px, evoking Ashborn the Shadow Monarch.
4. **Asymmetric Narrative Layout:**
   - Muted, faded status-quo on the left vs. bold, illuminated sovereign mechanism on the right.
5. **Hairline Accordions:**
   - Clean horizontal divider borders with royal amber `+` toggle triggers.
