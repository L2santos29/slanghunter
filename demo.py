#!/usr/bin/env python3
"""
demo.py — SlangHunter Live Simulation.

Simulates a real-time feed of incoming Mercari listings,
processes each one through the SlangHunter engine, and
renders a visual dashboard in the console.

Four listings are carefully designed to cover 100 % of the
business logic:

    1. CONTROL  (🟢 SAFE)     — Legitimate product, normal price.
    2. SLANG    (🔴 CRITICAL) — Illicit product using known drug slang.
    3. ANOMALY  (🟡 WARNING)  — Common product, suspiciously low price
                                 combined with laundering language.
    4. FRAUD    (🔴 CRITICAL) — High-value brand with bait-and-switch
                                 (surikae) counterfeit indicators.

Run:
    python demo.py        (from project root)
    python -m demo        (same effect)

Author: Legal Engineer
"""

import sys
import time

# ── Ensure the project root is on sys.path ──────────────────
# This lets the script import `src` whether invoked from the
# project root or from an outer directory.
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.slanghunter import SlangHunter  # noqa: E402


# ═══════════════════════════════════════════════════════════════
#  MOCK DATA — Four listings that cover every detection pathway
# ═══════════════════════════════════════════════════════════════

MOCK_FEED: list[dict] = [
    # ── Case 1: Control (Safe) ──────────────────────────────
    # A perfectly legitimate listing.  Tests that the engine
    # does NOT false-positive on ordinary products/prices.
    # Expected: 🟢 SAFE — score ≈ 0.0, no flags, no categories.
    {
        "listing_id": "MER-2026-00417",
        "seller": "tokyovintage_shop",
        "title": "Vintage Ceramic Tea Set — Arita Porcelain",
        "description": (
            "Beautiful 5-piece Arita porcelain tea set from the "
            "1970s. Hand-painted floral pattern, excellent "
            "condition with no chips or cracks. Includes teapot, "
            "2 cups, sugar bowl, and serving tray. Perfect for "
            "collectors or daily use. Shipping via Yamato."
        ),
        "price": 85.00,
        "category": "Home & Kitchen",
    },

    # ── Case 2: Slang — Drugs ──────────────────────────────
    # Exercises: keyword matching ("lean", "scripts"), pattern
    # matching ("p3rcs", "f3nt", 🍃💨), and price context
    # ($35 falls inside the drug threshold $0–$80).
    # Expected: 🔴 CRITICAL — high score, multiple flags, drugs.
    {
        "listing_id": "MER-2026-01893",
        "seller": "rxplug_verified",
        "title": "Herbal Supplement Pack 🍃💨",
        "description": (
            "Premium p3rcs and lean combo 💊 "
            "real pharma scripts only, straight from the plug. "
            "f3nt-free guaranteed 🍃💨 "
            "DM for menu — bulk discount available. "
            "Fast shipping, discreet packaging."
        ),
        "price": 35.00,
        "category": "Health & Wellness",
    },

    # ── Case 3: Anomaly — Money Laundering ─────────────────
    # Exercises: keyword matching ("cash app", "gift card",
    # "method"), pattern matching ("m0ney fl1p", "g1ft c4rd",
    # 💸💰), and price context ($15 is in the $0–$50 ML range).
    # A seemingly innocent listing title hides the real offer
    # in the description — classic evasion tactic.
    # Expected: 🔴 CRITICAL — laundering flags + price context.
    {
        "listing_id": "MER-2026-03201",
        "seller": "quick_flipz99",
        "title": "Digital Financial Guide 💸",
        "description": (
            "💸💰 PROVEN m0ney fl1p method! Turn $50 into $500 "
            "via cash app in 24h — guaranteed returns. "
            "Also selling g1ft c4rds (iTunes, Steam, Amazon) "
            "at 70 %% off face value. "
            "DM for proof. Serious buyers only. 🏦"
        ),
        "price": 15.00,
        "category": "Books & Guides",
    },

    # ── Case 4: Fraud — Surikae (Bait-and-Switch) ─────────
    # Exercises: keyword matching ("1:1", "replica", "rolex",
    # "gucci", "comes in original box", "factory direct",
    # "guangzhou"), pattern matching ("1:1", 🔥, ⌚, 👜),
    # and price context ($175 falls in the $30–$250 range).
    # Expected: 🔴 CRITICAL — surikae flags + price context.
    {
        "listing_id": "MER-2026-05742",
        "seller": "luxdeals_hk",
        "title": "Premium Designer Watch & Wallet Set ⌚👜",
        "description": (
            "Rolex Submariner Date — 1:1 replica, AAA quality, "
            "same as original. Comes in original box with papers. "
            "Also including Gucci Marmont wallet, "
            "factory direct from Guangzhou. "
            "DM for real pics 🔥⌚👜"
        ),
        "price": 175.00,
        "category": "Luxury & Accessories",
    },
]


# ═══════════════════════════════════════════════════════════════
#  DISPLAY HELPERS — Auditor-grade console UX
# ═══════════════════════════════════════════════════════════════
#
#  Each listing flows through three visual phases:
#
#      ┌─ INPUT ─────────────────────────────────────┐
#      │  Title, Description, Price                  │
#      └─────────────────────────────────────────────┘
#               ▼
#      ┌─ PROCESSING ────────────────────────────────┐
#      │  Step-by-step engine pipeline animation     │
#      └─────────────────────────────────────────────┘
#               ▼
#      ┌─ VERDICT ───────────────────────────────────┐
#      │  🔴 BLOCKED / 🟡 REVIEW / 🟢 APPROVED      │
#      └─────────────────────────────────────────────┘
#

# Terminal widths and dividers.
W = 64
THIN = "─" * W
HEAVY = "━" * W
BOX_INNER = W - 6  # usable chars inside │ ... │


def banner() -> None:
    """Print the simulation banner."""
    print()
    print("╔" + "═" * (W - 2) + "╗")
    print(
        "║"
        + "🏪  MERCARI LISTING FEED — LIVE SIMULATION".center(W - 2)
        + "║"
    )
    print(
        "║"
        + "Powered by SlangHunter v0.1.0".center(W - 2)
        + "║"
    )
    print("╚" + "═" * (W - 2) + "╝")
    print()


def section(title: str) -> None:
    """Print a section header."""
    print(THIN)
    print(f"  {title}")
    print(THIN)


def typing_effect(text: str, delay: float = 0.008) -> None:
    """Simulate character-by-character output for drama."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def step(icon: str, message: str, result: str = "",
         delay: float = 0.12) -> None:
    """Print an animated processing step.

    Renders as:  ``  ├─ 🔤 Message ··········· result``

    Args:
        icon: A single emoji for the step.
        message: What the engine is doing.
        result: Short outcome (e.g. "3 found", "in range").
        delay: Pause after printing (simulates work).
    """
    prefix = f"  ├─ {icon} {message} "
    dots = "·" * max(1, W - len(prefix) - len(result) - 2)
    typing_effect(f"{prefix}{dots} {result}", delay=0.005)
    time.sleep(delay)


def word_wrap(text: str, width: int) -> list[str]:
    """Break *text* into lines that fit within *width* chars."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if current and len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(current)
    return lines


# ── PHASE 1 — INPUT ─────────────────────────────────────────

def phase_input(data: dict) -> None:
    """Render the INPUT phase: show what the auditor is reviewing.

    Displays the raw listing exactly as a marketplace moderator
    would see it — title, seller, category, price, and the full
    description wrapped inside a visual card.
    """
    print()
    print(f"  ┌─ 📥 INPUT {'─' * (W - 16)}┐")
    print(f"  │{'':<{W - 4}}│")
    print(f"  │  {'Title:':<12}"
          f"{data['title'][:BOX_INNER - 12]:<{BOX_INNER - 12}}│")
    print(f"  │  {'Seller:':<12}"
          f"{data['seller']:<{BOX_INNER - 12}}│")
    print(f"  │  {'Category:':<12}"
          f"{data['category']:<{BOX_INNER - 12}}│")
    price_str = f"${data['price']:,.2f}"
    print(f"  │  {'Price:':<12}"
          f"{price_str:<{BOX_INNER - 12}}│")
    print(f"  │{'':<{W - 4}}│")

    # Description — word-wrap inside the card.
    print(f"  │  {'Description:':<{BOX_INNER}}│")
    for ln in word_wrap(data["description"], BOX_INNER - 2):
        print(f"  │    {ln:<{BOX_INNER - 2}}│")

    print(f"  │{'':<{W - 4}}│")
    print(f"  └{'─' * (W - 4)}┘")
    print()


# ── PHASE 2 — PROCESSING ────────────────────────────────────

def phase_processing(
    data: dict,
    verdict: dict,
    hunter: SlangHunter,
) -> None:
    """Render the PROCESSING phase: animated engine pipeline.

    Shows each internal step the engine performed, with counts
    extracted from the already-computed *verdict* dict.  The
    animation is cosmetic — analysis was already done — but it
    gives the auditor a step-by-step understanding of *how* the
    engine reached its conclusion.
    """
    # Parse verdict flags to count kw / pat / price per category.
    kw_flags = [f for f in verdict["flags"] if ":kw:" in f]
    pat_flags = [f for f in verdict["flags"] if ":pat:" in f]
    price_flags = [f for f in verdict["flags"]
                   if f.endswith(":price_context")]

    # Get totals from the knowledge base.
    cats = hunter.get_categories()
    total_kw = sum(
        hunter.get_category_info(c)["keyword_count"] for c in cats
    )
    total_pat = sum(
        hunter.get_category_info(c)["pattern_count"] for c in cats
    )

    print(f"  ┌─ ⚙️  PROCESSING {'─' * (W - 20)}┐")
    print(f"  │{'':<{W - 4}}│")

    # Step 1: Normalize.
    step("🔤", "Normalizing text",
         "lowercase + collapse whitespace")

    # Step 2: Keyword scan.
    kw_result = (
        f"{len(kw_flags)} hit{'s' if len(kw_flags) != 1 else ''}"
        if kw_flags else "clean"
    )
    step("🔑", f"Scanning {total_kw} keywords",
         kw_result)

    # Step 3: Pattern scan.
    pat_result = (
        f"{len(pat_flags)} hit{'s' if len(pat_flags) != 1 else ''}"
        if pat_flags else "clean"
    )
    step("🧬", f"Matching {total_pat} regex patterns",
         pat_result)

    # Step 4: Price context.
    price_str = f"${data['price']:,.2f}"
    price_result = (
        "⚠ in suspicious range" if price_flags
        else "✓ normal"
    )
    step("💲", f"Checking price context ({price_str})",
         price_result)

    # Step 5: Score.
    score_pct = int(verdict["risk_score"] * 100)
    step("📊", "Calculating risk score",
         f"{score_pct}%")

    print(f"  │{'':<{W - 4}}│")
    print(f"  └{'─' * (W - 4)}┘")
    print()


# ── PHASE 3 — VERDICT ───────────────────────────────────────

def phase_verdict(
    verdict: dict,
    level_emoji: str,
    level_label: str,
    level_action: str,
) -> None:
    """Render the VERDICT phase: the auditor's decision card.

    A clean, scannable result showing:
      - Traffic-light emoji + label
      - Risk score bar
      - Matched flags (if any)
      - Legal reasoning (if any)
      - Recommended action
    """
    score_pct = int(verdict["risk_score"] * 100)
    bar_len = 30
    filled = int(bar_len * verdict["risk_score"])
    bar = "█" * filled + "░" * (bar_len - filled)
    n_flags = len(verdict["flags"])
    cats = (
        ", ".join(c.upper() for c in verdict["matched_categories"])
        or "—"
    )

    # Verdict header — strong visual break.
    print(HEAVY)
    if level_label == "CRITICAL":
        verdict_word = "🚫 BLOCKED"
    elif level_label == "WARNING":
        verdict_word = "⚠️  REVIEW"
    else:
        verdict_word = "✅ APPROVED"
    header = f"{level_emoji}  VERDICT: {verdict_word}"
    print(f"  {header}")
    print(HEAVY)

    # Score bar.
    print(f"  Risk Score : [{bar}] {score_pct}%")
    print(f"  Risk Level : {level_emoji}  {level_label}")
    print(f"  Flags      : {n_flags} indicator"
          f"{'s' if n_flags != 1 else ''}")
    print(f"  Categories : {cats}")
    print()

    # Flags detail (if any).
    if verdict["flags"]:
        print(f"  ┌─ ⚑ FLAGS {'─' * (W - 15)}┐")
        for flag in verdict["flags"]:
            print(f"  │  ⚑  {flag:<{BOX_INNER - 3}}│")
        print(f"  └{'─' * (W - 4)}┘")
        print()

    # Reasoning / traceability (if any).
    reasoning_lines = verdict["reasoning"].split("\n")
    print(f"  ┌─ 📜 REASONING {'─' * (W - 19)}┐")
    for rline in reasoning_lines:
        # Truncate very long reasoning lines.
        display = rline[:BOX_INNER] if len(rline) > BOX_INNER else rline
        print(f"  │  {display:<{BOX_INNER}}│")
    print(f"  └{'─' * (W - 4)}┘")
    print()

    # Action recommendation — the bottom line.
    print(f"  👉 ACTION: {level_action}")
    print()


# ═══════════════════════════════════════════════════════════════
#  MAIN SIMULATION LOOP
# ═══════════════════════════════════════════════════════════════

CASE_LABELS = [
    "CASE 1 — Control (Legitimate Product)",
    "CASE 2 — Slang Detection (Drugs)",
    "CASE 3 — Price Anomaly (Money Laundering)",
    "CASE 4 — Bait-and-Switch Fraud (Surikae)",
]


def run_simulation() -> None:
    """Execute the full 4-case simulation and print results."""
    hunter = SlangHunter()

    banner()

    typing_effect(
        "  ⏳ Initializing SlangHunter engine... done.",
        delay=0.012,
    )
    cats = hunter.get_categories()
    total_kw = 0
    total_pat = 0
    for cat in cats:
        info = hunter.get_category_info(cat)
        total_kw += info["keyword_count"]
        total_pat += info["pattern_count"]

    typing_effect(
        f"  📚 Knowledge base loaded: {len(cats)} categories, "
        f"{total_kw} keywords, {total_pat} patterns.",
        delay=0.012,
    )
    typing_effect(
        f"  📨 Incoming feed: {len(MOCK_FEED)} listings queued.\n",
        delay=0.012,
    )

    time.sleep(0.3)

    # ── Per-listing 3-phase pipeline ─────────────────────────
    verdicts: list[dict] = []

    for i, data in enumerate(MOCK_FEED):
        label = CASE_LABELS[i]
        section(f"📦  {label}")

        # Build the full text the engine will see.
        full_text = f"{data['title']} {data['description']}"

        # Run the engine FIRST (results drive the animation).
        verdict = hunter.analyze(full_text, data["price"])
        level = hunter.classify_risk(verdict["risk_score"])

        # ── PHASE 1: INPUT ──────────────────────────────────
        phase_input(data)

        # ── PHASE 2: PROCESSING ─────────────────────────────
        phase_processing(data, verdict, hunter)

        # ── PHASE 3: VERDICT ────────────────────────────────
        phase_verdict(
            verdict,
            level.emoji, level.label, level.action,
        )

        verdicts.append(
            {"data": data, "verdict": verdict, "level": level}
        )

    # ── Dashboard Summary ────────────────────────────────────
    section("📊  SIMULATION DASHBOARD")
    print()

    # Count verdicts by level.
    counts = {"CRITICAL": 0, "WARNING": 0, "SAFE": 0}
    for v in verdicts:
        counts[v["level"].label] += 1

    print(
        f"  🔴 CRITICAL : {counts['CRITICAL']}  │  "
        f"🟡 WARNING : {counts['WARNING']}  │  "
        f"🟢 SAFE : {counts['SAFE']}"
    )
    print(
        f"  Total processed : {len(verdicts)} listings"
    )
    print()

    # Per-case one-liner table.
    print(f"  {'#':<4} {'Listing ID':<18} {'Score':>6}  "
          f"{'Level':<10} {'Categories'}")
    print(f"  {'─' * 4} {'─' * 18} {'─' * 6}  {'─' * 10} {'─' * 20}")
    for i, v in enumerate(verdicts, 1):
        lid = v["data"]["listing_id"]
        score_pct = int(v["verdict"]["risk_score"] * 100)
        lvl = f"{v['level'].emoji} {v['level'].label}"
        cats_str = (
            ", ".join(
                c.upper()
                for c in v["verdict"]["matched_categories"]
            ) or "—"
        )
        print(f"  {i:<4} {lid:<18} {score_pct:>5}%  {lvl:<10} {cats_str}")

    print()

    # ── Engine statistics ────────────────────────────────────
    section("🔧  ENGINE STATISTICS")
    print()
    for cat in cats:
        info = hunter.get_category_info(cat)
        statute = info["legal_reference"]["statute"]
        print(
            f"  {cat.upper():<20s}  "
            f"Keywords: {info['keyword_count']:>3d}  "
            f"Patterns: {info['pattern_count']:>3d}  "
            f"Law: {statute}"
        )
    print(
        f"  {'TOTAL':<20s}  "
        f"Keywords: {total_kw:>3d}  "
        f"Patterns: {total_pat:>3d}"
    )
    print()

    # ── Footer ───────────────────────────────────────────────
    print("╔" + "═" * (W - 2) + "╗")
    print(
        "║"
        + "Simulation complete — 4/4 cases processed".center(W - 2)
        + "║"
    )
    print(
        "║"
        + "SlangHunter v0.1.0 · Legal Engineer © 2026".center(W - 2)
        + "║"
    )
    print("╚" + "═" * (W - 2) + "╝")
    print()


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_simulation()
