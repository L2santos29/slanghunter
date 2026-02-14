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
#  DISPLAY HELPERS — make the console output shine
# ═══════════════════════════════════════════════════════════════

# Terminal widths and dividers.
W = 64
THIN = "─" * W
DOUBLE = "═" * W


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


def typing_effect(text: str, delay: float = 0.01) -> None:
    """Simulate character-by-character output for drama."""
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def listing_card(data: dict) -> None:
    """Print a simulated marketplace listing card."""
    print(f"  ┌{'─' * (W - 4)}┐")
    print(f"  │ {'ID:':<10}{data['listing_id']:<{W - 16}}│")
    print(f"  │ {'Seller:':<10}{data['seller']:<{W - 16}}│")

    # Title may need wrapping.
    title = data["title"]
    print(f"  │ {'Title:':<10}{title[:W - 16]:<{W - 16}}│")

    # Price line.
    price_str = f"${data['price']:,.2f}"
    print(f"  │ {'Price:':<10}{price_str:<{W - 16}}│")
    print(f"  │ {'Category:':<10}{data['category']:<{W - 16}}│")
    print(f"  │{' ' * (W - 4)}│")

    # Description — word-wrap to fit the card.
    desc = data["description"]
    max_line = W - 8
    words = desc.split()
    line = ""
    for word in words:
        if len(line) + len(word) + 1 <= max_line:
            line = f"{line} {word}" if line else word
        else:
            print(f"  │  {line:<{W - 6}}│")
            line = word
    if line:
        print(f"  │  {line:<{W - 6}}│")

    print(f"  └{'─' * (W - 4)}┘")


def result_summary(
    case_num: int,
    data: dict,
    verdict: dict,
    level_emoji: str,
    level_label: str,
    level_action: str,
) -> None:
    """Print a compact result summary line."""
    score_pct = int(verdict["risk_score"] * 100)
    bar_len = 20
    filled = int(bar_len * verdict["risk_score"])
    bar = "█" * filled + "░" * (bar_len - filled)
    n_flags = len(verdict["flags"])
    cats = (
        ", ".join(c.upper() for c in verdict["matched_categories"])
        or "—"
    )

    print()
    print(f"  {level_emoji}  VERDICT: {level_label}")
    print(f"     Score    : [{bar}] {score_pct}%")
    print(f"     Flags    : {n_flags} indicator{'s' if n_flags != 1 else ''}")
    print(f"     Category : {cats}")
    print(f"     Action   : {level_action}")


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
        delay=0.015,
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
        delay=0.015,
    )
    typing_effect(
        f"  📨 Incoming feed: {len(MOCK_FEED)} listings queued.\n",
        delay=0.015,
    )

    time.sleep(0.3)

    # ── Per-listing analysis ─────────────────────────────────
    verdicts: list[dict] = []

    for i, data in enumerate(MOCK_FEED):
        label = CASE_LABELS[i]
        section(f"📦  {label}")
        print()

        # Show the raw listing card.
        listing_card(data)
        print()

        # Build the full text the engine will see.
        full_text = f"{data['title']} {data['description']}"

        typing_effect("  🔍 Scanning...", delay=0.02)
        time.sleep(0.2)

        # Run the engine.
        verdict = hunter.analyze(full_text, data["price"])
        level = hunter.classify_risk(verdict["risk_score"])

        result_summary(
            i + 1, data, verdict,
            level.emoji, level.label, level.action,
        )

        # Show the full detailed report.
        print()
        report = hunter.generate_report(full_text, data["price"])
        print(report)
        print()

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
