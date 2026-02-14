"""
__main__.py — SlangHunter CLI Demo.

Run with:
    python -m src

This module demonstrates the engine against a curated set
of test listings that cover all three crime categories,
evasion tactics, and edge cases.

Designed to be shown to hiring managers, compliance teams,
or in a portfolio demo.  Every verdict is self-explanatory.
"""

from src.slanghunter import SlangHunter

# ── Demo listings ────────────────────────────────────────────
# Each tuple is (description, text, price).
# They progress from clean → suspicious → critical to show
# the full range of the traffic-light system.

DEMO_LISTINGS: list[tuple[str, str, float | None]] = [
    # ── 🟢 SAFE ────────────────────────────────────────────
    (
        "Clean listing — ordinary product",
        "Vintage wooden bookshelf, great condition. "
        "Pick up in downtown area.",
        45.00,
    ),
    (
        "Clean listing — normal electronics",
        "Samsung Galaxy S24 Ultra, factory unlocked, "
        "256GB. Includes charger and case.",
        650.00,
    ),

    # ── 🟡 WARNING ─────────────────────────────────────────
    (
        "Drug slang evasion — 'p3rcs' (Percocet)",
        "got them p3rcs 💊 real pharma hmu",
        None,
    ),
    (
        "Counterfeit sneakers — surikae",
        "Jordan 1 Retro High OG - 1:1 top quality, "
        "comes in original box, DM for real pics 🔥👟",
        65.00,
    ),

    # ── 🔴 CRITICAL ────────────────────────────────────────
    (
        "Drug trafficking — multiple keywords + price",
        "Purple lean + xanax combo pack. "
        "Scripts straight from the plug 💨🍃",
        40.00,
    ),
    (
        "Money laundering — flip + gift cards + evasion",
        "💸 m0ney fl1p method! Turn $50 into $500 "
        "via ca$h app. Also selling g1ft c4rds 💰",
        10.00,
    ),
    (
        "Multi-category — drugs + money laundering",
        "Selling p3rcs and f3nt, also do cash flips "
        "on cashapp. Bulk pricing available. DM only.",
        25.00,
    ),
    (
        "Surikae — counterfeit luxury goods",
        "Rolex Submariner r3plica - AAA quality, "
        "same as original. Gucci inspired wallet too. "
        "Factory direct from Guangzhou ⌚👜",
        150.00,
    ),
]


def main() -> None:
    """Run the SlangHunter demo against all test listings."""
    hunter = SlangHunter()

    # ── Banner ───────────────────────────────────────────────
    print()
    print("╔" + "═" * 58 + "╗")
    print("║" + "  🔍 SLANGHUNTER — Semantic Risk Detection Demo".center(58) + "║")
    print("║" + "  Trust & Safety Automation Prototype".center(58) + "║")
    print("╚" + "═" * 58 + "╝")
    print()

    for i, (description, text, price) in enumerate(DEMO_LISTINGS, 1):
        print(f"  ▸ Demo Case #{i}: {description}")
        print()
        report = hunter.generate_report(text, price)
        print(report)
        print()

    # ── Summary stats ────────────────────────────────────────
    print("─" * 60)
    print("  📊 ENGINE STATISTICS")
    print("─" * 60)
    cats = hunter.get_categories()
    total_kw = 0
    total_pat = 0
    for cat in cats:
        info = hunter.get_category_info(cat)
        total_kw += info["keyword_count"]
        total_pat += info["pattern_count"]
        print(
            f"  {cat.upper():20s}  "
            f"Keywords: {info['keyword_count']:>3d}  "
            f"Patterns: {info['pattern_count']:>3d}  "
            f"Law: {info['legal_reference']['statute']}"
        )
    print(f"  {'TOTAL':20s}  Keywords: {total_kw:>3d}  Patterns: {total_pat:>3d}")
    print("─" * 60)
    print()


if __name__ == "__main__":
    main()
