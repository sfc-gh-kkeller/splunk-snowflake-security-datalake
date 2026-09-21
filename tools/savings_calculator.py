#!/usr/bin/env python3
"""
Splunk + Snowflake Savings Calculator

Interactive CLI tool that estimates cost savings from a hybrid
Splunk + Snowflake security data lake architecture.

Usage:
    python tools/savings_calculator.py
    python tools/savings_calculator.py --total 100   # shortcut: 100 GB/day total
"""

import argparse
import sys

# Default pricing (per GB/day/month for Splunk, per TB/month for Snowflake)
SPLUNK_COST_PER_GB_DAY_MONTH = 150  # ~$150/GB/day ingested per month
SNOWFLAKE_STORAGE_PER_TB_MONTH = 40  # $40/TB/month (on-demand)
SNOWFLAKE_COMPUTE_MONTHLY = 200  # estimated compute for queries

DATA_SOURCES = [
    # (name, default_gb_per_day, routes_to_splunk, description)
    ("Firewall / IDS / IPS", 30, True, "Critical for real-time attack detection"),
    ("EDR (CrowdStrike, etc.)", 15, True, "Endpoint threat detection"),
    ("Authentication (AD/Okta)", 5, True, "Identity-based attack detection"),
    ("Cloud Audit (AWS/Azure/GCP)", 10, True, "Cloud security monitoring"),
    ("Email Security", 5, True, "Phishing detection"),
    ("Web / Proxy Logs", 25, False, "High volume — investigation only"),
    ("Application Logs", 10, False, "Troubleshooting, not real-time SIEM"),
    ("DNS Logs", 5, False, "Threat hunting, not real-time"),
    ("NetFlow / PCAP Metadata", 10, False, "Forensics only"),
]


def prompt_volumes(defaults_only=False):
    """Prompt user for daily ingest volumes per source."""
    volumes = []
    if not defaults_only:
        print("\nEnter daily ingest volume per source (GB/day).")
        print("Press Enter to accept the default shown in brackets.\n")

    for name, default_gb, to_splunk, desc in DATA_SOURCES:
        if defaults_only:
            gb = default_gb
        else:
            try:
                raw = input(f"  {name:<30} [{default_gb:>3} GB/day]: ").strip()
                gb = float(raw) if raw else default_gb
            except (ValueError, EOFError):
                gb = default_gb
        volumes.append((name, gb, to_splunk, desc))
    return volumes


def calculate_savings(volumes, splunk_rate=SPLUNK_COST_PER_GB_DAY_MONTH,
                      sf_storage_rate=SNOWFLAKE_STORAGE_PER_TB_MONTH,
                      sf_compute=SNOWFLAKE_COMPUTE_MONTHLY):
    """Calculate monthly costs for all-Splunk vs hybrid architecture."""
    total_gb = sum(v[1] for v in volumes)
    splunk_gb = sum(v[1] for v in volumes if v[2])
    snowflake_only_gb = total_gb - splunk_gb

    # All-Splunk scenario
    all_splunk_monthly = total_gb * splunk_rate

    # Hybrid scenario
    hybrid_splunk_monthly = splunk_gb * splunk_rate
    hybrid_sf_storage = (total_gb * 30 / 1000) * sf_storage_rate  # daily * 30 days, convert to TB
    hybrid_sf_compute = sf_compute
    hybrid_total = hybrid_splunk_monthly + hybrid_sf_storage + hybrid_sf_compute

    savings_monthly = all_splunk_monthly - hybrid_total
    savings_pct = (savings_monthly / all_splunk_monthly * 100) if all_splunk_monthly > 0 else 0

    return {
        "total_gb": total_gb,
        "splunk_gb": splunk_gb,
        "snowflake_only_gb": snowflake_only_gb,
        "all_splunk_monthly": all_splunk_monthly,
        "hybrid_splunk_monthly": hybrid_splunk_monthly,
        "hybrid_sf_storage": hybrid_sf_storage,
        "hybrid_sf_compute": hybrid_sf_compute,
        "hybrid_total": hybrid_total,
        "savings_monthly": savings_monthly,
        "savings_pct": savings_pct,
    }


def print_report(volumes, result):
    """Print formatted savings report."""
    w = 64

    print("\n" + "=" * w)
    print("  SPLUNK + SNOWFLAKE SAVINGS REPORT")
    print("=" * w)

    # Data routing breakdown
    print(f"\n{'Data Source':<32} {'GB/day':>8} {'Route':>18}")
    print("-" * w)
    for name, gb, to_splunk, _ in volumes:
        if gb > 0:
            route = "Splunk + Snowflake" if to_splunk else "Snowflake only"
            print(f"  {name:<30} {gb:>6.0f}   {route:>18}")
    print("-" * w)
    print(f"  {'TOTAL':<30} {result['total_gb']:>6.0f}")
    print(f"  {'To Splunk (critical)':<30} {result['splunk_gb']:>6.0f}   ({result['splunk_gb']/result['total_gb']*100:.0f}%)")
    print(f"  {'Snowflake only':<30} {result['snowflake_only_gb']:>6.0f}   ({result['snowflake_only_gb']/result['total_gb']*100:.0f}%)")

    # Cost comparison
    print(f"\n{'':=<{w}}")
    print(f"\n{'Cost Comparison':<32} {'All-Splunk':>14} {'Hybrid':>14}")
    print("-" * w)
    print(f"  {'Splunk ingestion':<30} ${result['all_splunk_monthly']:>12,.0f} ${result['hybrid_splunk_monthly']:>12,.0f}")
    print(f"  {'Snowflake storage':<30} {'$0':>13} ${result['hybrid_sf_storage']:>12,.0f}")
    print(f"  {'Snowflake compute (est.)':<30} {'$0':>13} ${result['hybrid_sf_compute']:>12,.0f}")
    print("-" * w)
    print(f"  {'MONTHLY TOTAL':<30} ${result['all_splunk_monthly']:>12,.0f} ${result['hybrid_total']:>12,.0f}")
    print(f"  {'ANNUAL TOTAL':<30} ${result['all_splunk_monthly']*12:>12,.0f} ${result['hybrid_total']*12:>12,.0f}")
    print(f"  {'3-YEAR TOTAL':<30} ${result['all_splunk_monthly']*36:>12,.0f} ${result['hybrid_total']*36:>12,.0f}")

    # Savings
    print(f"\n{'':=<{w}}")
    print(f"\n  Monthly savings:  ${result['savings_monthly']:>12,.0f}  ({result['savings_pct']:.0f}%)")
    print(f"  Annual savings:   ${result['savings_monthly']*12:>12,.0f}")
    print(f"  3-year savings:   ${result['savings_monthly']*36:>12,.0f}")
    print(f"\n{'':=<{w}}")

    # Key points
    print("\nKey Points:")
    print(f"  - {result['splunk_gb']/result['total_gb']*100:.0f}% of data goes to Splunk (critical subset for real-time detection)")
    print(f"  - 100% of data goes to Snowflake (full retention for investigation & compliance)")
    print(f"  - Snowflake storage is ~{result['all_splunk_monthly']/max(result['hybrid_sf_storage'],1):.0f}x cheaper than Splunk ingestion")
    print(f"  - Federated search bridges the gap (DB Connect today, native integration GA July 2026)")
    print()


def main():
    parser = argparse.ArgumentParser(description="Splunk + Snowflake Savings Calculator")
    parser.add_argument("--total", type=float, help="Total daily ingest in GB (uses default source split)")
    parser.add_argument("--splunk-rate", type=float, default=SPLUNK_COST_PER_GB_DAY_MONTH,
                        help=f"Splunk cost per GB/day/month (default: ${SPLUNK_COST_PER_GB_DAY_MONTH})")
    parser.add_argument("--csv", action="store_true", help="Output as CSV instead of formatted table")
    args = parser.parse_args()

    print("=" * 64)
    print("  Splunk + Snowflake Savings Calculator")
    print("=" * 64)

    if args.total:
        # Scale defaults proportionally
        default_total = sum(s[1] for s in DATA_SOURCES)
        scale = args.total / default_total
        volumes = [(n, gb * scale, s, d) for n, gb, s, d in DATA_SOURCES]
    else:
        volumes = prompt_volumes()

    result = calculate_savings(volumes, splunk_rate=args.splunk_rate)

    if args.csv:
        print("source,gb_per_day,route,monthly_splunk,monthly_snowflake")
        for name, gb, to_splunk, _ in volumes:
            route = "both" if to_splunk else "snowflake_only"
            sp_cost = gb * args.splunk_rate if to_splunk else 0
            sf_cost = (gb * 30 / 1000) * SNOWFLAKE_STORAGE_PER_TB_MONTH
            print(f'"{name}",{gb:.1f},{route},{sp_cost:.0f},{sf_cost:.0f}')
    else:
        print_report(volumes, result)


if __name__ == "__main__":
    main()
