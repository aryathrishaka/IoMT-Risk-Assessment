"""Evaluate or replay an EBSR evidence bundle without Docker or NVD."""

import argparse
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ebsr_adapter import (
    build_assessment,
    load_input,
    print_assessment_summary,
    replay_assessment,
    save_assessment,
)


def main():
    parser = argparse.ArgumentParser(
        description="Offline EBSR scenario evaluation and replay."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--input",
        help="Evidence/scenario bundle to evaluate.",
    )
    source.add_argument(
        "--replay",
        help="Previously saved EBSR report to replay.",
    )
    parser.add_argument(
        "--out",
        default="output/ebsr_assessments",
        help="Report file or output directory.",
    )
    args = parser.parse_args()

    if args.replay:
        report = replay_assessment(args.replay)
    else:
        report = build_assessment(load_input(args.input))

    print_assessment_summary(report)
    saved_path = save_assessment(
        report,
        output_path=args.out,
    )
    print()
    print(f"Saved report: {saved_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
