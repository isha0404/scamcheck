"""Check a message from the command line:

    python -m scamcheck "Your parcel could not be delivered..."
"""
import json
import sys

from .checker import check
from .model import ScamModel


def main() -> int:
    if len(sys.argv) < 2:
        print('Usage: python -m scamcheck "message to check"  [--json]')
        return 2
    as_json = "--json" in sys.argv
    text = " ".join(a for a in sys.argv[1:] if a != "--json")
    result = check(text, ScamModel.load())
    if as_json:
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    print(f"\n{result.label.upper()}  (risk {result.risk:.0%})\n{result.summary}\n")
    for s in result.signals:
        print(f"  [{s.severity}] {s.title}: {s.detail}")
    if result.model_terms:
        print("\n  Words that looked scam-like: " + ", ".join(t["term"] for t in result.model_terms))
    return 0


if __name__ == "__main__":
    sys.exit(main())
