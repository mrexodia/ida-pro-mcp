# Dump the tools/call trace stored inside an IDB to JSONL.

import argparse
import json
import sys
from pathlib import Path

# idapro must come first to initialize idalib.
import idapro
from ida_pro_mcp.ida_mcp.trace import iter_idb_records


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export the tools/call trace from an IDB as JSONL."
    )
    parser.add_argument("idb", type=Path, help="Path to the .idb / .i64 to read.")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=None,
        metavar="PATH",
        help="Write JSONL to PATH (default: stdout).",
    )
    args = parser.parse_args()

    if not args.idb.exists():
        parser.error(f"IDB not found: {args.idb}")

    if idapro.open_database(str(args.idb), run_auto_analysis=False) != 0:
        print(f"failed to open IDB: {args.idb}", file=sys.stderr)
        return 1

    try:
        out = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout
        try:
            count = 0
            for rec in iter_idb_records():
                out.write(json.dumps(rec, separators=(",", ":"), default=str))
                out.write("\n")
                count += 1
            out.flush()
        finally:
            if out is not sys.stdout:
                out.close()
    finally:
        idapro.close_database(False)

    print(f"exported {count} record(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
