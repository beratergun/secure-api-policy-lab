import argparse
import json
from pathlib import Path

from policy import validate_record


def main():
    parser = argparse.ArgumentParser(description="Review bounded, recorded HTTP metadata with local rules.")
    parser.add_argument("input", type=Path)
    args = parser.parse_args()
    data = json.loads(args.input.read_text(encoding="utf-8"))
    records = data if isinstance(data, list) else [data]
    if not records or len(records) > 10_000:
        raise SystemExit("records must contain 1..10000 items")
    try:
        output = [validate_record(record) for record in records]
    except ValueError as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
