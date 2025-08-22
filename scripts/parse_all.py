#!/usr/bin/env python3
import os, sys, json

try:
    import yaml  # PyYAML
except ImportError:
    print("PyYAML not installed. Run: python3 -m pip install --user pyyaml", file=sys.stderr)
    sys.exit(2)

def main():
    yaml_file = os.getenv("YAML_CONFIG")

    with open(yaml_file) as f:
        y = yaml.safe_load(f)

    # Compact JSON for fromJSON(...)
    json_str = json.dumps(y, separators=(",", ":"))

    # Emit to GITHUB_OUTPUT
    out = os.getenv("GITHUB_OUTPUT")
    if not out:
        print("GITHUB_OUTPUT not set", file=sys.stderr); sys.exit(1)
    with open(out, "a") as fh:
        fh.write("json<<JSON\n"); fh.write(json_str + "\nJSON\n")

if __name__ == "__main__":
    main()
