#!/usr/bin/env python3
import os, sys, json

try:
    import yaml  # PyYAML
except ImportError:
    print("PyYAML not installed. Run: python3 -m pip install --user pyyaml", file=sys.stderr)
    sys.exit(2)


def main():
    env_name  = os.getenv("ENV_NAME")
    yaml_file = os.getenv("YAML_CONFIG", "myvars.yaml")
    if not env_name:
        print("ENV_NAME is required", file=sys.stderr); sys.exit(1)

    with open(yaml_file) as f:
        y = yaml.safe_load(f)

    if env_name not in y:
        print(f"ENV_NAME '{env_name}' not found in {yaml_file}", file=sys.stderr)
        sys.exit(1)

    section = y[env_name]

    # Validate & build secrets block
    lines = []
    for s in section.get("secrets", []):
        p = str(s["path"])
        k = str(s["key"])
        e = str(s["env_name"])
        if " " in p:
            raise ValueError(f"Secret path contains spaces: {p!r}")
        lines.append(f"{p} {k} | {e} ;")

    # Compact JSON for fromJSON(...)
    json_str = json.dumps(section, separators=(",", ":"))

    # Emit to GITHUB_OUTPUT
    out = os.getenv("GITHUB_OUTPUT")
    if not out:
        print("GITHUB_OUTPUT not set", file=sys.stderr); sys.exit(1)
    with open(out, "a") as fh:
        fh.write("json<<JSON\n"); fh.write(json_str + "\nJSON\n")
        fh.write("secrets<<SECS\n"); fh.write("\n".join(lines) + "\nSECS\n")

if __name__ == "__main__":
    main()
