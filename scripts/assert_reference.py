"""CI gate: the harness itself works (reference client/server interoperate on every
config). Findings in other implementations are reported, not treated as CI failures."""
import json, sys
rows = json.load(open(sys.argv[1]))
ref = [r for r in rows if r["client"] == r["server"] == "amneziawg-go"]
bad = [r["config"] for r in ref if not r.get("ping")]
print(f"reference pairs: {len(ref)}, failing: {bad}")
sys.exit(1 if bad or not ref else 0)
