#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p scripts/.bin
go build -o scripts/.bin/ecvrf-go ./cmd/ecvrf-cli
(cd dart && dart compile exe bin/ecvrf_cli.dart -o ../scripts/.bin/ecvrf-dart >/dev/null)

python3 - <<'EOF'
import json, subprocess, pathlib

root = pathlib.Path(".")
data = json.loads((root / "vectors/vectors.json").read_text())

clis = {
    "python": ["python3", "python/cli.py"],
    "go": ["scripts/.bin/ecvrf-go"],
    "js": ["node", "js/cli.mjs"],
    "dart": ["scripts/.bin/ecvrf-dart"],
}

for vec in data["vectors"][:5]:
    sk, pk, alpha, want_pi, want_beta = vec["sk"], vec["pk"], vec["alpha"], vec["pi"], vec["beta"]
    for prover, pcmd in clis.items():
        got_pk = subprocess.check_output(pcmd + ["derive-pk", sk], text=True).strip()
        assert got_pk == pk, f"{prover} pk mismatch"
        got_pi = subprocess.check_output(pcmd + ["prove", sk, alpha], text=True).strip()
        assert got_pi == want_pi, f"{prover} pi mismatch on {vec['label']}"
        for verifier, vcmd in clis.items():
            got_beta = subprocess.check_output(vcmd + ["verify", pk, got_pi, alpha], text=True).strip()
            assert got_beta == want_beta, f"{verifier} failed verifying {prover} on {vec['label']}"

print(f"Cross-validation passed across {list(clis.keys())} (all prove x all verify).")
EOF
