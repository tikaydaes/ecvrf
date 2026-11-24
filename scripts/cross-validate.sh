#!/usr/bin/env bash
set -euo pipefail

# Cross-implementation validation for RFC 9381 ECVRF-EDWARDS25519-SHA512-TAI (suite 0x03).
#
# Modes:
#   1. CI mode (ECVRF_BIN_DIR set): uses pre-built binaries downloaded by GitHub Actions.
#   2. Local mode (default): auto-detects installed toolchains, builds their CLIs, and
#      cross-validates every available implementation.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p scripts/.bin

# Ensure ghcup / homebrew openjdk are discoverable when present
[ -d "$HOME/.ghcup/bin" ] && export PATH="$HOME/.ghcup/bin:$PATH"
if [ -z "${JAVA_HOME:-}" ] && [ -d "/opt/homebrew/opt/openjdk@21" ]; then
    export JAVA_HOME="/opt/homebrew/opt/openjdk@21"
fi

declare -a PROVER_SPECS=()
declare -a VERIFIER_ONLY_SPECS=()
declare -a SKIPPED=()

add_prover() {
    PROVER_SPECS+=("$1=$2")
}

add_verifier_only() {
    VERIFIER_ONLY_SPECS+=("$1=$2")
}

if [ -n "${ECVRF_BIN_DIR:-}" ]; then
    echo "Using pre-built CLI binaries from $ECVRF_BIN_DIR"
    add_prover "python" "python3|python/cli.py"
    add_prover "js" "node|js/cli.mjs"

    declare -a MISSING_ARTIFACTS=()

    require_ci_prover() {
        local name="$1" path="$2" cmd="$3" needs_chmod="${4:-0}"
        if [ -f "$path" ]; then
            [ "$needs_chmod" = "1" ] && chmod +x "$path"
            add_prover "$name" "$cmd"
        else
            MISSING_ARTIFACTS+=("$name ($path)")
        fi
    }

    require_ci_prover "go" "$ECVRF_BIN_DIR/go/ecvrf-go" "$ECVRF_BIN_DIR/go/ecvrf-go" 1
    require_ci_prover "dart" "$ECVRF_BIN_DIR/dart/ecvrf-dart" "$ECVRF_BIN_DIR/dart/ecvrf-dart" 1

    if [ -f "typescript/dist/cli.js" ]; then
        add_prover "typescript" "node|typescript/dist/cli.js"
    elif [ -f "$ECVRF_BIN_DIR/typescript/dist/cli.js" ]; then
        add_prover "typescript" "node|$ECVRF_BIN_DIR/typescript/dist/cli.js"
    else
        MISSING_ARTIFACTS+=("typescript (typescript/dist/cli.js)")
    fi

    require_ci_prover "c" "$ECVRF_BIN_DIR/c/ecvrf_cli" "$ECVRF_BIN_DIR/c/ecvrf_cli" 1
    require_ci_prover "rust" "$ECVRF_BIN_DIR/rust/cli" "$ECVRF_BIN_DIR/rust/cli" 1
    require_ci_prover "csharp" "$ECVRF_BIN_DIR/csharp/Ecvrf.Cli.dll" "dotnet|exec|$ECVRF_BIN_DIR/csharp/Ecvrf.Cli.dll" 0
    require_ci_prover "kotlin" "$ECVRF_BIN_DIR/kotlin/bin/ecvrf-kotlin" "$ECVRF_BIN_DIR/kotlin/bin/ecvrf-kotlin" 1
    require_ci_prover "haskell" "$ECVRF_BIN_DIR/haskell/ecvrf-cli" "$ECVRF_BIN_DIR/haskell/ecvrf-cli" 1
    require_ci_prover "zig" "$ECVRF_BIN_DIR/zig/ecvrf-cli" "$ECVRF_BIN_DIR/zig/ecvrf-cli" 1

    # Swift runs on macos-latest in CI, so its artifact is optional on Linux cross-validate
    if [ -f "$ECVRF_BIN_DIR/swift/ecvrf-cli" ]; then
        chmod +x "$ECVRF_BIN_DIR/swift/ecvrf-cli"
        add_prover "swift" "$ECVRF_BIN_DIR/swift/ecvrf-cli"
    else
        SKIPPED+=("swift")
    fi

    if [ -f "$ECVRF_BIN_DIR/solana/cli" ]; then
        chmod +x "$ECVRF_BIN_DIR/solana/cli"
        add_verifier_only "solana" "$ECVRF_BIN_DIR/solana/cli"
    else
        MISSING_ARTIFACTS+=("solana ($ECVRF_BIN_DIR/solana/cli)")
    fi

    if [ "${#MISSING_ARTIFACTS[@]}" -gt 0 ]; then
        echo "ERROR: missing expected CI artifacts:" >&2
        printf '  - %s\n' "${MISSING_ARTIFACTS[@]}" >&2
        exit 1
    fi
else
    echo "Building available local implementations..."

    # Python (always required as orchestrator)
    add_prover "python" "python3|python/cli.py"

    # Go
    if command -v go >/dev/null 2>&1; then
        go build -o scripts/.bin/ecvrf-go ./cmd/ecvrf-cli
        add_prover "go" "scripts/.bin/ecvrf-go"
    else
        SKIPPED+=("go")
    fi

    # JavaScript & TypeScript
    if command -v node >/dev/null 2>&1; then
        add_prover "js" "node|js/cli.mjs"
        if [ -d typescript/node_modules ]; then
            (cd typescript && npm run build >/dev/null)
            add_prover "typescript" "node|typescript/dist/cli.js"
        elif [ -f typescript/dist/cli.js ]; then
            add_prover "typescript" "node|typescript/dist/cli.js"
        else
            SKIPPED+=("typescript")
        fi
    else
        SKIPPED+=("js" "typescript")
    fi

    # Dart
    if command -v dart >/dev/null 2>&1; then
        (cd dart && dart pub get >/dev/null && dart compile exe bin/ecvrf_cli.dart -o ../scripts/.bin/ecvrf-dart >/dev/null)
        add_prover "dart" "scripts/.bin/ecvrf-dart"
    else
        SKIPPED+=("dart")
    fi

    # C
    if command -v cc >/dev/null 2>&1; then
        (cd c && make ecvrf_cli >/dev/null)
        add_prover "c" "c/ecvrf_cli"
    else
        SKIPPED+=("c")
    fi

    # Swift
    if command -v swift >/dev/null 2>&1; then
        if (cd swift && swift build -c release >/dev/null 2>&1); then
            add_prover "swift" "swift/.build/release/ecvrf-cli"
        elif [ -x swift/.build/debug/ecvrf-cli ]; then
            add_prover "swift" "swift/.build/debug/ecvrf-cli"
        else
            SKIPPED+=("swift")
        fi
    else
        SKIPPED+=("swift")
    fi

    # Kotlin
    if [ -x kotlin/build/install/ecvrf-kotlin/bin/ecvrf-kotlin ]; then
        add_prover "kotlin" "kotlin/build/install/ecvrf-kotlin/bin/ecvrf-kotlin"
    elif [ -n "${JAVA_HOME:-}" ] || (command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1); then
        if (cd kotlin && ./gradlew installDist --quiet >/dev/null 2>&1); then
            add_prover "kotlin" "kotlin/build/install/ecvrf-kotlin/bin/ecvrf-kotlin"
        else
            SKIPPED+=("kotlin")
        fi
    else
        SKIPPED+=("kotlin")
    fi

    # Rust & Solana
    if command -v cargo >/dev/null 2>&1; then
        (cd rust && cargo build --example cli --release >/dev/null 2>&1)
        add_prover "rust" "rust/target/release/examples/cli"
        (cd solana && cargo build --example cli --features no-entrypoint --release >/dev/null 2>&1)
        add_verifier_only "solana" "solana/target/release/examples/cli"
    else
        SKIPPED+=("rust" "solana")
    fi

    # C#
    if command -v dotnet >/dev/null 2>&1; then
        (cd csharp/Ecvrf.Cli && dotnet build -c Release --nologo -v q >/dev/null)
        add_prover "csharp" "dotnet|run|--project|csharp/Ecvrf.Cli|-c|Release|--no-build|--"
    else
        SKIPPED+=("csharp")
    fi

    # Haskell
    if command -v cabal >/dev/null 2>&1; then
        (cd haskell && cabal build ecvrf-cli >/dev/null 2>&1)
        HASKELL_BIN="$(cd haskell && cabal list-bin ecvrf-cli)"
        add_prover "haskell" "$HASKELL_BIN"
    else
        SKIPPED+=("haskell")
    fi

    # Zig
    if command -v zig >/dev/null 2>&1; then
        (cd zig && zig build -Doptimize=ReleaseFast >/dev/null 2>&1)
        add_prover "zig" "zig/zig-out/bin/ecvrf-cli"
    else
        SKIPPED+=("zig")
    fi
fi

export ECVRF_PROVERS="$(IFS=$'\n'; echo "${PROVER_SPECS[*]}")"
export ECVRF_VERIFIERS_ONLY="$(IFS=$'\n'; echo "${VERIFIER_ONLY_SPECS[*]:-}")"
export ECVRF_SKIPPED="$(IFS=','; echo "${SKIPPED[*]:-}")"

python3 - <<'EOF'
import json
import os
import pathlib
import subprocess
import sys

def parse_specs(raw: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        name, cmd = line.split("=", 1)
        out[name] = cmd.split("|")
    return out

provers = parse_specs(os.environ.get("ECVRF_PROVERS", ""))
verifiers_only = parse_specs(os.environ.get("ECVRF_VERIFIERS_ONLY", ""))
verifiers = dict(provers)
verifiers.update(verifiers_only)
skipped = [s for s in os.environ.get("ECVRF_SKIPPED", "").split(",") if s]

data = json.loads(pathlib.Path("vectors/vectors.json").read_text(encoding="utf-8"))
vectors = data["vectors"]
negatives = data["negative_vectors"]

print(f"Provers ({len(provers)}):   {list(provers.keys())}")
print(f"Verifiers ({len(verifiers)}): {list(verifiers.keys())}")
if skipped:
    print(f"Skipped ({len(skipped)}):   {skipped}")

# Phase 1 & 2: derive-pk, prove identity, and all-provers x all-verifiers matrix
for idx, vec in enumerate(vectors):
    sk, pk, alpha, want_pi, want_beta = vec["sk"], vec["pk"], vec["alpha"], vec["pi"], vec["beta"]
    for prover, pcmd in provers.items():
        got_pk = subprocess.check_output(pcmd + ["derive-pk", sk], text=True).strip()
        assert got_pk == pk, f"[{vec['label']}] {prover} pk mismatch: {got_pk} != {pk}"
        got_pi = subprocess.check_output(pcmd + ["prove", sk, alpha], text=True).strip()
        assert got_pi == want_pi, f"[{vec['label']}] {prover} pi mismatch"
        # Full cross-verification matrix on first 5 vectors, self+oracle on remaining
        if idx < 5:
            target_verifiers = list(verifiers.items())
        else:
            target_verifiers = [(prover, pcmd)]
            if prover != "python" and "python" in verifiers:
                target_verifiers.append(("python", verifiers["python"]))
            elif prover == "python":
                target_verifiers.extend(verifiers_only.items())
        for verifier, vcmd in target_verifiers:
            got_beta = subprocess.check_output(vcmd + ["verify", pk, got_pi, alpha], text=True).strip()
            assert got_beta == want_beta, f"[{vec['label']}] {verifier} failed verifying {prover}"

print(f"Phase 1+2 PASSED: {len(vectors)} positive vectors across {len(provers)} provers x {len(verifiers)} verifiers.")

# Phase 3: negative vector rejection across all verifiers
for neg in negatives:
    pk, pi, alpha = neg["pk"], neg["pi"], neg["alpha"]
    for verifier, vcmd in verifiers.items():
        proc = subprocess.run(
            vcmd + ["verify", pk, pi, alpha],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.returncode != 0, f"[{neg['description']}] {verifier} erroneously accepted invalid proof"

print(f"Phase 3 PASSED: {len(negatives)} negative vectors rejected by all {len(verifiers)} verifiers.")
EOF
