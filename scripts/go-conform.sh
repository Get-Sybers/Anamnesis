#!/usr/bin/env bash
# ==============================================================================
# go-conform.sh — the Go conformance gate (go-standards.md §12).
#
# Runs, across every module in the workspace: a module-path check, gofmt -l,
# go vet, go build, go test, a go:generate drift check, and a structural lint
# (no exported Get* accessors). For anamnesis it also builds the optional
# native MemProcFS backend behind its build tag (purego, still CGO_ENABLED=0),
# so the tagged path is gated too. Exits non-zero on any failure.
#
# Usage: scripts/go-conform.sh [module-dir ...]   (default: all workspace modules)
# ==============================================================================
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.." || exit 2
ROOT="$PWD"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  OK=$'\033[38;5;172m'; ERR=$'\033[38;5;167m'; DIM=$'\033[38;5;245m'; RST=$'\033[0m'
else OK= ERR= DIM= RST=; fi
pass=0; fail=0
ok()   { printf '%s[ ok ]%s %s\n'   "$OK"  "$RST" "$*"; pass=$((pass+1)); }
bad()  { printf '%s[fail]%s %s\n'   "$ERR" "$RST" "$*" >&2; fail=$((fail+1)); }
note() { printf '       %s%s%s\n'   "$DIM" "$*" "$RST"; }

WANT_PREFIX="github.com/Get-Sybers/Anamnesis"

# workspace modules (from go.work), or the args given
modules() {
  if [[ $# -gt 0 ]]; then printf '%s\n' "$@"; return; fi
  go work edit -json | sed -n 's/.*"DiskPath": "\(.*\)".*/\1/p'
}

mapfile -t MODS < <(modules "$@")   # array preserves paths with spaces; no word-split/glob
for m in "${MODS[@]}"; do
  d="$ROOT/${m#./}"
  name="${m#./}"; [[ "$name" == "." ]] && name="$(basename "$ROOT")"
  [[ -f "$d/go.mod" ]] || { bad "$name: no go.mod"; continue; }

  # module path convention
  mp=$(sed -n 's/^module //p' "$d/go.mod")
  case "$mp" in
    "$WANT_PREFIX"|"$WANT_PREFIX"/*) : ;;
    *) bad "$name: module path $mp is not $WANT_PREFIX[/…]" ;;
  esac

  # gofmt — a gofmt error (e.g. a parse error) fails the check, never passes silently
  # tracked files only: a bare `gofmt -l` filesystem walk would also scan a
  # warm CI module cache (GOPATH inside the checkout)
  if ! unformatted=$(cd "$d" && git ls-files -z -- '*.go' | xargs -0 -r gofmt -l 2>/tmp/gc.fmt.err); then
    bad "$name: gofmt errored:"; head -6 /tmp/gc.fmt.err >&2
  elif [[ -n "$unformatted" ]]; then
    bad "$name: gofmt needed: $unformatted"
  fi

  # no exported Get* accessors (go-standards.md §6)
  getters=$(cd "$d" && git ls-files -z -- '*.go' | xargs -0 -r grep -nE 'func (\([^)]*\) )?Get[A-Z]' 2>/dev/null | grep -v '_test.go' || true)
  [[ -z "$getters" ]] || bad "$name: exported Get* accessor(s):"$'\n'"$getters"

  ( cd "$d" && go vet ./... ) 2>/tmp/gc.err   && ok "$name: vet"   || { bad "$name: vet";   head -6 /tmp/gc.err >&2; }
  ( cd "$d" && go build ./... ) 2>/tmp/gc.err  && ok "$name: build" || { bad "$name: build"; head -6 /tmp/gc.err >&2; }
  ( cd "$d" && go test ./... >/tmp/gc.out 2>&1 ) && ok "$name: test" || { bad "$name: test"; grep -E '^(FAIL|---|panic)' /tmp/gc.out | head -8 >&2; }

  # optional native backend: must still compile behind its tag (purego dlopen,
  # CGO_ENABLED=0 — the shared library is only needed at runtime).
  if grep -rql '//go:build memprocfs' "$d" --include=*.go 2>/dev/null; then
    ( cd "$d" && CGO_ENABLED=0 go build -tags memprocfs ./... ) 2>/tmp/gc.err \
      && ok "$name: build (-tags memprocfs)" || { bad "$name: build (-tags memprocfs)"; head -6 /tmp/gc.err >&2; }
    ( cd "$d" && CGO_ENABLED=0 go vet -tags memprocfs ./... ) 2>/tmp/gc.err \
      && ok "$name: vet (-tags memprocfs)" || { bad "$name: vet (-tags memprocfs)"; head -6 /tmp/gc.err >&2; }
    ( cd "$d" && CGO_ENABLED=0 go test -tags memprocfs ./... >/tmp/gc.out 2>&1 ) \
      && ok "$name: test (-tags memprocfs)" || { bad "$name: test (-tags memprocfs)"; grep -E '^(FAIL|---|panic)' /tmp/gc.out | head -8 >&2; }
  fi

  # go:generate drift: only if the module declares any directive
  if grep -rql '//go:generate' "$d" --include=*.go 2>/dev/null; then
    ( cd "$d" && go generate ./... ) >/dev/null 2>&1
    if ! drift=$(cd "$ROOT" && git status --porcelain -- "${m#./}" 2>/tmp/gc.git.err); then
      bad "$name: generate drift check — git status failed:"; head -3 /tmp/gc.git.err >&2
    elif [[ -z "$drift" ]]; then
      ok "$name: generate (no drift)"
    else
      bad "$name: go:generate drift"; echo "$drift" >&2
    fi
  fi
done

echo
if [[ $fail -eq 0 ]]; then printf '%sconform: %d checks passed%s\n' "$OK" "$pass" "$RST"; exit 0
else printf '%sconform: %d passed, %d FAILED%s\n' "$ERR" "$pass" "$fail" "$RST"; exit 1; fi
