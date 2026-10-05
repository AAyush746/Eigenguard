#!/usr/bin/env bash
#
# Run every test suite in the repository.
#
#   bash scripts/smoke_test.sh          # everything
#   bash scripts/smoke_test.sh python   # honeypot + ml only
#   bash scripts/smoke_test.sh node     # http logger only
#   bash scripts/smoke_test.sh ui       # dashboard lint, typecheck, tests, build
#
# Exits non-zero on the first failing suite so CI can use it directly.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${1:-all}"

PYTHON="${PYTHON:-python3}"
FAILED=()

run() {
  local name="$1"; shift
  echo
  echo "=== ${name} ==="
  if "$@"; then
    echo "--- ${name}: PASS"
  else
    echo "--- ${name}: FAIL"
    FAILED+=("${name}")
  fi
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "SKIP: $1 is not installed"
    return 1
  }
}

if [[ "${TARGET}" == "all" || "${TARGET}" == "python" ]]; then
  run "honeypot (SSH capture + REST API)" \
    "${PYTHON}" -m pytest "${REPO_ROOT}/honeypot/tests" -q

  run "ml (feature extraction)" \
    "${PYTHON}" -m pytest "${REPO_ROOT}/ml/tests" -q
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "node" ]]; then
  if need node; then
    run "http logger" npm --prefix "${REPO_ROOT}/http_logger" test
  fi
fi

if [[ "${TARGET}" == "all" || "${TARGET}" == "ui" ]]; then
  if need node && [[ -d "${REPO_ROOT}/dashboard/node_modules" ]]; then
    run "dashboard lint"      npm --prefix "${REPO_ROOT}/dashboard" run lint
    run "dashboard typecheck" npm --prefix "${REPO_ROOT}/dashboard" run typecheck
    run "dashboard tests"     npm --prefix "${REPO_ROOT}/dashboard" test
    run "dashboard build"     npm --prefix "${REPO_ROOT}/dashboard" run build
  else
    echo "SKIP: dashboard (run 'npm install' in dashboard/)"
  fi
fi

echo
if [[ ${#FAILED[@]} -eq 0 ]]; then
  echo "All suites passed."
  exit 0
fi

echo "FAILED: ${FAILED[*]}"
exit 1