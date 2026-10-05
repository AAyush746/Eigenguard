#!/usr/bin/env bash
#
# Start the EigenGuard honeypot stack.
#
#   bash start.sh              API + SSH honeypot
#   bash start.sh --with-ui    also start the React dashboard
#
# Override defaults with environment variables, e.g.
#   EG_SSH_PORT=2022 EG_API_PORT=9000 bash start.sh
#
# PIDs are written to .run/ so `bash stop.sh` can shut everything down.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/.." && pwd)"
RUN_DIR="${HERE}/.run"
LOG_DIR="${HERE}/logs"

API_HOST="${EG_API_HOST:-0.0.0.0}"
API_PORT="${EG_API_PORT:-8000}"
SSH_HOST="${EG_SSH_HOST:-0.0.0.0}"
SSH_PORT="${EG_SSH_PORT:-2222}"

WITH_UI=0
[[ "${1:-}" == "--with-ui" ]] && WITH_UI=1

mkdir -p "${RUN_DIR}" "${LOG_DIR}"

# The package is imported as `eigenguard.*`, so the working directory has to be
# honeypot/ regardless of where this script was invoked from. Without this,
# `bash honeypot/start.sh` from the repo root starts two processes that die
# immediately with ModuleNotFoundError.
cd "${HERE}"
export PYTHONPATH="${HERE}${PYTHONPATH:+:${PYTHONPATH}}"

start() {
  local name="$1"; shift
  local pid_file="${RUN_DIR}/${name}.pid"

  if [[ -f "${pid_file}" ]] && kill -0 "$(cat "${pid_file}")" 2>/dev/null; then
    echo "  ${name} already running (pid $(cat "${pid_file}"))"
    return 0
  fi

  "$@" >"${LOG_DIR}/${name}.log" 2>&1 &
  local pid=$!
  echo "${pid}" >"${pid_file}"

  # Confirm the process is still alive after a moment. A process that exits
  # during startup would otherwise be reported as started.
  sleep 0.5
  if kill -0 "${pid}" 2>/dev/null; then
    echo "  ${name} started (pid ${pid}) -> ${LOG_DIR}/${name}.log"
  else
    echo "  ${name} FAILED to start; last lines of ${LOG_DIR}/${name}.log:" >&2
    tail -n 15 "${LOG_DIR}/${name}.log" >&2 || true
    return 1
  fi
}

# Fail early with a clear message rather than letting uvicorn die on import.
PYTHON="${PYTHON:-python3}"
if ! "${PYTHON}" -c "import fastapi, uvicorn, sqlalchemy, paramiko" 2>/dev/null; then
  echo "Missing Python dependencies. Install them with:" >&2
  echo "  pip install -r ${HERE}/requirements.txt" >&2
  exit 1
fi

echo "Starting EigenGuard honeypot"

echo "SSH honeypot:"
start ssh "${PYTHON}" -m eigenguard.ssh_server || exit 1

echo "REST API (http://localhost:${API_PORT}):"
start api "${PYTHON}" -m uvicorn eigenguard.api:app --host "${API_HOST}" --port "${API_PORT}" || exit 1

if [[ "${WITH_UI}" -eq 1 ]]; then
  if [[ ! -d "${REPO_ROOT}/dashboard/node_modules" ]]; then
    echo "Dashboard dependencies missing; run 'npm install' in ${REPO_ROOT}/dashboard"
  else
    echo "Dashboard (http://localhost:5173):"
    start dashboard npm --prefix "${REPO_ROOT}/dashboard" run dev
  fi
fi

# Give the listeners a moment so the URLs below are not a lie.
sleep 1.5

echo
echo "  API          http://localhost:${API_PORT}/docs"
echo "  SSH honeypot ${SSH_HOST}:${SSH_PORT}"
[[ "${WITH_UI}" -eq 1 ]] && echo "  Dashboard    http://localhost:5173"
echo
echo "Stop everything with: bash stop.sh"
echo "Try the honeypot with: ssh -p ${SSH_PORT} root@localhost"