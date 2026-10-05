#!/usr/bin/env bash
#
# Stop every process started by start.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUN_DIR="${HERE}/.run"

if [[ ! -d "${RUN_DIR}" ]]; then
  echo "Nothing to stop: ${RUN_DIR} does not exist."
  exit 0
fi

stopped=0
for pid_file in "${RUN_DIR}"/*.pid; do
  [[ -e "${pid_file}" ]] || continue

  name="$(basename "${pid_file}" .pid)"
  pid="$(cat "${pid_file}" 2>/dev/null || true)"

  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    echo "  ${name} was not running"
    rm -f "${pid_file}"
    continue
  fi

  kill "${pid}" 2>/dev/null || true

  # Escalate if the process ignores SIGTERM.
  for _ in $(seq 1 20); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "${pid}" 2>/dev/null; then
    echo "  ${name} ignored SIGTERM, sending SIGKILL"
    kill -9 "${pid}" 2>/dev/null || true
  fi

  echo "  ${name} stopped (pid ${pid})"
  rm -f "${pid_file}"
  stopped=$((stopped + 1))
done

echo
echo "Stopped ${stopped} process(es)."