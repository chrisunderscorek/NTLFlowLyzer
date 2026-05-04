#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <BASE_INPUT_DIR>" >&2
  echo "Example: OUT_BASE=/tmp/ntl_udp THREADS=12 $0 /data/pcaps" >&2
  exit 1
fi

BASE_IN="$1"
OUT_BASE="${OUT_BASE:-./ntlflowlyzer_udp_out}"
THREADS="${THREADS:-8}"
NTL_BIN="${NTL_BIN:-ntlflowlyzer_udp}"
SKIP_EXISTING="${SKIP_EXISTING:-0}"

[[ -d "$BASE_IN" ]] || { echo "ERROR: Not a directory: $BASE_IN" >&2; exit 1; }
mkdir -p "$OUT_BASE"

shopt -s nullglob
for MAL_DIR in "$BASE_IN"/*/; do
  [[ -d "$MAL_DIR" ]] || continue

  LABEL="$(basename "$MAL_DIR")"
  IN_DIR="${MAL_DIR%/}"
  OUT_DIR="$OUT_BASE/$LABEL"

  if [[ "$SKIP_EXISTING" == "1" && -d "$OUT_DIR" ]]; then
    echo "Skipping '$LABEL' because output exists: $OUT_DIR"
    continue
  fi

  if [[ -z "$(find "$IN_DIR" -maxdepth 1 -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -print -quit)" ]]; then
    echo "Skipping '$LABEL' because no .pcap/.pcapng files were found"
    continue
  fi

  mkdir -p "$OUT_DIR"
  CFG_FILE="$(mktemp "/tmp/ntlflowlyzer_udp_${LABEL}.XXXXXX.json")"
  trap 'rm -f "$CFG_FILE"' EXIT

  python3 - "$IN_DIR" "$OUT_DIR" "$THREADS" "$LABEL" "$CFG_FILE" <<'PY'
import json
import sys

in_dir, out_dir, threads, label, cfg_file = sys.argv[1:]
config = {
    "batch_address": in_dir,
    "batch_address_output": out_dir,
    "number_of_threads": int(threads),
    "label": label,
}
with open(cfg_file, "w", encoding="utf-8") as fh:
    json.dump(config, fh, indent=2)
    fh.write("\n")
PY

  echo "=============================="
  echo "Label:   $LABEL"
  echo "Input:   $IN_DIR"
  echo "Output:  $OUT_DIR"
  echo "Config:  $CFG_FILE"
  echo "Running: $NTL_BIN -b -c $CFG_FILE"

  "$NTL_BIN" -b -c "$CFG_FILE"
  rm -f "$CFG_FILE"
  trap - EXIT
  echo "Done: $LABEL"
done

echo "All done. Results under: $OUT_BASE"
