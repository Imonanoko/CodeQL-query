#!/usr/bin/env bash
# Usage:
#   batch_autoql_from_csv.sh -c repos.csv -p ./projects [-a ./java_autoql.sh] [-d 1] [-m N] [-S seconds] [-o failed.csv] [-s]
#
# Example:
#   ./batch_autoql_from_csv.sh -c ../repos/repos_java.csv -p ../projects -a ./java_autoql.sh -d 1 -S 2 -s

set -euo pipefail

CSV_FILE=""
PROJECTS_ROOT=""
AUTOQL_SCRIPT="./java_autoql.sh"
GIT_DEPTH=1
MAX_COUNT=0
SLEEP_BETWEEN=0
FAIL_CSV=""
SKIP_IF_JSON_EXISTS=0

# Java preprocessing JSON root (match your java_autoql.sh output_dir base)
PREPROCESS_ROOT="./java_query_output"

print_help() { sed -n '2,25p' "$0"; }

while getopts ":c:p:a:d:m:S:o:sh" opt; do
  case "$opt" in
    c) CSV_FILE="$OPTARG" ;;
    p) PROJECTS_ROOT="$OPTARG" ;;
    a) AUTOQL_SCRIPT="$OPTARG" ;;
    d) GIT_DEPTH="$OPTARG" ;;
    m) MAX_COUNT="$OPTARG" ;;
    S) SLEEP_BETWEEN="$OPTARG" ;;
    o) FAIL_CSV="$OPTARG" ;;
    s) SKIP_IF_JSON_EXISTS=1 ;;
    h) print_help; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG"; print_help; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument."; exit 1 ;;
  esac
done

[[ -n "$CSV_FILE" && -n "$PROJECTS_ROOT" ]] || { echo "請至少指定 CSV (-c) 與 下載目錄 (-p)"; print_help; exit 1; }
[[ -f "$CSV_FILE" ]] || { echo "找不到 CSV 檔案：$CSV_FILE"; exit 1; }
[[ -x "$AUTOQL_SCRIPT" ]] || { echo "找不到或不可執行的 autoql 腳本：$AUTOQL_SCRIPT"; exit 1; }

mkdir -p "$PROJECTS_ROOT"
mkdir -p "$PREPROCESS_ROOT"

if [[ -z "${FAIL_CSV}" ]]; then
  FAIL_CSV="${CSV_FILE%.csv}.failed.csv"
fi
header="$(head -n1 "$CSV_FILE")"
echo "${header}" > "$FAIL_CSV"

COUNT=0

# NOTE: 這段 awk 沿用你原本 CSV 欄位假設：
#   $2 = full_name, $4 = clone_url, $6 = language
awk -v FPAT='([^,]*)|("[^"]*")' 'NR==1{next} {print $0 "\t" $2 "\t" $4 "\t" $6}' "$CSV_FILE" | \
while IFS=$'\t' read -r orig_line full_name clone_url language; do
  full_name="${full_name%\"}"; full_name="${full_name#\"}"
  clone_url="${clone_url%\"}"; clone_url="${clone_url#\"}"
  language="${language%\"}"; language="${language#\"}"

  # Only Java
  shopt -s nocasematch
  if [[ "$language" != "Java" ]]; then
    shopt -u nocasematch
    continue
  fi
  shopt -u nocasematch

  COUNT=$((COUNT+1))
  if [[ "$MAX_COUNT" -gt 0 && "$COUNT" -gt "$MAX_COUNT" ]]; then
    break
  fi

  repo_slug="$full_name"                 # owner/repo
  repo_name="${repo_slug##*/}"
  db_name="${repo_name}"  # avoid collisions across owners
  dest="$PROJECTS_ROOT/$db_name"

  # Candidate JSON locations (support both common layouts)
  json1="$PREPROCESS_ROOT/$db_name/$db_name.json"
  json2="$PREPROCESS_ROOT/$db_name.json"

  echo "=== [$COUNT] $repo_slug (Java) => db=$db_name ==="

  if [[ "$SKIP_IF_JSON_EXISTS" -eq 1 ]]; then
    if [[ -f "$json1" || -f "$json2" ]]; then
      echo "-- skip (json exists): $repo_slug"
      [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
      continue
    fi
  fi

  rm -rf "$dest"
  # clone with submodules (GitHub projects often require them)
  if ! git clone --depth "$GIT_DEPTH" --recurse-submodules --shallow-submodules "$clone_url" "$dest"; then
    echo "!! clone 失敗：$repo_slug"
    echo "${orig_line},clone_failed" >> "$FAIL_CSV"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  if "$AUTOQL_SCRIPT" "$db_name" "$dest"; then
    echo "-- autoql 完成：$repo_slug"
  else
    rc=$?
    echo "!! autoql 失敗：$repo_slug (exit=${rc})"
    echo "${orig_line},autoql_exit_${rc}" >> "$FAIL_CSV"
    rm -rf "$dest"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  # Verify preprocessing JSON exists
  if [[ -f "$json1" || -f "$json2" ]]; then
    echo "-- preprocessing json OK"
  else
    echo "!! preprocessing json missing：$repo_slug"
    echo "   expected: $json1 OR $json2"
    echo "${orig_line},json_missing" >> "$FAIL_CSV"
  fi

  rm -rf "$dest"
  [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
done

echo "[done] 失敗清單已輸出：$FAIL_CSV"
echo "[done] preprocessing root: $PREPROCESS_ROOT"
