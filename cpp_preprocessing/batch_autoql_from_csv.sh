#!/usr/bin/env bash
# Usage:
#   batch_autoql_from_csv.sh -c repos_cpp.csv -p ./projects [-a ./cpp_autoql.sh] [-l "C++"|""=all] [-d 1] [-m N] [-S seconds] [-o failed.csv]
# Example:
#   batch_autoql_from_csv.sh -c ../repos/repos_cpp_cmake.csv -p ../projects/ -a ./cpp_autoql.sh -d 1 -S 2

set -euo pipefail

CSV_FILE=""
PROJECTS_ROOT=""
AUTOQL_SCRIPT="./cpp_autoql.sh"
ONLY_LANGUAGE="cpp"
GIT_DEPTH=1
MAX_COUNT=0
SLEEP_BETWEEN=0
FAIL_CSV=""

print_help() { sed -n '2,18p' "$0"; }

while getopts ":c:p:a:l:d:m:S:o:h" opt; do
  case "$opt" in
    c) CSV_FILE="$OPTARG" ;;
    p) PROJECTS_ROOT="$OPTARG" ;;
    a) AUTOQL_SCRIPT="$OPTARG" ;;
    l) ONLY_LANGUAGE="$OPTARG" ;;
    d) GIT_DEPTH="$OPTARG" ;;
    m) MAX_COUNT="$OPTARG" ;;
    S) SLEEP_BETWEEN="$OPTARG" ;;
    o) FAIL_CSV="$OPTARG" ;;
    h) print_help; exit 0 ;;
    \?) echo "Unknown option: -$OPTARG"; print_help; exit 1 ;;
    :)  echo "Option -$OPTARG requires an argument."; exit 1 ;;
  esac
done

[[ -n "$CSV_FILE" && -n "$PROJECTS_ROOT" ]] || { echo "請至少指定 CSV (-c) 與 下載目錄 (-p)"; print_help; exit 1; }
[[ -f "$CSV_FILE" ]] || { echo "找不到 CSV 檔案：$CSV_FILE"; exit 1; }
[[ -x "$AUTOQL_SCRIPT" ]] || { echo "找不到或不可執行的 autoql 腳本：$AUTOQL_SCRIPT"; exit 1; }

mkdir -p "$PROJECTS_ROOT"

if [[ -z "${FAIL_CSV}" ]]; then
  FAIL_CSV="${CSV_FILE%.csv}.failed.csv"
fi
header="$(head -n1 "$CSV_FILE")"
echo "${header}" > "$FAIL_CSV"

COUNT=0

awk -v FPAT='([^,]*)|("[^"]*")' 'NR==1{next} {print $0 "\t" $2 "\t" $4 "\t" $6}' "$CSV_FILE" | \
while IFS=$'\t' read -r orig_line full_name clone_url language; do
  full_name="${full_name%\"}"; full_name="${full_name#\"}"
  clone_url="${clone_url%\"}"; clone_url="${clone_url#\"}"
  language="${language%\"}"; language="${language#\"}"
  if [[ -n "$ONLY_LANGUAGE" ]]; then
    shopt -s nocasematch
    if [[ "$language" != "$ONLY_LANGUAGE" ]]; then
      shopt -u nocasematch
      continue
    fi
    shopt -u nocasematch
  fi

  COUNT=$((COUNT+1))
  if [[ "$MAX_COUNT" -gt 0 && "$COUNT" -gt "$MAX_COUNT" ]]; then
    break
  fi

  repo_slug="$full_name"
  repo_name="${repo_slug##*/}"
  dest="$PROJECTS_ROOT/$repo_name"

  echo "=== [$COUNT] $repo_slug ($language) ==="
  # echo $repo_slug
  # echo $repo_name
  # echo $dest
  rm -rf "$dest"
  # 需要加上--recurse-submodules來下載這專案使用到的其他repo
  if ! git clone --depth "$GIT_DEPTH" --recurse-submodules --shallow-submodules "$clone_url" "$dest"; then
    echo "!! clone 失敗：$repo_slug"
    echo "${orig_line},clone_failed" >> "$FAIL_CSV"
    [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
    continue
  fi

  if "$AUTOQL_SCRIPT" "$repo_name" "$dest"; then
    echo "-- autoql 完成：$repo_slug"
  else
    rc=$?
    echo "!! autoql 失敗：$repo_slug (exit=${rc})"
    echo "${orig_line},autoql_exit_${rc}" >> "$FAIL_CSV"
  fi

  rm -rf "$dest"

  [[ "$SLEEP_BETWEEN" -gt 0 ]] && sleep "$SLEEP_BETWEEN"
done

echo "[done] 失敗清單已輸出：$FAIL_CSV"
