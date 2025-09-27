#!/usr/bin/env bash
set -euo pipefail

DEFAULT_SECURITY_DIR="${HOME}/.codeql/packages/codeql/python-queries/1.6.5/Security"

usage() {
  cat <<'USAGE'
Usage:
  run_cwe_queries.sh --project <PROJECT_DIR> [--db-dir <DB_ROOT>] --cwe <LIST> \
    [--security-dir <DIR>] [--out <OUT_DIR>] [--threads <N>] [--overwrite]

Options:
  --project        專案原始碼根目錄(將用來建立 CodeQL DB)
  --db-dir         DB 存放根目錄(預設:./db)。實際 DB 路徑會是 <DB_ROOT>/<project_basename>
  --cwe            要執行的 CWE 編號，可多次帶或逗號分隔，例如:--cwe 022 --cwe 078,113
  --security-dir   官方查詢包的 Security 目錄(預設見上)
  --out            輸出資料夾(預設:./results)
  --threads        CodeQL 建庫/查詢 threads(預設不指定;只有你帶了才會傳給 CodeQL)
  --overwrite      允許覆蓋既有 DB

輸出:
- CodeQL:<OUT>/<project_basename>/<CWE>/<QueryName>.csv
- Bandit:<OUT>/<project_basename>/bandit/CWE-XXX/report.csv
USAGE
}

PROJECT=""
DB_ROOT="./db"
SECURITY_DIR="$DEFAULT_SECURITY_DIR"
OUT_DIR="./results"
THREADS=""
OVERWRITE="false"
CWE_LIST=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:-}"; shift 2 ;;
    --db-dir) DB_ROOT="${2:-}"; shift 2 ;;
    --security-dir) SECURITY_DIR="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --threads) THREADS="${2:-}"; shift 2 ;;
    --overwrite) OVERWRITE="true"; shift ;;
    --cwe)
      IFS=',' read -r -a parts <<< "${2:-}"
      for p in "${parts[@]}"; do
        p="${p//CWE-/}"; p="${p//cwe-/}"; p="${p// /}"
        [[ -n "$p" ]] && CWE_LIST+=("$p")
      done
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$PROJECT" ]] && { echo "[ERR] --project 必填"; usage; exit 1; }
[[ ${#CWE_LIST[@]} -eq 0 ]] && { echo "[ERR] --cwe 至少指定一個"; usage; exit 1; }
[[ ! -d "$PROJECT" ]] && { echo "[ERR] 專案目錄不存在: $PROJECT"; exit 1; }
[[ ! -d "$SECURITY_DIR" ]] && { echo "[ERR] Security 目錄不存在: $SECURITY_DIR"; exit 1; }
command -v codeql >/dev/null 2>&1 || { echo "[ERR] 未找到 codeql，請先安裝"; exit 1; }

mkdir -p "$DB_ROOT" "$OUT_DIR"

proj_base="$(basename "$(realpath "$PROJECT")")"
DB_DIR="${DB_ROOT%/}/${proj_base}"
mkdir -p "${OUT_DIR%/}/${proj_base}"

echo "[*] 建立 CodeQL DB: $DB_DIR"
DB_CREATE_ARGS=( database create "$DB_DIR" --language=python --source-root "$PROJECT" )
[[ -n "$THREADS" ]] && DB_CREATE_ARGS+=( --threads="$THREADS" )
[[ "$OVERWRITE" == "true" ]] && DB_CREATE_ARGS+=( --overwrite )
codeql "${DB_CREATE_ARGS[@]}"

declare -A BANDIT_BY_CWE=(
  ["022"]="B202"
  ["078"]="B102,B601,B602,B603,B604,B605,B606,B607,B609"
  ["079"]="B704"
  ["326"]="B505"
  ["327"]="B324,B502,B503,B504"
  ["502"]="B506"
)

pad3() { printf "%03d" "$((10#$1))"; }

declare -a SEARCH_DIRS QUERIES
declare -A SEEN_DIR
add_dirs_for_cwe() {
  local num="$1" padded
  if [[ "$num" =~ ^[0-9]+$ && ${#num} -lt 3 ]]; then padded=$(pad3 "$num"); else padded="$num"; fi
  local dir1="${SECURITY_DIR}/CWE-${padded}"
  [[ -d "$dir1" ]] && SEARCH_DIRS+=("$dir1")
}
for cwe in "${CWE_LIST[@]}"; do add_dirs_for_cwe "$cwe"; done
for d in "${SEARCH_DIRS[@]}"; do
  [[ -n "${SEEN_DIR[$d]:-}" ]] && continue
  SEEN_DIR[$d]=1
  while IFS= read -r -d '' q; do QUERIES+=("$q"); done < <(find "$d" -type f -name '*.ql' -print0)
done
if [[ ${#QUERIES[@]} -eq 0 ]]; then
  echo "[WARN] 找不到任何 CodeQL 查詢"; exit 2
fi

bandit_pid=""
if command -v bandit >/dev/null 2>&1; then
  (
    echo "[*] Bandit:開始依 CWE 執行"
    for cwe in "${CWE_LIST[@]}"; do
      tests="${BANDIT_BY_CWE[$cwe]:-}"
      [[ -z "$tests" ]] && { echo "  - CWE-$cwe 無對應 Bandit 規則，略過"; continue; }
      padded="$(pad3 "$cwe")"
      outdir="${OUT_DIR%/}/${proj_base}/bandit/CWE-${padded}"
      mkdir -p "$outdir"
      echo "  -> CWE-${padded} (tests: $tests)"
      bandit -r "$PROJECT" -t "$tests" -f csv  -o "${outdir}/report.csv"  || true
    done
    echo "[*] Bandit:完成"
  ) &
  bandit_pid=$!
else
  echo "[INFO] 未找到 bandit，跳過 Bandit 掃描"
fi

echo "[*] CodeQL:共找到 ${#QUERIES[@]} 支查詢，開始執行…"
for q in "${QUERIES[@]}"; do
  rel="${q#${SECURITY_DIR}/}"
  subdir="$(dirname "$rel")"
  qname="$(basename "$q" .ql)"
  out_sub="${OUT_DIR%/}/${proj_base}/${subdir}"
  mkdir -p "$out_sub"

  bqrs="${out_sub}/${qname}.bqrs"
  csv="${out_sub}/${qname}.csv"

  printf "  -> %-40s\n" "$rel"
  QR_ARGS=( query run --database "$DB_DIR" "$q" --output "$bqrs" )
  [[ -n "$THREADS" ]] && QR_ARGS+=( --threads="$THREADS" )
  codeql "${QR_ARGS[@]}"

  codeql bqrs decode "$bqrs" --format=csv --output "$csv" || true
  rm -f -- "$bqrs"
done
echo "[*] CodeQL:完成"

if [[ -n "$bandit_pid" ]]; then
  wait "$bandit_pid"
fi

echo "[OK] 全部完成。輸出在:${OUT_DIR%/}/${proj_base}"
