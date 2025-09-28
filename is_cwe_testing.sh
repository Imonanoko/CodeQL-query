#!/usr/bin/env bash
set -euo pipefail

DEFAULT_SECURITY_DIR="${HOME}/.codeql/packages/codeql/python-queries/1.6.5/Security"

usage() {
  cat <<'USAGE'
Usage:
  is_cwe_testing.sh --project <PROJECT_DIR> --cwe <CWE_ID|CWE_ID,CWE_ID,...> \
    [--db-dir <DB_ROOT>] [--security-dir <DIR>] [--out <OUT_DIR>] [--threads <N>] [--overwrite]

Notes:
- 建議一次只給一個 CWE(腳本會針對該 CWE 完整執行 CodeQL / Bandit / Semgrep)。
- 若你用逗號提供多個，腳本會逐條序列跑(每條彼此獨立，較不易互相影響)。

輸出:
- CodeQL : <OUT>/<project>/<CWE-XXX>/<QueryName>.csv
- Bandit : <OUT>/<project>/bandit/CWE-XXX/report.csv
- Semgrep: <OUT>/<project>/semgrep/CWE-XXX/<rule>.json
USAGE
}

PROJECT=""
DB_ROOT="./db"
SECURITY_DIR="$DEFAULT_SECURITY_DIR"
OUT_DIR="./results"
THREADS=""
OVERWRITE="false"
RAW_CWE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:-}"; shift 2 ;;
    --db-dir) DB_ROOT="${2:-}"; shift 2 ;;
    --security-dir) SECURITY_DIR="${2:-}"; shift 2 ;;
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    --threads) THREADS="${2:-}"; shift 2 ;;
    --overwrite) OVERWRITE="true"; shift ;;
    --cwe) RAW_CWE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

[[ -z "$PROJECT" ]] && { echo "[ERR] --project 必填"; usage; exit 1; }
[[ -z "$RAW_CWE"  ]] && { echo "[ERR] --cwe 必填(單一或逗號清單)"; usage; exit 1; }
[[ ! -d "$PROJECT" ]] && { echo "[ERR] 專案目錄不存在: $PROJECT"; exit 1; }
command -v codeql >/dev/null 2>&1 || { echo "[ERR] 未找到 codeql，請先安裝"; exit 1; }

if [[ "$RAW_CWE" == *","* ]]; then
  IFS=',' read -r -a _parts <<< "$RAW_CWE"
  for _one in "${_parts[@]}"; do
    _one="${_one//CWE-/}"; _one="${_one//cwe-/}"; _one="${_one// /}"
    [[ -z "$_one" ]] && continue
    echo "===================="
    echo "[*] 逐條模式:開始處理 CWE-$_one"
    bash "$0" --project "$PROJECT" --cwe "$_one" \
      --db-dir "$DB_ROOT" --out "$OUT_DIR" --security-dir "$SECURITY_DIR" \
      ${THREADS:+--threads "$THREADS"} ${OVERWRITE:+"--overwrite"}
    echo "[*] 完成 CWE-$_one"
  done
  exit 0
fi

CWE="${RAW_CWE//CWE-/}"; CWE="${CWE//cwe-/}"; CWE="${CWE// /}"

pad3() { printf "%03d" "$((10#$1))"; }

mkdir -p "$DB_ROOT" "$OUT_DIR"
proj_base="$(basename "$(realpath "$PROJECT")")"
DB_DIR="${DB_ROOT%/}/${proj_base}"
mkdir -p "${OUT_DIR%/}/${proj_base}"

if [[ ! -d "$SECURITY_DIR" ]] || ! find "$SECURITY_DIR" -maxdepth 1 -type d -name 'CWE-*' | read -r _; then
  cand_dir="$(ls -d "$HOME"/.codeql/packages/codeql/python-queries/*/Security 2>/dev/null | sort -V | tail -n1 || true)"
  if [[ -n "$cand_dir" && -d "$cand_dir" ]]; then
    echo "[INFO] 既定 SECURITY_DIR 無效，改用最新:$cand_dir"
    SECURITY_DIR="$cand_dir"
  else
    echo "[ERR] 找不到任何 python-queries/*/Security 目錄。請先:codeql pack install codeql/python-queries"
    exit 1
  fi
fi

if [[ -d "$DB_DIR" && "$OVERWRITE" != "true" ]]; then
  echo "[*] 發現既有 DB:$DB_DIR(沿用;如需重建請加 --overwrite)"
else
  echo "[*] 建立 CodeQL DB: $DB_DIR"
  DB_CREATE_ARGS=( database create "$DB_DIR" --language=python --source-root "$PROJECT" )
  [[ -n "$THREADS" ]] && DB_CREATE_ARGS+=( --threads="$THREADS" )
  [[ "$OVERWRITE" == "true" ]] && DB_CREATE_ARGS+=( --overwrite )
  codeql "${DB_CREATE_ARGS[@]}"
fi

declare -A BANDIT_BY_CWE=(
  ["022"]="B202"
  ["078"]="B102,B601,B602,B603,B604,B605,B606,B607,B609"
  ["079"]="B704"
  ["326"]="B505"
  ["327"]="B324,B502,B503,B504"
  ["502"]="B506"
)
declare -A SEMPY_BY_CWE=(
  [022]="python.tarfile-extractall-traversal.tarfile-extractall-traversal"
  [078]="python.lang.security.audit.subprocess-shell-true.subprocess-shell-true python.lang.security.audit.dangerous-os-exec.dangerous-os-exec"
  [079]="python.flask.security.xss.audit.direct-use-of-jinja2.direct-use-of-jinja2 python.django.security.audit.avoid-mark-safe.avoid-mark-safe"
  [095]="python.lang.security.audit.eval-detected.eval-detected python.lang.security.audit.exec-detected.exec-detected"
  [326]="python.cryptography.security.empty-aes-key.empty-aes-key"
  [327]="python.lang.security.audit.crypto.use-of-md5.use-of-md5 lang.security.audit.crypto.use-of-sha1.use-of-sha1"
  [347]="python.jwt.security.audit.jwt-decode-without-verify.jwt-decode-without-verify"
  [377]="gitlab.bandit.B108"
  [502]="python.lang.security.deserialization.avoid-pyyaml-load.avoid-pyyaml-load python.lang.security.deserialization.pickle.avoid-pickle"
  [643]="python.lang.security.injection.xpath"
  [918]="python.flask.security.injection.ssrf-requests.ssrf-requests"
  [943]="python.lang.security.audit.formatted-sql-query.formatted-sql-query"
)

CWE_PAD="$(pad3 "$CWE")"
CWE_DIR="${SECURITY_DIR}/CWE-${CWE_PAD}"
declare -a QUERIES=()
if [[ -d "$CWE_DIR" ]]; then
  while IFS= read -r -d '' q; do QUERIES+=("$q"); done < <(find "$CWE_DIR" -type f -name '*.ql' -print0)
  echo "[*] CodeQL: CWE-${CWE_PAD} 找到 ${#QUERIES[@]} 支查詢"
else
  echo "[INFO] CodeQL: Security pack 中不存在 CWE-${CWE_PAD} 目錄(將跳過 CodeQL)"
fi

if [[ ${#QUERIES[@]} -gt 0 ]]; then
  for q in "${QUERIES[@]}"; do
    rel="${q#${SECURITY_DIR}/}"
    out_sub="${OUT_DIR%/}/${proj_base}/codeql/$(dirname "$rel")"
    mkdir -p "$out_sub"
    bqrs="${out_sub}/$(basename "$q" .ql).bqrs"
    csv="${out_sub}/$(basename "$q" .ql).csv"

    printf "  -> CodeQL  %s\n" "$rel"
    QR_ARGS=( query run --database "$DB_DIR" "$q" --output "$bqrs" )
    [[ -n "$THREADS" ]] && QR_ARGS+=( --threads="$THREADS" )
    if ! codeql "${QR_ARGS[@]}"; then
      echo "     [WARN] CodeQL 執行失敗，跳過:$rel"
      rm -f -- "$bqrs"
      continue
    fi
    codeql bqrs decode "$bqrs" --format=csv --output "$csv" || true
    rm -f -- "$bqrs"
  done
else
  echo "[INFO] CodeQL:此 CWE 無可執行查詢(已跳過)"
fi

if command -v bandit >/dev/null 2>&1; then
  tests="${BANDIT_BY_CWE[$CWE]:-}"
  if [[ -n "$tests" ]]; then
    outdir="${OUT_DIR%/}/${proj_base}/bandit/CWE-${CWE_PAD}"
    mkdir -p "$outdir"
    echo "  -> Bandit  tests=${tests}"
    bandit -r "$PROJECT" -t "$tests" -f csv -o "${outdir}/report.csv" || true
  else
    echo "[INFO] Bandit:CWE-${CWE_PAD} 無對應規則(略過)"
  fi
else
  echo "[INFO] 未找到 bandit，跳過 Bandit 掃描(建議用 venv/pip 安裝)"
fi

if command -v semgrep >/dev/null 2>&1; then
  rules="${SEMPY_BY_CWE[$CWE]:-}"
  if [[ -n "$rules" ]]; then
    outdir="${OUT_DIR%/}/${proj_base}/semgrep/CWE-${CWE_PAD}"
    mkdir -p "$outdir"
    for rid in $rules; do
      safe="$(echo "$rid" | sed 's#[^A-Za-z0-9._-]#_#g')"
      echo "  -> Semgrep ${rid}"
      semgrep --config "ruleset_id=${rid}" --json -o "${outdir}/${safe}.json" "$PROJECT" || true
    done
  else
    echo "[INFO] Semgrep:CWE-${CWE_PAD} 無精準規則(略過)"
  fi
else
  echo "[INFO] 未找到 semgrep，跳過 Semgrep 掃描(安裝:pip/pipx/或 Docker)"
fi

echo "[OK] 完成 CWE-${CWE_PAD}。輸出在:${OUT_DIR%/}/${proj_base}"
