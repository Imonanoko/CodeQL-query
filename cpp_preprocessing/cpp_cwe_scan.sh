#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  is_cwe_testing_c_cpp.sh --project <PROJECT_DIR> --cwe <CWE_ID|CWE_ID,CWE_ID,...> \
    [--out <OUT_DIR>] [--threads <N>] [--overwrite]

說明:
- 給 C/C++ 專案用的實驗腳本。
- 工具：
    - Flawfinder: 每個 CWE 個別跑一次 (--csv + --dataonly + --regex)。
    - Cppcheck  : 全專案只掃描一次 (XML)，之後每個 CWE 只從 XML 過濾 <error>。

輸出目錄結構 (以 <OUT> = ./results、專案名 foo 為例):
- Flawfinder:
    ./results/foo/flawfinder/CWE-022/report.csv
    ./results/foo/flawfinder/CWE-078/report.csv
    ...
- Cppcheck:
    ./results/foo/cppcheck/_all/cppcheck_full.xml
    ./results/foo/cppcheck/CWE-022/cppcheck_cwe_022.xml
    ./results/foo/cppcheck/CWE-078/cppcheck_cwe_078.xml
USAGE
}

PROJECT=""
OUT_DIR="./results"
THREADS=""
OVERWRITE="false"
RAW_CWE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) PROJECT="${2:-}"; shift 2 ;;
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

declare -a CWE_LIST=()

RAW_CWE_LIST="${RAW_CWE//,/ }"

for token in $RAW_CWE_LIST; do
  t="${token//CWE-/}"
  t="${t//cwe-/}"
  t="${t// /}"
  [[ -z "$t" ]] && continue
  if [[ "$t" =~ ^[0-9]+$ ]]; then
    CWE_LIST+=("$t")
  else
    echo "[WARN] 忽略無效 CWE: '$token'"
  fi
done

if [[ ${#CWE_LIST[@]} -eq 0 ]]; then
  echo "[ERR] 從 --cwe 參數中沒有解析出任何有效 CWE 數字"
  exit 1
fi

pad3() { printf "%03d" "$((10#$1))"; }

mkdir -p "$OUT_DIR"
proj_base="$(basename "$(realpath "$PROJECT")")"
proj_out="${OUT_DIR%/}/${proj_base}"
mkdir -p "$proj_out"

echo "[*] 專案: $proj_base"
echo "[*] CWE 清單: ${CWE_LIST[*]}"
echo "[*] 輸出根目錄: $proj_out"

global_cpp_dir="${proj_out}/cppcheck/_all"
global_cpp_xml="${global_cpp_dir}/cppcheck_full.xml"

if command -v cppcheck >/dev/null 2>&1; then
  mkdir -p "$global_cpp_dir"

  if [[ -f "$global_cpp_xml" && "$OVERWRITE" != "true" ]]; then
    echo "[*] Cppcheck: 使用既有全域 XML: $global_cpp_xml (如需重跑請加 --overwrite)"
  else
    echo "[*] Cppcheck: 全專案掃描一次，輸出 XML -> $global_cpp_xml"
    cpp_args=(
      --enable=all
      --inconclusive
      --xml
      --xml-version=2
    )
    [[ -n "$THREADS" ]] && cpp_args+=( -j "$THREADS" )

    cppcheck "${cpp_args[@]}" "$PROJECT" \
      1> "${global_cpp_dir}/cppcheck_stdout.log" \
      2> "$global_cpp_xml" || true
  fi
else
  echo "[INFO] 未找到 cppcheck，將略過所有 Cppcheck 步驟"
fi

for CWE_RAW in "${CWE_LIST[@]}"; do
  CWE_NUM=$((10#$CWE_RAW))
  CWE_PAD="$(pad3 "$CWE_NUM")"

  echo "===================="
  echo "[*] 處理 CWE-${CWE_PAD} (數值=${CWE_NUM})"

  if command -v flawfinder >/dev/null 2>&1; then
    ff_outdir="${proj_out}/flawfinder/CWE-${CWE_PAD}"

    if [[ -d "$ff_outdir" && "$OVERWRITE" != "true" ]]; then
      echo "  [Flawfinder] 發現既有輸出 $ff_outdir (沿用; 如需重跑請加 --overwrite)"
    else
      mkdir -p "$ff_outdir"
      echo "  [Flawfinder] 掃描 CWE-${CWE_PAD}"

      flawfinder --csv --dataonly --regex "CWE-${CWE_NUM}" "$PROJECT" \
        > "${ff_outdir}/report.csv" \
        2> "${ff_outdir}/flawfinder_stderr.log" || true
    fi
  else
    echo "  [Flawfinder] 未安裝 flawfinder，略過"
  fi

  if [[ -f "$global_cpp_xml" ]]; then
    cpp_outdir="${proj_out}/cppcheck/CWE-${CWE_PAD}"
    mkdir -p "$cpp_outdir"
    cwe_xml="${cpp_outdir}/cppcheck_cwe_${CWE_PAD}.xml"

    if [[ -f "$cwe_xml" && "$OVERWRITE" != "true" ]]; then
      echo "  [Cppcheck] 已存在: $cwe_xml (沿用; 如需重建請加 --overwrite)"
    else
      echo "  [Cppcheck] 從全域 XML 中過濾出 cwe=\"${CWE_NUM}\" 的 <error>"

      awk -v CWE_VAL="$CWE_NUM" '
        BEGIN {
          print "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";
          print "<results>";
          print "  <errors>";
          inerr = 0;
          has = 0;
          block = "";
        }
        /<error / {
          inerr = 1;
          block = $0 "\n";
          has = ( $0 ~ ("cwe=\"" CWE_VAL "\"") );
          next;
        }
        inerr {
          block = block $0 "\n";
          if ($0 ~ ("cwe=\"" CWE_VAL "\"")) has = 1;
          if ($0 ~ /<\/error>/) {
            if (has) {
              gsub(/^/, "    ", block);  # 縮排一下
              printf "%s", block;
            }
            inerr = 0;
            has = 0;
            block = "";
          }
          next;
        }
        END {
          print "  </errors>";
          print "</results>";
        }
      ' "$global_cpp_xml" > "$cwe_xml" || true
    fi
  else
    echo "  [Cppcheck] 全域 XML 不存在 (可能沒安裝 cppcheck 或前面執行失敗)，略過"
  fi

  echo "[OK] 完成 CWE-${CWE_PAD}"
done

echo "===================="
echo "[OK] 全部 CWE 處理完成，輸出根目錄: $proj_out"
