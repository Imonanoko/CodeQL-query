#!/bin/bash
# example: ./cpp_autoql.sh yt-dlp ./projects/yt-dlp/
if [[ $# -ne 2 ]]; then
    echo "Usage: $(basename "$0") <db name> <project root>"
    exit 1
fi
DB_NAME="$1"
SRC_ROOT="$2"

codeql_db_dir="/home/sixsquare/codeQL/db"
output_dir="/home/sixsquare/codeQL/cpp_preprocessing/cpp_query_output/$DB_NAME"
ql_dir="/home/sixsquare/codeQL/cpp-ql"
echo "建立輸出資料夾: $output_dir"
mkdir -p "$output_dir"
ql_list=("CWE-022" "CWE-078" "CWE-079" "CWE-095" "CWE-113" "CWE-117" "CWE-326" "CWE-327" "CWE-329" "CWE-347" "CWE-377" "CWE-502" "CWE-643" "CWE-760" "CWE-918" "CWE-943" "CWE-1333")
pushd "$SRC_ROOT" >/dev/null #先切換到project的專案
codeql database create "$codeql_db_dir/$DB_NAME" --language=cpp --source-root "${pwd}" --command 'bash -lc "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build --parallel $(nproc)"' --threads=0 --overwrite
popd >/dev/null #跳回原本執行目錄
if [[ ! -d "$codeql_db_dir/$DB_NAME/db-cpp" ]]; then
  echo "codeql 無法成功編譯 $DB_NAME project."
  exit 1
fi

for cwe_number in "${ql_list[@]}";do
    codeql query run "${ql_dir}/${cwe_number}.ql" --database "$codeql_db_dir/$DB_NAME" --output "${output_dir}/${cwe_number}.bqrs"
    codeql bqrs decode --format=csv --output "${output_dir}/${cwe_number}.csv" "${output_dir}/${cwe_number}.bqrs"
done
python3 /home/sixsquare/codeQL/gen_cwe_json.py ${output_dir} $DB_NAME
rm -f "${output_dir}"/*.bqrs
exit 0