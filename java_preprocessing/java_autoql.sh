#!/bin/bash
# example: ./java_autoql.sh owner__repo ../projects/owner__repo/
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $(basename "$0") <db name> <project root>"
  exit 1
fi

DB_NAME="$1"
SRC_ROOT="$2"

codeql_db_dir="/home/sixsquare/codeQL/db"
output_dir="/home/sixsquare/codeQL/java_preprocessing/java_query_output/$DB_NAME"
ql_dir="/home/sixsquare/codeQL/java-ql"
gen_json_py="/home/sixsquare/codeQL/gen_cwe_json.py"

echo "建立輸出資料夾: $output_dir"
mkdir -p "$output_dir"

ql_list=("CWE-022" "CWE-078" "CWE-079" "CWE-095" "CWE-113" "CWE-117" "CWE-326" "CWE-327" "CWE-329" "CWE-347" "CWE-377" "CWE-502" "CWE-643" "CWE-760" "CWE-918" "CWE-943" "CWE-1333")

trim() { sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' ; }

norm_java_major() {
  local v="$1"
  v="$(echo "$v" | trim)"
  v="${v//\"/}"
  v="${v//\'/}"
  if [[ -z "$v" ]]; then
    echo ""
    return 0
  fi
  if [[ "$v" =~ ^1\.8($|[^0-9]) ]]; then
    echo "8"
    return 0
  fi
  if [[ "$v" =~ ^([0-9]+) ]]; then
    echo "${BASH_REMATCH[1]}"
    return 0
  fi
  echo ""
}

find_jdk_home_major() {
  local major="$1"
  [[ -n "$major" ]] || return 1

  local candidates=(
    "/usr/lib/jvm/java-${major}-openjdk-amd64"
    "/usr/lib/jvm/java-${major}-openjdk"
  )

  for c in "${candidates[@]}"; do
    if [[ -x "$c/bin/java" ]]; then
      echo "$c"
      return 0
    fi
  done

  local hit
  hit="$(ls -1d /usr/lib/jvm/* 2>/dev/null \
    | grep -E "(^|/)(java|jdk|temurin|zulu).*(^|[^0-9])${major}([^0-9]|$)" \
    | head -n 1 || true)"
  if [[ -n "$hit" && -x "$hit/bin/java" ]]; then
    echo "$hit"
    return 0
  fi

  return 1
}

maven_requested_java_major() {
  [[ -f "pom.xml" ]] || { echo ""; return 0; }

  local v=""
  v="$(sed -n 's:.*<maven\.compiler\.release>\(.*\)</maven\.compiler\.release>.*:\1:p' pom.xml | head -n1 | trim)"
  if [[ -z "$v" ]]; then
    v="$(sed -n 's:.*<maven\.compiler\.source>\(.*\)</maven\.compiler\.source>.*:\1:p' pom.xml | head -n1 | trim)"
  fi
  if [[ -z "$v" ]]; then
    v="$(sed -n 's:.*<maven\.compiler\.target>\(.*\)</maven\.compiler\.target>.*:\1:p' pom.xml | head -n1 | trim)"
  fi
  if [[ -z "$v" ]]; then
    v="$(sed -n 's:.*<java\.version>\(.*\)</java\.version>.*:\1:p' pom.xml | head -n1 | trim)"
  fi

  norm_java_major "$v"
}

gradle_requested_java_major() {
  if [[ -f "gradle.properties" ]]; then
    local home
    home="$(grep -E '^[[:space:]]*org\.gradle\.java\.home[[:space:]]*=' gradle.properties 2>/dev/null | head -n1 | cut -d= -f2- | trim || true)"
    if [[ -n "$home" ]]; then
      if [[ "$home" =~ (1\.8|8)([^0-9]|$) ]]; then echo "8"; return 0; fi
      if [[ "$home" =~ (11)([^0-9]|$) ]]; then echo "11"; return 0; fi
      if [[ "$home" =~ (17)([^0-9]|$) ]]; then echo "17"; return 0; fi
      if [[ "$home" =~ (21)([^0-9]|$) ]]; then echo "21"; return 0; fi
    fi
  fi

  local f=""
  if [[ -f "build.gradle.kts" ]]; then
    f="build.gradle.kts"
  elif [[ -f "build.gradle" ]]; then
    f="build.gradle"
  else
    echo ""
    return 0
  fi

  local line
  line="$(grep -E 'sourceCompatibility|targetCompatibility|JavaLanguageVersion\.of|VERSION_' "$f" 2>/dev/null | head -n 1 || true)"

  if [[ "$line" =~ VERSION_1_8 ]]; then echo "8"; return 0; fi
  if [[ "$line" =~ VERSION_11 ]]; then echo "11"; return 0; fi
  if [[ "$line" =~ VERSION_17 ]]; then echo "17"; return 0; fi
  if [[ "$line" =~ VERSION_21 ]]; then echo "21"; return 0; fi
  if [[ "$line" =~ JavaLanguageVersion\.of\(([0-9]+)\) ]]; then echo "${BASH_REMATCH[1]}"; return 0; fi

  local num
  num="$(echo "$line" | grep -Eo "1\.8|[0-9]{2}" | head -n1 || true)"
  norm_java_major "$num"
}

detect_build() {
  local tool=""
  local cmd=""

  if [[ -f "./mvnw" || -f "pom.xml" ]]; then
    tool="maven"
    if [[ -f "./mvnw" ]]; then
      chmod +x ./mvnw || true
      cmd='./mvnw -q -DskipTests -Dmaven.test.skip=true -DskipITs package'
    else
      cmd='mvn -q -DskipTests -Dmaven.test.skip=true -DskipITs package'
    fi
    echo "${tool}|${cmd}"
    return 0
  fi

  if [[ -f "./gradlew" || -f "build.gradle" || -f "build.gradle.kts" || -f "settings.gradle" || -f "settings.gradle.kts" ]]; then
    tool="gradle"
    if [[ -f "./gradlew" ]]; then
      chmod +x ./gradlew || true
      cmd='./gradlew -q build -x test --no-daemon'
    else
      # For batch stability: prefer buildless if no wrapper (many repos won't build reliably)
      cmd=''
    fi
    echo "${tool}|${cmd}"
    return 0
  fi

  if [[ -f "build.xml" ]]; then
    tool="ant"
    cmd='ant -q jar || ant -q compile'
    echo "${tool}|${cmd}"
    return 0
  fi

  echo "none|"
}

select_java_for_repo() {
  local major=""
  if [[ -f "pom.xml" ]]; then
    major="$(maven_requested_java_major)"
  elif [[ -f "build.gradle" || -f "build.gradle.kts" || -f "gradle.properties" ]]; then
    major="$(gradle_requested_java_major)"
  fi

  if [[ -z "$major" ]]; then
    major="17"
  fi

  local home=""
  if home="$(find_jdk_home_major "$major")"; then
    export JAVA_HOME="$home"
    export PATH="$JAVA_HOME/bin:$PATH"
    echo "[+] Selected JAVA_HOME=$JAVA_HOME (major=$major)"
    java -version 2>&1 | sed 's/^/[+] /'
    return 0
  fi

  echo "[!] Requested Java major=$major but no matching JDK found under /usr/lib/jvm"
  echo "[!] Will keep current JAVA_HOME (if any) and may fallback to --build-mode=none"
  return 1
}

create_db_none() {
  local db_path="$1"
  echo "[+] Creating CodeQL DB with --build-mode=none"
  codeql database create "$db_path" \
    --language=java \
    --source-root "${PWD}" \
    --build-mode=none \
    --threads=0 \
    --overwrite
}

pushd "$SRC_ROOT" >/dev/null

select_java_for_repo || true

detected="$(detect_build)"
build_tool="${detected%%|*}"
build_cmd="${detected#*|}"

echo "[+] Detected build tool: ${build_tool}"
if [[ -n "${build_cmd}" ]]; then
  echo "[+] Build command: ${build_cmd}"
else
  echo "[+] Build command: (none)"
fi

db_path="$codeql_db_dir/$DB_NAME"
rm -rf "$db_path" || true

run_create_with_cmd() {
  local cmd="$1"
  set +e
  codeql database create "$db_path" \
    --language=java \
    --source-root "${PWD}" \
    --command "bash -lc \"export JAVA_HOME='$JAVA_HOME'; export PATH='$JAVA_HOME/bin:$PATH'; $cmd\"" \
    --threads=0 \
    --overwrite
  rc=$?
  set -e
  return $rc
}

if [[ "$build_tool" == "maven" ]]; then
  build_cmd="timeout 30m $build_cmd"
  if ! run_create_with_cmd "$build_cmd"; then
    echo "[!] Maven build failed, fallback to --build-mode=none"
    rm -rf "$db_path" || true
    create_db_none "$db_path"
  fi

elif [[ "$build_tool" == "gradle" ]]; then
  if [[ -z "$build_cmd" ]]; then
    echo "[+] Gradle without wrapper detected -> use --build-mode=none"
    create_db_none "$db_path"
  else
    build_cmd="timeout 45m $build_cmd"
    if ! run_create_with_cmd "$build_cmd"; then
      echo "[!] Gradle build failed, fallback to --build-mode=none"
      rm -rf "$db_path" || true
      create_db_none "$db_path"
    fi
  fi

elif [[ "$build_tool" == "ant" ]]; then
  build_cmd="timeout 30m $build_cmd"
  if ! run_create_with_cmd "$build_cmd"; then
    echo "[!] Ant build failed, fallback to --build-mode=none"
    rm -rf "$db_path" || true
    create_db_none "$db_path"
  fi

else
  echo "[+] No build tool detected, use --build-mode=none"
  create_db_none "$db_path"
fi

popd >/dev/null

if ! ls -d "$db_path"/db-* >/dev/null 2>&1; then
  echo "[!] codeql 無法成功建立 Java DB: $DB_NAME"
  echo "[!] DB path: $db_path"
  exit 1
fi

for cwe_number in "${ql_list[@]}"; do
  ql_file="${ql_dir}/${cwe_number}.ql"
  if [[ ! -f "$ql_file" ]]; then
    echo "[!] Missing query: $ql_file"
    exit 1
  fi

  codeql query run "$ql_file" \
    --database "$db_path" \
    --output "${output_dir}/${cwe_number}.bqrs"

  codeql bqrs decode \
    --format=csv \
    --output "${output_dir}/${cwe_number}.csv" \
    "${output_dir}/${cwe_number}.bqrs"
done

python3 "$gen_json_py" "$output_dir" "$DB_NAME"

rm -f "${output_dir}"/*.bqrs
rm -rf "$db_path"
exit 0
