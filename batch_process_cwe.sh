#!/bin/bash
# filepath: batch_process_cwe.sh

# ==================== 設定參數區域 ====================
# 向上額外刪除的行數
ABOVE_LINES=0

# 向下額外刪除的行數
BELOW_LINES=0

# 刪除模式 (call/caller/bb)
MODE="call"
# ====================================================

# 目錄設定
PROJECTS_DIR="./projects"
OUTPUT_BASE_DIR="./rm_output"
JSON_DIR="./python_query_output"

# 要處理的 CWE 列表
CWES=(
    "020"
    "022" 
    "078"
    "079"
    "095"
    "113"
    "117"
    "326"
    "327"
    "329"
    "347"
    "377"
    "400"
    "502"
    "643"
    "732"
    "760"
    "918"
    "943"
    "1333"
)

echo "=== 批次處理 CWE 漏洞程式碼刪除 ==="
echo "向上刪除行數: $ABOVE_LINES"
echo "向下刪除行數: $BELOW_LINES"
echo "處理模式: $MODE"
echo "========================================="

# 檢查必要目錄是否存在
if [ ! -d "$PROJECTS_DIR" ]; then
    echo "錯誤: 找不到專案目錄 $PROJECTS_DIR"
    exit 1
fi

if [ ! -d "$JSON_DIR" ]; then
    echo "錯誤: 找不到 JSON 目錄 $JSON_DIR"
    exit 1
fi

# 建立基礎輸出目錄
mkdir -p "$OUTPUT_BASE_DIR"

# 統計變數
total_projects=0
processed_projects=0
total_operations=0
successful_operations=0

# 計算總專案數
for project_dir in "$PROJECTS_DIR"/*; do
    if [ -d "$project_dir" ]; then
        ((total_projects++))
    fi
done

echo "發現 $total_projects 個專案"
echo ""

# 處理每個專案
for project_dir in "$PROJECTS_DIR"/*; do
    if [ -d "$project_dir" ]; then
        project_name=$(basename "$project_dir")
        json_file="$JSON_DIR/$project_name/$project_name.json"
        
        echo "處理專案: $project_name"
        
        if [ ! -f "$json_file" ]; then
            echo "  ⚠️  警告: 找不到 JSON 檔案: $json_file"
            echo "  ⏭️  跳過此專案"
            echo ""
            continue
        fi
        
        ((processed_projects++))
        project_success=0
        
        # 為每個 CWE 進行處理
        for cwe in "${CWES[@]}"; do
            echo "  處理 CWE-$cwe ..."
            
            # 建立 CWE 特定的輸出目錄
            cwe_output_dir="$OUTPUT_BASE_DIR/CWE-$cwe"
            mkdir -p "$cwe_output_dir"
            
            ((total_operations++))
            
            # 執行刪除操作
            if python3 rm_project_call_function.py "$project_dir" \
                --json "$json_file" \
                --cwe "$cwe" \
                --mode "$MODE" \
                --above "$ABOVE_LINES" \
                --below "$BELOW_LINES" \
                -o "$cwe_output_dir" > /dev/null 2>&1; then
                
                echo "    ✅ CWE-$cwe 處理成功"
                ((successful_operations++))
                ((project_success++))
            else
                echo "    ❌ CWE-$cwe 處理失敗"
            fi
        done
        
        echo "  📊 專案 $project_name 完成: $project_success/${#CWES[@]} 個 CWE 處理成功"
        echo ""
    fi
done

echo "========================================="
echo "📈 處理總結:"
echo "  總專案數: $total_projects"
echo "  已處理專案: $processed_projects"
echo "  總操作數: $total_operations"
echo "  成功操作數: $successful_operations"
echo "  成功率: $(( successful_operations * 100 / total_operations ))%" 2>/dev/null || echo "  成功率: N/A"
echo ""
echo "🗂️  輸出目錄結構:"
for cwe in "${CWES[@]}"; do
    cwe_dir="$OUTPUT_BASE_DIR/CWE-$cwe"
    if [ -d "$cwe_dir" ]; then
        count=$(find "$cwe_dir" -maxdepth 1 -type d | wc -l)
        count=$((count - 1))  # 扣除目錄本身
        echo "  CWE-$cwe/: $count 個處理結果"
    fi
done
echo ""
echo "✨ 批次處理完成！"