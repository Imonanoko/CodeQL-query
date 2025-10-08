#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批次處理 CWE 漏洞程式碼刪除工具
"""

import os
import sys
import subprocess
from pathlib import Path
import argparse
import json
import shutil
import csv
import datetime
import logging

# ==================== 設定參數區域 ====================
# 向上額外刪除的行數
ABOVE_LINES = 0

# 向下額外刪除的行數
BELOW_LINES = 0

# 刪除模式 (call/caller/bb)
MODE = "call"
# ====================================================

# 要處理的 CWE 列表
#"022", "078", "079", "095", "113", "117", "326", "327", "329", "347", "377", "502", "643", "760", "918", "943", "1333"
CWES = ["022"]
def print_colored(text, color="white"):
    """簡單的顏色輸出函數，同時記錄到日誌"""
    colors = {
        "red": "\033[91m",
        "green": "\033[92m", 
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "reset": "\033[0m"
    }
    formatted_text = f"{colors.get(color, colors['white'])}{text}{colors['reset']}"
    print(formatted_text)
    
    # 同時記錄到日誌（去除顏色代碼）
    if hasattr(print_colored, 'logger'):
        clean_text = text  # 日誌中不包含顏色代碼
        if color == "red":
            print_colored.logger.error(clean_text)
        elif color == "yellow":
            print_colored.logger.warning(clean_text)
        elif color in ["green", "cyan"]:
            print_colored.logger.info(clean_text)
        else:
            print_colored.logger.info(clean_text)

def check_vulnerabilities_found(cwe_output_dir, project_name):
    """
    檢查是否確實發現了漏洞
    返回發現的漏洞數量，如果沒有發現則返回 0
    """
    import json
    
    # 尋找專案輸出目錄
    project_dirs = [d for d in cwe_output_dir.iterdir() if d.is_dir() and project_name in d.name]
    
    if not project_dirs:
        return 0
    
    total_vulnerabilities = 0
    
    for project_dir in project_dirs:
        # 檢查 removed_ranges.json 檔案
        removed_ranges_file = project_dir / "removed_ranges.json"
        if removed_ranges_file.exists():
            try:
                with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                # 計算實際有內容的檔案數量
                non_empty_files = sum(1 for file_ranges in data.values() if file_ranges)
                total_vulnerabilities += non_empty_files
            except (json.JSONDecodeError, Exception):
                pass
        
        # 檢查 prompt.txt 檔案是否為空
        prompt_file = project_dir / "prompt.txt"
        if prompt_file.exists():
            try:
                content = prompt_file.read_text(encoding='utf-8').strip()
                if not content:
                    # prompt.txt 是空的，表示沒有發現漏洞
                    continue
                else:
                    # prompt.txt 有內容，表示發現了漏洞
                    total_vulnerabilities += len(content.splitlines())
            except Exception:
                pass
    
    return total_vulnerabilities

def cleanup_empty_output(cwe_output_dir, project_name):
    """
    清理沒有發現漏洞的專案輸出目錄
    """
    import shutil
    
    # 尋找專案輸出目錄
    project_dirs = [d for d in cwe_output_dir.iterdir() if d.is_dir() and project_name in d.name]
    
    for project_dir in project_dirs:
        try:
            # 檢查是否為空輸出
            is_empty = True
            
            # 檢查 removed_ranges.json
            removed_ranges_file = project_dir / "removed_ranges.json"
            if removed_ranges_file.exists():
                try:
                    with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    # 如果有任何檔案有範圍資料，就不是空的
                    if any(file_ranges for file_ranges in data.values()):
                        is_empty = False
                except:
                    pass
            
            # 檢查 prompt.txt
            prompt_file = project_dir / "prompt.txt"
            if prompt_file.exists():
                try:
                    content = prompt_file.read_text(encoding='utf-8').strip()
                    if content:
                        is_empty = False
                except:
                    pass
            
            # 如果確定是空的，就刪除整個專案目錄
            if is_empty:
                shutil.rmtree(project_dir, ignore_errors=True)
                
        except Exception as e:
            # 如果刪除失敗，不要影響其他處理
            pass

def check_dependencies():
    """檢查依賴項目"""
    script_path = Path("rm_project_call_function.py")
    if not script_path.exists():
        print_colored("❌ 錯誤: 找不到 rm_project_call_function.py 腳本", "red")
        return False
    
    try:
        result = subprocess.run([sys.executable, "--version"], 
                              capture_output=True, text=True)
        if result.returncode == 0:
            print_colored(f"✅ Python 版本: {result.stdout.strip()}", "green")
        else:
            print_colored("❌ Python 檢查失敗", "red")
            return False
    except Exception as e:
        print_colored(f"❌ Python 檢查失敗: {e}", "red")
        return False
    
    return True

def process_project(project_dir, project_name, json_file, output_base_dir):
    """處理單一專案的所有 CWE"""
    print_colored(f"處理專案: {project_name}", "yellow")
    
    if not json_file.exists():
        print_colored(f"  ⚠️  警告: 找不到 JSON 檔案: {json_file}", "yellow")
        print_colored("  ⏭️  跳過此專案", "yellow")
        return 0, len(CWES)
    
    successful_operations = 0
    total_operations = len(CWES)
    
    for cwe in CWES:
        print(f"  處理 CWE-{cwe} ...")
        
        # 建立 CWE 特定的輸出目錄
        cwe_output_dir = output_base_dir / f"CWE-{cwe}"
        cwe_output_dir.mkdir(parents=True, exist_ok=True)
        
        # 準備命令參數
        cmd = [
            sys.executable, "rm_project_call_function.py",
            str(project_dir),
            "--json", str(json_file),
            "--cwe", cwe,
            "--mode", MODE,
            "--above", str(ABOVE_LINES),
            "--below", str(BELOW_LINES),
            "-o", str(cwe_output_dir)
        ]
        
        try:
            # 執行刪除操作
            result = subprocess.run(cmd, 
                                  capture_output=True, 
                                  text=True, 
                                  timeout=300)  # 5分鐘超時
            
            if result.returncode == 0:
                # 檢查是否有實際的漏洞處理結果
                has_vulnerabilities = check_vulnerabilities_found(cwe_output_dir, project_name)
                
                if has_vulnerabilities:
                    print_colored(f"    ✅ CWE-{cwe} 處理成功 (發現 {has_vulnerabilities} 個漏洞)", "green")
                    successful_operations += 1
                else:
                    print_colored(f"    ℹ️  CWE-{cwe} 處理完成，但未發現漏洞，已清理空輸出", "yellow")
                    # 清理空的輸出目錄
                    cleanup_empty_output(cwe_output_dir, project_name)
            else:
                print_colored(f"    ❌ CWE-{cwe} 處理失敗", "red")
                if result.stderr:
                    error_msg = result.stderr.strip()
                    print(f"    錯誤信息: {error_msg}")
                    # 同時記錄到日誌
                    if hasattr(print_colored, 'logger'):
                        print_colored.logger.error(f"CWE-{cwe} 詳細錯誤: {error_msg}")
                if result.stdout:
                    stdout_msg = result.stdout.strip() 
                    if stdout_msg:
                        print(f"    輸出信息: {stdout_msg}")
                        if hasattr(print_colored, 'logger'):
                            print_colored.logger.info(f"CWE-{cwe} 輸出: {stdout_msg}")
                    
        except subprocess.TimeoutExpired:
            print_colored(f"    ⏰ CWE-{cwe} 處理超時", "red")
        except Exception as e:
            print_colored(f"    ❌ CWE-{cwe} 處理失敗: {e}", "red")
    
    success_rate = (successful_operations / total_operations) * 100 if total_operations > 0 else 0
    print_colored(f"  📊 專案 {project_name} 完成: {successful_operations}/{total_operations} 個 CWE 處理成功 ({success_rate:.1f}%)", "cyan")
    print()
    
    return successful_operations, total_operations

def get_directory_stats(output_base_dir):
    """統計輸出目錄的結果"""
    print_colored("🗂️  輸出目錄結構:", "cyan")
    
    total_results = 0
    total_vulnerabilities = 0
    
    for cwe in CWES:
        cwe_dir = output_base_dir / f"CWE-{cwe}"
        if cwe_dir.exists():
            # 計算該 CWE 目錄下的專案數量
            project_dirs = [d for d in cwe_dir.iterdir() if d.is_dir()]
            count = len(project_dirs)
            total_results += count
            
            # 統計實際的漏洞數量
            cwe_vulnerabilities = 0
            for project_dir in project_dirs:
                # 檢查 removed_ranges.json
                removed_ranges_file = project_dir / "removed_ranges.json"
                if removed_ranges_file.exists():
                    try:
                        with open(removed_ranges_file, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        # 計算有內容的檔案數量
                        cwe_vulnerabilities += sum(1 for file_ranges in data.values() if file_ranges)
                    except:
                        pass
            
            total_vulnerabilities += cwe_vulnerabilities
            
            if count > 0:
                if cwe_vulnerabilities > 0:
                    print(f"  CWE-{cwe}/: {count} 個專案, {cwe_vulnerabilities} 個漏洞檔案")
                else:
                    print_colored(f"  CWE-{cwe}/: {count} 個專案, 但無有效漏洞", "yellow")
            else:
                print_colored(f"  CWE-{cwe}/: 0 個處理結果", "yellow")
        else:
            print_colored(f"  CWE-{cwe}/: 目錄不存在", "red")
    
    return total_results, total_vulnerabilities

def setup_logging(output_dir):
    """設置日誌系統"""
    log_dir = output_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # 建立帶時間戳的日誌檔名
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"batch_process_{timestamp}.log"
    
    # 設置日誌格式
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
        ]
    )
    
    logger = logging.getLogger('batch_process')
    print_colored.logger = logger  # 將 logger 附加到 print_colored 函數
    
    return logger, log_file

def count_vulnerabilities_from_json(json_file):
    """從 JSON 檔案統計各 CWE 的漏洞數量"""
    cwe_counts = {}
    
    if not json_file.exists():
        return cwe_counts
    
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for cwe_key, cwe_data in data.items():
            if cwe_key.startswith('CWE-'):
                cwe_num = cwe_key.split('-')[1]
                
                # 計算該 CWE 的漏洞數量
                count = 0
                if isinstance(cwe_data, dict):
                    for vuln_type, vuln_files in cwe_data.items():
                        if isinstance(vuln_files, dict):
                            for file_path, file_vulns in vuln_files.items():
                                if isinstance(file_vulns, list):
                                    count += len(file_vulns)
                
                cwe_counts[cwe_num] = count
        
    except Exception as e:
        print_colored(f"讀取 JSON 檔案失敗: {json_file} - {e}", "red")
    
    return cwe_counts

def generate_csv_report(projects_dir, json_dir, output_dir):
    """生成 CSV 統計報告"""
    csv_file = output_dir / "vulnerability_statistics.csv"
    
    # 準備 CSV 標題
    headers = ['Project Name'] + [f'CWE-{cwe}' for cwe in CWES] + ['Total']
    
    # 收集所有專案的統計資料
    project_stats = []
    
    project_dirs = [d for d in projects_dir.iterdir() if d.is_dir()]
    
    for project_dir in project_dirs:
        project_name = project_dir.name
        json_file = json_dir / project_name / f"{project_name}.json"
        
        # 統計該專案的漏洞數量
        cwe_counts = count_vulnerabilities_from_json(json_file)
        
        # 準備該專案的統計行
        row = [project_name]
        total_count = 0
        
        for cwe in CWES:
            count = cwe_counts.get(cwe, 0)
            row.append(count)
            total_count += count
        
        row.append(total_count)
        project_stats.append(row)
    
    # 寫入 CSV 檔案
    try:
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(project_stats)
        
        print_colored(f"✅ CSV 統計報告已生成: {csv_file}", "green")
        
        # 統計總數
        total_projects = len(project_stats)
        total_vulnerabilities = sum(row[-1] for row in project_stats)
        
        print_colored(f"📊 統計摘要: {total_projects} 個專案，總共 {total_vulnerabilities} 個漏洞", "cyan")
        
        return csv_file
        
    except Exception as e:
        print_colored(f"❌ 生成 CSV 報告失敗: {e}", "red")
        return None

def main():
    parser = argparse.ArgumentParser(description="批次處理 CWE 漏洞程式碼刪除")
    parser.add_argument("--projects-dir", default="./projects", 
                       help="專案目錄路徑 (預設: ./projects)")
    parser.add_argument("--json-dir", default="./python_query_output",
                       help="JSON 檔案目錄路徑 (預設: ./python_query_output)")
    parser.add_argument("--output-dir", default="./rm_output",
                       help="輸出目錄路徑 (預設: ./rm_output)")
    parser.add_argument("--dry-run", action="store_true",
                       help="只顯示將要處理的專案，不實際執行")
    args = parser.parse_args()
    
    # 轉換為 Path 物件
    projects_dir = Path(args.projects_dir).expanduser().resolve()
    json_dir = Path(args.json_dir).expanduser().resolve()
    output_base_dir = Path(args.output_dir).expanduser().resolve()
    
    print_colored("=== 批次處理 CWE 漏洞程式碼刪除 ===", "cyan")
    print(f"向上刪除行數: {ABOVE_LINES}")
    print(f"向下刪除行數: {BELOW_LINES}")
    print(f"處理模式: {MODE}")
    print(f"專案目錄: {projects_dir}")
    print(f"JSON 目錄: {json_dir}")
    print(f"輸出目錄: {output_base_dir}")
    if args.dry_run:
        print_colored("🔍 模擬運行模式 (不會實際執行)", "yellow")
    print_colored("=========================================", "cyan")
    
    # 檢查依賴
    if not check_dependencies():
        return 1
    
    # 檢查必要目錄
    if not projects_dir.exists():
        print_colored(f"❌ 錯誤: 找不到專案目錄 {projects_dir}", "red")
        return 1
    
    if not json_dir.exists():
        print_colored(f"❌ 錯誤: 找不到 JSON 目錄 {json_dir}", "red")
        return 1
    
    # 建立輸出目錄
    if not args.dry_run:
        output_base_dir.mkdir(parents=True, exist_ok=True)
        
        # 設置日誌系統
        logger, log_file = setup_logging(output_base_dir)
        logger.info("=== 批次處理 CWE 漏洞程式碼刪除開始 ===")
        logger.info(f"向上刪除行數: {ABOVE_LINES}")
        logger.info(f"向下刪除行數: {BELOW_LINES}")
        logger.info(f"處理模式: {MODE}")
        logger.info(f"專案目錄: {projects_dir}")
        logger.info(f"JSON 目錄: {json_dir}")
        logger.info(f"輸出目錄: {output_base_dir}")
        logger.info(f"日誌檔案: {log_file}")
        print_colored(f"📝 日誌將保存到: {log_file}", "cyan")
    
    # 統計變數
    total_projects = 0
    processed_projects = 0
    total_operations = 0
    successful_operations = 0
    
    # 找到所有專案
    project_dirs = [d for d in projects_dir.iterdir() if d.is_dir()]
    total_projects = len(project_dirs)
    
    if total_projects == 0:
        print_colored("⚠️  警告: 在專案目錄中沒有找到任何子目錄", "yellow")
        return 0
    
    print(f"發現 {total_projects} 個專案")
    print()
    
    if args.dry_run:
        print_colored("將要處理的專案:", "cyan")
        for project_dir in project_dirs:
            project_name = project_dir.name
            json_file = json_dir / project_name / f"{project_name}.json"
            status = "✅" if json_file.exists() else "❌"
            print(f"  {status} {project_name} - JSON: {json_file}")
        print(f"\n總共 {len(CWES)} 個 CWE 類型")
        print(f"預計總操作數: {total_projects * len(CWES)}")
        return 0
    
    # 處理每個專案
    for project_dir in project_dirs:
        project_name = project_dir.name
        json_file = json_dir / project_name / f"{project_name}.json"
        
        processed_projects += 1
        
        # 處理專案
        success_count, op_count = process_project(
            project_dir, project_name, json_file, output_base_dir
        )
        
        successful_operations += success_count
        total_operations += op_count
    
    # 輸出統計結果
    print_colored("=========================================", "cyan")
    print_colored("📈 處理總結:", "cyan")
    print(f"  總專案數: {total_projects}")
    print(f"  已處理專案: {processed_projects}")
    print(f"  總操作數: {total_operations}")
    print(f"  成功操作數: {successful_operations}")
    
    if total_operations > 0:
        success_rate = (successful_operations / total_operations) * 100
        color = "green" if success_rate >= 80 else "yellow" if success_rate >= 50 else "red"
        print_colored(f"  成功率: {success_rate:.1f}%", color)
    else:
        print("  成功率: N/A")
    
    print()
    
    # 統計輸出目錄
    total_results, total_vulnerabilities = get_directory_stats(output_base_dir)
    
    print()
    
    # 生成 CSV 統計報告
    if not args.dry_run:
        print_colored("📊 正在生成 CSV 統計報告...", "cyan")
        csv_file = generate_csv_report(projects_dir, json_dir, output_base_dir)
        
        # 記錄完成信息到日誌
        if hasattr(print_colored, 'logger'):
            logger = print_colored.logger
            logger.info("=== 批次處理完成 ===")
            logger.info(f"總專案數: {total_projects}")
            logger.info(f"已處理專案: {processed_projects}")
            logger.info(f"總操作數: {total_operations}")
            logger.info(f"成功操作數: {successful_operations}")
            if total_operations > 0:
                success_rate = (successful_operations / total_operations) * 100
                logger.info(f"成功率: {success_rate:.1f}%")
            logger.info(f"總處理結果: {total_results}")
            logger.info(f"總漏洞檔案: {total_vulnerabilities}")
            if csv_file:
                logger.info(f"CSV 統計報告: {csv_file}")
    
    if total_results > 0:
        if total_vulnerabilities > 0:
            print_colored("✨ 批次處理完成！", "green")
            print_colored(f"📁 總共產生了 {total_results} 個處理結果，發現 {total_vulnerabilities} 個漏洞檔案", "green")
        else:
            print_colored(f"⚠️  批次處理完成，產生了 {total_results} 個處理結果，但沒有發現任何漏洞", "yellow")
    else:
        print_colored("⚠️  批次處理完成，但沒有產生任何結果", "yellow")
    
    if not args.dry_run and hasattr(print_colored, 'logger'):
        print_colored(f"📝 完整日誌已保存到: {log_file}", "green")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print_colored("\n\n⏹️  用戶中斷處理", "yellow")
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n❌ 發生未預期的錯誤: {e}", "red")
        import traceback
        traceback.print_exc()
        sys.exit(1)