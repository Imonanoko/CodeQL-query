import os

def rename_folders():
    # 設定目標資料夾路徑 ('.' 代表當前資料夾)
    target_dir = './rm_output'
    
    # --- 設定模式 ---
    # True = 測試模式 (只會印出訊息，不會真的改名)
    # False = 執行模式 (真的會改名)
    dry_run = False
    
    print(f"--- 開始執行 ({'測試模式' if dry_run else '正式執行'}) ---")

    # 取得資料夾內所有檔案與資料夾
    try:
        items = os.listdir(target_dir)
    except FileNotFoundError:
        print(f"找不到路徑: {target_dir}")
        return

    count = 0
    for item in items:
        # 組合完整路徑
        full_path = os.path.join(target_dir, item)
        
        # 確保是對「資料夾」進行操作，且名稱中包含雙底線 '__'
        if os.path.isdir(full_path) and '__' in item:
            
            # 切割字串，取第一部分 (__ 之前)
            new_name = item.split('__')[0]
            new_full_path = os.path.join(target_dir, new_name)
            
            # 避免改名後的名稱已經存在 (例如已經有一個叫 corrade 的資料夾)
            if os.path.exists(new_full_path):
                print(f"[跳過] 目標名稱已存在: {item} -> {new_name}")
                continue
            
            # 執行改名
            if dry_run:
                print(f"[預覽] 將會改名: {item} -> {new_name}")
            else:
                try:
                    os.rename(full_path, new_full_path)
                    print(f"[成功] 已改名: {item} -> {new_name}")
                except Exception as e:
                    print(f"[錯誤] 無法改名 {item}: {e}")
            
            count += 1
            
    if count == 0:
        print("沒有發現符合命名規則 (含有 '__') 的資料夾。")
    else:
        print(f"--- 處理完成，共掃描到 {count} 個項目 ---")
        if dry_run:
            print("請將程式碼中的 'dry_run = True' 改為 'False' 以執行實際改名。")

if __name__ == '__main__':
    rename_folders()