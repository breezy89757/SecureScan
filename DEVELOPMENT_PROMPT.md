# SecureScan Development Prompt for Cline

Use this prompt to have Cline (or another AI agent) develop the full SecureScan application.

---

## 📋 Development Prompt

```
請先讀取 .agent/rules.md，然後開發 SecureScan 專案的核心功能。

SecureScan 是一個 Web-based 的程式碼安全掃描工具，基於 OWASP Top 10 檢測常見漏洞。

## 功能需求

### Phase 1: 基礎掃描 UI
1. **首頁**：讓使用者貼上程式碼或上傳檔案
2. **掃描按鈕**：點擊後執行 OWASP Top 10 檢測
3. **結果顯示**：以表格顯示發現的風險（嚴重度、位置、說明）

### Phase 2: 掃描引擎
請參考 `.agent/workflows/security-review.md` 的 grep 規則，實作以下掃描：
- A01 Injection：偵測 SQL 拼接、命令執行
- A02 Cryptographic Failures：偵測硬編碼密鑰
- A03 XSS：偵測未編碼的輸出
- A07 識別失敗：偵測弱密碼規則

### Phase 3: 報告功能
1. **風險摘要**：顯示高/中/低風險數量
2. **詳細建議**：每個問題提供修正建議
3. **匯出功能**：可匯出 JSON 或 Markdown 報告

## 技術規格
- 使用 Blazor Server + InteractiveServer
- 遵循 .agent/rules.md 的命名規範
- UI 使用繁體中文
- 樣式使用 wwwroot/app.css 的現有主題

## 開發流程
1. 先完成 Phase 1 的 UI
2. 驗證 UI 可正常顯示
3. 再實作 Phase 2 的掃描邏輯
4. 最後加入 Phase 3 的報告功能

請逐 Phase 開發，每完成一個 Phase 先告知我驗證。
```

---

## 💡 使用說明

1. 開啟 VSCode + Cline
2. 確保 SecureScan 資料夾已存在
3. 複製上方 prompt 貼到 Cline
4. 讓 AI 逐步開發

## 🎯 預期成果

- 可上傳/貼上程式碼進行安全掃描
- 顯示 OWASP Top 10 相關風險
- 可匯出報告
