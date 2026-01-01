using Azure.AI.OpenAI;
using OpenAI.Chat;
using Microsoft.Extensions.Options;

namespace SecureScan.Services;

public class LlmSecurityAdvisorOptions
{
    public string Endpoint { get; set; } = "";
    public string ApiKey { get; set; } = "";
    public string DeploymentName { get; set; } = "";
}

public class AiFixSuggestion
{
    public string Explanation { get; set; } = "";
    public string OriginalCode { get; set; } = "";
    public string FixedCode { get; set; } = "";
    public string SecurityNote { get; set; } = "";
}

public class LlmSecurityAdvisor
{
    private readonly LlmSecurityAdvisorOptions _options;
    private readonly ChatClient? _chatClient;

    public LlmSecurityAdvisor(IOptions<LlmSecurityAdvisorOptions> options)
    {
        _options = options.Value;
        
        if (!string.IsNullOrEmpty(_options.Endpoint) && !string.IsNullOrEmpty(_options.ApiKey))
        {
            var client = new AzureOpenAIClient(new Uri(_options.Endpoint), new System.ClientModel.ApiKeyCredential(_options.ApiKey));
            _chatClient = client.GetChatClient(_options.DeploymentName);
        }
    }

    public bool IsConfigured => _chatClient != null;

    public async Task<AiFixSuggestion> GetFixSuggestionAsync(ScanFinding finding)
    {
        if (_chatClient == null)
        {
            return new AiFixSuggestion
            {
                Explanation = "AI 服務未設定。請在 appsettings.json 中設定 Azure OpenAI 連線資訊。",
                OriginalCode = finding.ProblematicLine,
                FixedCode = "// 需要手動修正",
                SecurityNote = finding.Recommendation
            };
        }

        var prompt = @$"你是一位資安專家。請分析以下程式碼的安全問題並提供修正建議。

## 風險類型
{finding.RiskType}

## 問題說明
{finding.Description}

## 問題程式碼上下文
```
{finding.CodeSnippet}
```

## 問題行
{finding.ProblematicLine}

請提供：
1. 為什麼這是安全問題的簡短解釋（2-3 句話）
2. 修正後的程式碼範例
3. 額外的安全建議

請只回覆 JSON 格式（不要 markdown）：
{{""explanation"": ""..."", ""fixedCode"": ""..."", ""securityNote"": ""...""}}
";

        try
        {
            var response = await _chatClient.CompleteChatAsync(
                new ChatMessage[]
                {
                    new SystemChatMessage("分析程式碼安全問題並提供修正建議。回覆請使用繁體中文，格式為 JSON。"),
                    new UserChatMessage(prompt)
                });

            var content = response.Value.Content[0].Text;
            
            // Simple JSON parsing (could use System.Text.Json for production)
            var result = System.Text.Json.JsonSerializer.Deserialize<AiFixSuggestion>(content, 
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            
            if (result != null)
            {
                result.OriginalCode = finding.ProblematicLine;
                return result;
            }
        }
        catch (Exception ex)
        {
            return new AiFixSuggestion
            {
                Explanation = $"AI 分析時發生錯誤：{ex.Message}",
                OriginalCode = finding.ProblematicLine,
                FixedCode = "// 無法自動產生",
                SecurityNote = finding.Recommendation
            };
        }

        return new AiFixSuggestion
        {
            Explanation = "無法解析 AI 回應",
            OriginalCode = finding.ProblematicLine,
            FixedCode = "// 無法自動產生",
            SecurityNote = finding.Recommendation
        };
    }

    /// <summary>
    /// Generate a comprehensive security report for multiple findings in one API call
    /// </summary>
    public async Task<string> GenerateBatchReportAsync(List<ScanFinding> findings)
    {
        if (_chatClient == null)
        {
            return "❌ AI 服務未設定。請在 appsettings.json 中設定 Azure OpenAI 連線資訊。";
        }

        if (findings.Count == 0)
        {
            return "✅ 沒有選取任何風險項目。";
        }

        // Group findings by risk type for efficiency
        var grouped = findings.GroupBy(f => f.RiskType).ToList();
        var scanDate = DateTime.Now.ToString("yyyy-MM-dd HH:mm");
        
        var findingsSummary = string.Join("\n\n", grouped.Select(g => $@"
### {g.Key} ({g.Count()} 處)
範例程式碼：
```
{g.First().CodeSnippet}
```
其他位置：{string.Join(", ", g.Skip(1).Take(5).Select(f => $"{Path.GetFileName(f.FilePath)}:{f.LineNo}"))}
"));

        var prompt = $@"請根據以下程式碼掃描結果產生一份安全報告。

## 掃描資訊
- 掃描時間：{scanDate}
- 總共發現 {findings.Count} 個潛在安全風險
- 高風險：{findings.Count(f => f.Level == "高")} 個
- 中風險：{findings.Count(f => f.Level == "中")} 個
- 低風險：{findings.Count(f => f.Level == "低")} 個

## 風險詳情（依類型分組）
{findingsSummary}

請產生一份 Markdown 格式的安全報告，包含：
1. 執行摘要（2-3 句話總結風險狀況）
2. 各類型風險的詳細說明與修正範例（提供可直接使用的程式碼）
3. 優先處理建議（先修哪些）
4. 整體安全建議

請使用繁體中文，語氣專業但不要自稱任何身份。";

        try
        {
            var response = await _chatClient.CompleteChatAsync(
                new ChatMessage[]
                {
                    new SystemChatMessage("你是一個程式碼安全分析助手。請產生清晰、專業的安全報告，提供具體可執行的修正建議。不要自稱專家或任何身份。"),
                    new UserChatMessage(prompt)
                });

            return response.Value.Content[0].Text;
        }
        catch (Exception ex)
        {
            return $"❌ AI 分析時發生錯誤：{ex.Message}";
        }
    }
}

