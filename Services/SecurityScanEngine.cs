using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace SecureScan.Services
{
    public class ScanFinding
    {
        public string FilePath { get; set; } = "";
        public string RiskType { get; set; } = "";
        public string Level { get; set; } = "";
        public int LineNo { get; set; }
        public string Description { get; set; } = "";
        public string Recommendation { get; set; } = "";
        public string CodeSnippet { get; set; } = "";  // ±3 lines context
        public string ProblematicLine { get; set; } = "";
    }

    public static class SecurityScanEngine
    {
        record Rule(string Key, string RiskType, string Level, string Pattern, string Description, string Recommendation);

        private static readonly string[] SupportedExtensions = { ".cs", ".razor", ".js", ".ts", ".jsx", ".tsx" };
        private static readonly string[] IgnoreFolders = { "bin", "obj", "node_modules", ".git", ".vs", "wwwroot" };
        private static readonly string[] IgnoreFilePatterns = { ".template.", ".sample.", ".example.", "appsettings.Development" };

        static readonly Rule[] Rules = new[]
        {
            // A01 Injection - 更精確的 SQL 注入偵測
            new Rule("A01", "Injection", "高", @"(""SELECT.*""\s*\+|string\.Concat.*SELECT|Process\.Start\s*\(.*\+|Runtime\.exec)",
                "偵測到 SQL 拼接或可能的指令注入", "請使用參數化查詢，不可將使用者輸入直接拼接 SQL/指令。"),
            // A02 Cryptographic Failures - 排除空值和範本
            new Rule("A02", "Cryptographic Failure", "高", @"(password\s*=\s*""[^""]+|Password\s*=\s*""[^""]+|secret\s*=\s*""[^""]+|apikey\s*=\s*""[^""]+|api_key\s*=\s*""[^""])",
                "發現疑似硬編碼密碼、Secret、API Key", "請將密碼與敏感 Key 移至安全設定檔（如 appsettings.json + gitignore）。"),
            // A03 XSS
            new Rule("A03", "XSS", "高", @"(Html\.Raw\s*\(|\.innerHTML\s*=|dangerouslySetInnerHTML|@\(\(MarkupString\))",
                "發現潛在 XSS 輸出（未進行安全編碼）", "請使用 HTML Encoder，勿將外部輸入以 Raw/innerHTML 方式直接渲染。"),
            // A07 Weak Authentication
            new Rule("A07", "Weak Authentication", "中", @"(password.*\.Length\s*[<>=]+\s*[1-7]\b|minlength\s*=\s*['""][1-7]['""])",
                "發現長度過短的密碼規則", "建議密碼至少 8 碼且含大小寫、數字、特殊符號。"),
        };

        /// <summary>
        /// Scan a folder recursively for security issues
        /// </summary>
        public static List<ScanFinding> ScanFolder(string folderPath)
        {
            var results = new List<ScanFinding>();
            if (!Directory.Exists(folderPath))
                return results;

            var files = Directory.EnumerateFiles(folderPath, "*.*", SearchOption.AllDirectories)
                .Where(f => SupportedExtensions.Contains(Path.GetExtension(f).ToLowerInvariant()))
                .Where(f => !IgnoreFolders.Any(ignore => f.Contains(Path.DirectorySeparatorChar + ignore + Path.DirectorySeparatorChar)))
                .Where(f => !IgnoreFilePatterns.Any(pattern => f.Contains(pattern, StringComparison.OrdinalIgnoreCase)));

            foreach (var file in files)
            {
                try
                {
                    var content = File.ReadAllText(file);
                    var fileFindings = ScanCode(content, file);
                    results.AddRange(fileFindings);
                }
                catch { /* Skip files that can't be read */ }
            }

            return results;
        }

        /// <summary>
        /// Scan code content (paste mode)
        /// </summary>
        public static List<ScanFinding> Scan(string code) => ScanCode(code, "（貼上的程式碼）");

        private static List<ScanFinding> ScanCode(string code, string filePath)
        {
            var results = new List<ScanFinding>();
            var lines = code.Replace("\r\n", "\n").Split('\n');
            
            for (int i = 0; i < lines.Length; i++)
            {
                var line = lines[i];
                foreach (var rule in Rules)
                {
                    var regex = new Regex(rule.Pattern, RegexOptions.IgnoreCase);
                    if (regex.IsMatch(line))
                    {
                        results.Add(new ScanFinding
                        {
                            FilePath = filePath,
                            RiskType = $"{rule.Key}: {rule.RiskType}",
                            Level = rule.Level,
                            LineNo = i + 1,
                            Description = rule.Description,
                            Recommendation = rule.Recommendation,
                            ProblematicLine = line.Trim(),
                            CodeSnippet = ExtractContext(lines, i, 3)
                        });
                    }
                }
            }
            return results;
        }

        private static string ExtractContext(string[] lines, int index, int contextLines)
        {
            var start = Math.Max(0, index - contextLines);
            var end = Math.Min(lines.Length - 1, index + contextLines);
            var result = new List<string>();
            
            for (int i = start; i <= end; i++)
            {
                var prefix = i == index ? ">> " : "   ";
                result.Add($"{prefix}{i + 1}: {lines[i]}");
            }
            
            return string.Join("\n", result);
        }
    }
}

