# Reddit 大模型安全讨论抓取与风险预警

这个仓库提供一个可直接运行的脚本，可从多个来源抓取帖子并筛选“大模型安全漏洞/风险”相关讨论，自动生成客户可读的风险预警报告。

## 1. 运行方式

```bash
python reddit_llm_security_risk_report.py \
  --source reddit \
  --subreddit ChatGPTPromptGenius \
  --sort new \
  --limit 250 \
  --outdir output
```

V2EX（国内讨论区）示例：

```bash
python reddit_llm_security_risk_report.py \
  --source v2ex \
  --limit 200 \
  --outdir output
```

离线 JSON 示例（网络受限时推荐）：

```bash
python reddit_llm_security_risk_report.py \
  --source local_json \
  --input-file sample_posts.json \
  --outdir output
```

可选参数：
- `--sort`: `new|hot|top|rising`
- `--limit`: 最大抓取帖子数（默认 250）
- `--outdir`: 输出目录（默认 `output`）
- `--source`: `reddit|v2ex|local_json`
- `--input-file`: 本地 JSON 文件路径（`--source=local_json` 时必填）

## 2. 输出结果

脚本会生成两个文件：
- `output/reddit_security_posts.json`: 命中安全关键词的原始帖子数据。
- `output/risk_warning_report.md`: 自动汇总的风险预警报告（可直接发客户/内部评审）。

## 3. 分析逻辑

脚本内置多类风险关键词并自动打标签：
- Prompt Injection / Jailbreak
- Data Leakage / Privacy / PII
- Malicious Use（钓鱼、恶意滥用）
- Alignment / Safety
- Agentic Risk（工具调用与自动化）

随后按“主题分布、时间趋势、高互动样本”输出摘要，并提供客户风险预警建议。

## 4. 网络说明

若运行环境存在统一外网限制（如代理/网络策略返回 `403 CONNECT tunnel failed`），访问 Reddit/V2EX 都可能失败。
此时建议：
1. 在可访问外网的网络中执行；或
2. 通过公司合规代理执行；或
3. 改用 `--source local_json` 进行离线分析。
