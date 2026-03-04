#!/usr/bin/env python3
"""Collect and summarize LLM security-vulnerability discussions from Reddit.

Target: https://www.reddit.com/r/ChatGPTPromptGenius/

This script fetches subreddit posts via Reddit JSON endpoints, filters discussions
related to LLM security vulnerabilities, and generates a risk-warning report.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import ssl
import sys
import textwrap
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

USER_AGENT = "Mozilla/5.0 (compatible; LLMRiskCrawler/1.0; +https://example.local)"

SECURITY_KEYWORDS = {
    "prompt_injection": [
        "prompt injection",
        "injection",
        "jailbreak",
        "越狱",
        "提示词注入",
    ],
    "data_leakage": [
        "data leak",
        "leak",
        "privacy",
        "pii",
        "泄露",
        "隐私",
        "数据泄漏",
    ],
    "malicious_use": [
        "phishing",
        "malware",
        "abuse",
        "misuse",
        "诈骗",
        "恶意",
        "攻击",
    ],
    "model_alignment": [
        "alignment",
        "safety",
        "unsafe",
        "hallucination",
        "对齐",
        "安全",
        "幻觉",
    ],
    "agentic_risk": [
        "agent",
        "tool calling",
        "function call",
        "automation",
        "agentic",
        "代理",
        "自动化",
    ],
}


@dataclass
class Post:
    title: str
    body: str
    author: str
    score: int
    comments: int
    created_utc: int
    permalink: str
    matched_categories: List[str]

    @property
    def created_at(self) -> str:
        return dt.datetime.utcfromtimestamp(self.created_utc).strftime("%Y-%m-%d")

    @property
    def engagement(self) -> int:
        return self.score + self.comments


def fetch_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8"))


def iter_reddit_posts(subreddit: str, limit: int = 200, sort: str = "new") -> Iterable[dict]:
    per_page = 100
    fetched = 0
    after = None
    while fetched < limit:
        batch = min(per_page, limit - fetched)
        params = {"limit": str(batch)}
        if after:
            params["after"] = after
        url = (
            f"https://www.reddit.com/r/{subreddit}/{sort}.json?"
            + urllib.parse.urlencode(params)
        )
        payload = fetch_json(url)
        children = payload.get("data", {}).get("children", [])
        if not children:
            return

        for child in children:
            yield child.get("data", {})
            fetched += 1
            if fetched >= limit:
                return

        after = payload.get("data", {}).get("after")
        if not after:
            return


def fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
        return resp.read().decode("utf-8", errors="replace")


def iter_v2ex_posts(limit: int = 200) -> Iterable[dict]:
    """Fetch posts from V2EX AI node RSS.

    URL: https://www.v2ex.com/go/ai/rss
    """
    rss_url = "https://www.v2ex.com/go/ai/rss"
    raw = fetch_text(rss_url)
    root = ET.fromstring(raw)
    items = root.findall("./channel/item")
    for item in items[:limit]:
        title = item.findtext("title", default="")
        link = item.findtext("link", default="")
        description = item.findtext("description", default="")
        pub_date = item.findtext("pubDate", default="")
        created_utc = int(dt.datetime.utcnow().timestamp())
        if pub_date:
            try:
                created_utc = int(
                    dt.datetime.strptime(pub_date, "%a, %d %b %Y %H:%M:%S %z").timestamp()
                )
            except ValueError:
                pass
        yield {
            "title": title,
            "selftext": description,
            "author": "v2ex_user",
            "score": 0,
            "num_comments": 0,
            "created_utc": created_utc,
            "permalink": link,
        }


def iter_local_posts(input_file: str) -> Iterable[dict]:
    """Load posts from local JSON for offline analysis.

    JSON format: a list of objects with keys similar to Reddit fields:
    title, selftext, author, score, num_comments, created_utc, permalink
    """
    data = json.loads(Path(input_file).read_text(encoding="utf-8"))
    for row in data:
        yield {
            "title": row.get("title", ""),
            "selftext": row.get("selftext", row.get("body", "")),
            "author": row.get("author", "unknown"),
            "score": int(row.get("score", 0) or 0),
            "num_comments": int(row.get("num_comments", row.get("comments", 0)) or 0),
            "created_utc": int(row.get("created_utc", dt.datetime.utcnow().timestamp()) or 0),
            "permalink": row.get("permalink", ""),
        }


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def match_categories(text: str) -> List[str]:
    normalized = normalize_text(text)
    hits: List[str] = []
    for category, keywords in SECURITY_KEYWORDS.items():
        if any(kw in normalized for kw in keywords):
            hits.append(category)
    return hits


def classify_posts(raw_posts: Iterable[dict]) -> List[Post]:
    results: List[Post] = []
    for d in raw_posts:
        title = d.get("title", "")
        body = d.get("selftext", "")
        categories = match_categories(f"{title}\n{body}")
        if not categories:
            continue
        permalink = d.get("permalink", "")
        if permalink and not permalink.startswith(("http://", "https://")):
            permalink = f"https://www.reddit.com{permalink}"

        results.append(
            Post(
                title=title,
                body=body,
                author=d.get("author", "unknown"),
                score=int(d.get("score", 0) or 0),
                comments=int(d.get("num_comments", 0) or 0),
                created_utc=int(d.get("created_utc", 0) or 0),
                permalink=permalink,
                matched_categories=categories,
            )
        )
    return results


def make_summary(posts: List[Post], source_label: str, limit: int) -> str:
    now = dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    if not posts:
        return textwrap.dedent(
            f"""
            # Reddit 大模型安全讨论风险预警（自动生成）

            - 生成时间：{now}
            - 数据来源：{source_label}
            - 抓取上限：{limit}

            未检索到命中关键词的帖子。可能原因：
            1. 当前时间窗口内相关讨论较少。
            2. 关键词覆盖不足。
            3. 网络访问限制导致抓取失败。
            """
        ).strip()

    category_counter = Counter()
    daily_counter = defaultdict(int)
    for p in posts:
        for c in p.matched_categories:
            category_counter[c] += 1
        daily_counter[p.created_at] += 1

    top_posts = sorted(posts, key=lambda x: x.engagement, reverse=True)[:8]
    top_lines = "\n".join(
        [
            (
                f"- [{p.title}]({p.permalink}) | 作者 u/{p.author} | "
                f"互动={p.engagement} (赞同 {p.score} + 评论 {p.comments}) | "
                f"分类: {', '.join(p.matched_categories)}"
            )
            for p in top_posts
        ]
    )

    category_lines = "\n".join(
        [f"- {k}: {v}" for k, v in category_counter.most_common()]
    )

    trend_lines = "\n".join(
        [f"- {d}: {daily_counter[d]} 条" for d in sorted(daily_counter.keys())[-14:]]
    )

    return textwrap.dedent(
        f"""
        # Reddit 大模型安全讨论风险预警（自动生成）

        - 生成时间：{now}
        - 数据来源：{source_label}
        - 样本量（命中安全关键词）：{len(posts)}
        - 抓取上限：{limit}

        ## 1) 主要风险主题分布
        {category_lines}

        ## 2) 近期讨论趋势（按发帖日期）
        {trend_lines}

        ## 3) 高互动样本（优先人工复核）
        {top_lines}

        ## 4) 面向客户的风险预警建议
        - 建立 **Prompt Injection 防护基线**：输入净化、系统提示隔离、工具调用最小权限。
        - 把 **数据泄露风险** 纳入发布门禁：敏感词检测、PII 脱敏、审计日志留存。
        - 对 **恶意滥用场景** 建立灰度监测：越狱检测、异常请求速率控制、可疑行为封禁。
        - 对 **Agent/自动化链路** 增加人工确认步骤：高风险操作需二次确认。
        - 每周复盘社区高热帖子并更新威胁情报标签，形成滚动预警。
        """
    ).strip()


def write_outputs(posts: List[Post], summary_md: str, outdir: Path) -> Tuple[Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    raw_path = outdir / "reddit_security_posts.json"
    report_path = outdir / "risk_warning_report.md"

    serialized = [
        {
            "title": p.title,
            "body": p.body,
            "author": p.author,
            "score": p.score,
            "comments": p.comments,
            "created_utc": p.created_utc,
            "created_at": p.created_at,
            "permalink": p.permalink,
            "engagement": p.engagement,
            "matched_categories": p.matched_categories,
        }
        for p in posts
    ]

    raw_path.write_text(json.dumps(serialized, ensure_ascii=False, indent=2), encoding="utf-8")
    report_path.write_text(summary_md + "\n", encoding="utf-8")
    return raw_path, report_path


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Reddit LLM security discussion crawler")
    p.add_argument(
        "--source",
        choices=["reddit", "v2ex", "local_json"],
        default="reddit",
        help="Data source",
    )
    p.add_argument("--subreddit", default="ChatGPTPromptGenius")
    p.add_argument("--limit", type=int, default=250, help="Maximum posts to pull")
    p.add_argument(
        "--sort",
        choices=["new", "hot", "top", "rising"],
        default="new",
        help="Listing order",
    )
    p.add_argument("--outdir", default="output")
    p.add_argument(
        "--input-file",
        default="",
        help="Path to local JSON when --source=local_json",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.source == "reddit":
            raw_posts = list(iter_reddit_posts(args.subreddit, limit=args.limit, sort=args.sort))
        elif args.source == "v2ex":
            raw_posts = list(iter_v2ex_posts(limit=args.limit))
        else:
            if not args.input_file:
                raise ValueError("--input-file is required when --source=local_json")
            raw_posts = list(iter_local_posts(args.input_file))
        posts = classify_posts(raw_posts)
        if args.source == "reddit":
            source_label = f"reddit:r/{args.subreddit}"
        elif args.source == "v2ex":
            source_label = "v2ex:/go/ai"
        else:
            source_label = f"local_json:{args.input_file}"

        summary = make_summary(posts, source_label, args.limit)
        raw_path, report_path = write_outputs(posts, summary, Path(args.outdir))
        print(f"Fetched posts: {len(raw_posts)}")
        print(f"Matched security posts: {len(posts)}")
        print(f"Saved raw data: {raw_path}")
        print(f"Saved report: {report_path}")
        return 0
    except urllib.error.URLError as e:
        print(f"Network error while fetching source '{args.source}'. Details:", e, file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001
        print("Unexpected error:", e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
