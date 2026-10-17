"""架构守卫：这些测试守的是「约定」，不是「功能」。

功能测试问"结果对不对"，守卫测试问"以后有没有人绕过设计"。
它们测的是代码的形状，所以失败信息都写清了该怎么做。
"""

from __future__ import annotations

import pathlib

import pytest

from phishscope.models import Finding, Severity
from phishscope.rules import RULES, Category

PACKAGE = pathlib.Path(__file__).resolve().parent.parent / "phishscope"

# 只有这两个模块可以碰 headers 字典：一个定义它，一个构造它。
HEADERS_OWNERS = {"models.py", "parser.py"}


def test_no_direct_headers_access_outside_the_owners():
    """除 models.py / parser.py 外，一律走 ParsedEmail.header()。

    直接写 headers.get("Reply-To")，会在把头部写成小写 `reply-to:` 的邮件上
    静默返回空——规则不触发，报告显示"一切正常"。假阴性比假阳性更难发现，
    所以这条守卫不许有例外。
    """
    offenders: list[str] = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in HEADERS_OWNERS:
            continue
        text = path.read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("#", "from ", "import ")):
                continue  # 注释，以及 import 里的模块路径（from .analyzers.headers import ...）
            if ".headers" in line:
                rel = path.relative_to(PACKAGE.parent)
                offenders.append(f"  {rel}:{lineno}  {stripped}")

    assert not offenders, (
        "这些地方直接访问了 .headers，请改用 mail.header(name)：\n" + "\n".join(offenders)
    )


def test_header_rules_are_registered_with_header_category():
    """第 2 周的 13 条规则必须都在注册表里，且分类是「头部」。"""
    header_rules = [name for name, category in RULES.items() if category is Category.HEADER]
    assert len(header_rules) == 13, f"头部规则应有 13 条，注册表里有 {len(header_rules)} 条"
    assert len(set(header_rules)) == len(header_rules), "注册表里有重复的规则名"


def test_unregistered_rule_name_is_rejected():
    """规则名拼错要在构造 Finding 时就炸，而不是等第 6 周算分时静默变成 0 分。"""
    with pytest.raises(ValueError, match="未注册的规则名"):
        Finding(
            rule="这条规则名根本不存在",
            severity=Severity.LOW,
            summary="x",
            evidence="y",
        )


def test_registered_rule_name_is_accepted():
    finding = Finding(
        rule="回复地址与发件人不一致",
        severity=Severity.MEDIUM,
        summary="x",
        evidence="y",
    )
    assert finding.rule in RULES
