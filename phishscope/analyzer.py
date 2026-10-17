"""分析编排层：把所有分析器跑一遍，产出排好序的 Finding 列表。

为什么排序：同一封邮件两次运行的输出顺序必须一致，否则测试没法断言，
用户也没法比对两次结果。排序规则是「级别高的在前，同级别按规则名」。
"""

from __future__ import annotations

from .analyzers.headers import analyze_headers
from .models import Finding, ParsedEmail, Severity

# 严重程度排序：数值越小越靠前
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sort_key(finding: Finding) -> tuple[int, str]:
    return (_SEVERITY_RANK[finding.severity], finding.rule)


def analyze(mail: ParsedEmail) -> list[Finding]:
    """跑全部分析器，返回排好序的 Finding 列表。

    第 3 周起会依次加进来：认证规则 / 链接规则 / 附件规则 / 正文规则。
    每加一类就在下面多一行 extend，评分层和报告层都不用改。
    """
    findings: list[Finding] = []
    findings.extend(analyze_headers(mail))
    findings.sort(key=_sort_key)
    return findings
