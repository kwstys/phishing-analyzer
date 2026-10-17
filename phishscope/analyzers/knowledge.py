"""知识库加载：把 phishscope/data/*.yaml 读成 Python 结构。

为什么单独一个模块：分析器只该关心"怎么判断"，不该关心 YAML 长什么样。
数据文件的格式一变，只改这里。

为什么每个函数都加 functools.cache：这些表会被 13 条规则各自调用。
不缓存的话每调一次就重新读盘 + 解析 YAML，测试和 CLI 都会明显变慢。
"""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any

import yaml

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# confusables.yaml 里属于「文字系统同形字」的三张表。
# 单独一组的 digit_lookalikes 不算——域名里有数字完全正常（360.cn / 163.com），
# 它只用于"域名归一化之后去比品牌表"，见 domain_lookalikes()。
_SCRIPT_TABLES = ("cyrillic_to_latin", "greek_to_latin", "other_scripts")


def _load(filename: str) -> Any:
    with (DATA_DIR / filename).open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


@functools.cache
def brands() -> dict[str, tuple[frozenset[str], frozenset[str]]]:
    """品牌名 → (别名集合, 合法域名集合)。

    brands.yaml 按行业分了好几组（international_tech / china_finance / ...），
    这里拍平成一个字典，组名不参与判断。
    别名和域名统一转小写，比较时就不用再管大小写。
    """
    merged: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for group in _load("brands.yaml").values():
        for item in group:
            aliases = frozenset(str(a).strip().lower() for a in item.get("aliases", []))
            domains = frozenset(str(d).strip().lower() for d in item.get("domains", []))
            merged[str(item["name"])] = (aliases, domains)
    return merged


@functools.cache
def free_mail_domains() -> frozenset[str]:
    """全部免费邮箱域名（global / china / disposable 三组合并）。"""
    return frozenset(
        str(domain).strip().lower()
        for group in _load("free_mail.yaml").values()
        for domain in group
    )


@functools.cache
def script_confusables() -> dict[str, str]:
    """文字系统同形字：混淆字符 → 它冒充的拉丁字符。

    只合并 cyrillic / greek / other_scripts 三张表。
    这三张表里的字符**单独出现就可以当信号**——正常域名不会混着用西里尔字母。
    """
    raw = _load("confusables.yaml")
    merged: dict[str, str] = {}
    for table in _SCRIPT_TABLES:
        for key, value in raw.get(table, {}).items():
            merged[str(key)] = str(value)
    return merged


@functools.cache
def domain_lookalikes() -> dict[str, str]:
    """域名归一化用的替换表：同形字 + 数字 → 对应的拉丁字符。

    和 script_confusables() 的区别：这张表**不能当独立信号**。
    用途是把 micros0ft-support.com 归一化成 microsoftsupport，
    再去和品牌名比对。域名里有数字很正常，不能一见数字就报警。
    """
    merged = dict(script_confusables())
    for key, value in _load("confusables.yaml").get("digit_lookalikes", {}).items():
        merged[str(key)] = str(value)
    return merged


@functools.cache
def lure_words() -> dict[str, tuple[str, ...]]:
    """诱导话术分类 → 短语元组。中英文词库按分类合并。

    分类名（credential / threat / finance / reward / urgency / action）
    决定严重程度，所以不能拍平成一个大列表。
    """
    merged: dict[str, list[str]] = {}
    for filename in ("lure_words_zh.yaml", "lure_words_en.yaml"):
        for category, phrases in (_load(filename) or {}).items():
            merged.setdefault(str(category), []).extend(str(p) for p in phrases)
    return {category: tuple(phrases) for category, phrases in merged.items()}
