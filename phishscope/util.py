"""跨层共享的小工具。

只放"纯函数 + 无状态、且不认识任何项目数据结构"的东西。
判据：一个函数如果需要认识 ParsedEmail / Finding，那它就不属于这里——
它该是那个数据结构的方法。放不进这个定义的，说明它该有自己的模块。
"""

import re
import unicodedata
from email.utils import parseaddr

import tldextract

# 连续空白（空格 / TAB / 换行 / CR）
_WHITESPACE_RUN = re.compile(r"\s+")

# 关闭联网：默认参数会去 publicsuffix.org 和 raw.githubusercontent.com 拉后缀列表，
# 首次调用就发网络请求，直接违反"纯离线"这条红线。用随包自带的快照。
# 模块级只建一次：构造时会加载后缀表快照，每次调用都新建会很慢。
_extract = tldextract.TLDExtract(suffix_list_urls=(), fallback_to_snapshot=True)

# 展示时要剔掉的 Unicode 类别：
#   Cc = 控制字符（含 ESC——ANSI 转义的起点；还有 BEL、退格、回车）
#   Cf = 格式字符（含 U+202E 这类会**翻转文字显示顺序**的字符）
_CONTROL_CATEGORIES = frozenset({"Cc", "Cf"})


def split_address(value: str) -> tuple[str, str]:
    """ "微软账户团队 <a@b.com>" → ("微软账户团队", "a@b.com")

    解析不出地址时把整串当显示名返回、地址返回空串，不抛异常。
    """
    display, addr = parseaddr(value)
    if not addr and value.strip():
        return value.strip(), ""
    return display.strip(), addr.strip()


def domain_of(addr: str) -> str:
    """ "a@b.com" → "b.com"（**原始**域名，不是注册域）；没有 @ 时返回空串"""
    if "@" not in addr:
        return ""
    return addr.rpartition("@")[2].strip().lower()


def top_domain(domain: str) -> str:
    """ "mail.neea.edu.cn" → "neea.edu.cn"（**注册域**）

    比较"两个域是不是同一家"时必须用它：mail.neea.edu.cn 和 neea.edu.cn
    属于同一家机构，用原始域名直接比会误报。
    IP 地址和单标签主机名（如 WIN-7NMETV5JCU5）没有注册域，返回空串。
    """
    if not domain:
        return ""
    return _extract(domain.strip().lower()).top_domain_under_public_suffix


def unfold(value: str) -> str:
    """把头部值里的折叠空白（换行 + TAB）压成单个空格。

    邮件长头部会折行，值里因此混着 CRLF 和 TAB。
    注意：折叠点可能落在**一个 token 中间**，压成空格后 token 仍然是被劈开的，
    取地址 / 域名时还要对被匹配出来的那一段再去一次空白。
    """
    if not value:
        return ""
    return _WHITESPACE_RUN.sub(" ", value).strip()


def sanitize(text: str) -> str:
    """去掉控制字符和 Unicode 格式字符，**只用于展示**。

    为什么需要：邮件内容来自攻击者。主题或显示名里塞一个 ESC 加 `[2J`
    就能清掉分析员终端上已经看到的结论，塞一个 U+202E 就能把后面的文字
    翻转显示——对研判工具来说，这等于可以伪造输出。

    为什么不在解析层调用：这些字符本身就是"混淆绕过"的检测特征，
    分析器要看得到它们。所以只在打印 / 渲染时清洗。
    """
    if not text:
        return ""
    return "".join(ch for ch in text if unicodedata.category(ch) not in _CONTROL_CATEGORIES)
