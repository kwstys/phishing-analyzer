"""跨层数据契约。

两个对象把整条链路切成三段：

    ParsedEmail —— 解析层的产物，**分析层唯一认识的东西**
    Finding     —— 分析层的产物，**评分层 / 报告层唯一认识的东西**

解析层不该懂钓鱼，评分层不该懂邮件，两边只通过这两个对象打交道。
"""

from dataclasses import dataclass, field
from enum import Enum

from .rules import RULES


@dataclass
class Attachment:
    filename: str  # 文件名（已解码）
    content_type: str  # 声明的 MIME 类型
    size: int  # 解码后的字节数
    content: bytes  # 解码后的原始字节
    is_inline: bool = False  # 内嵌资源（正文里的图片），通常不算真附件


@dataclass
class ParsedEmail:
    source: str  # 来源

    from_display: str  # From 的显示名
    from_addr: str  # From 的地址
    from_domain: str  # 地址的域名
    reply_to: str  # Reply-To 原始值
    return_path: str  # Return-Path 原始值
    to: str
    subject: str
    date: str
    message_id: str

    # 值是 list：Received 会有十几条。第 2、3 周查投递链要用
    headers: dict[str, list[str]] = field(default_factory=dict)

    # ----正文（可能只有一个，另一个为空字符串）----
    body_text: str = ""  # text/plain 部分
    body_html: str = ""  # text/html 部分

    # ----附件----
    attachments: list[Attachment] = field(default_factory=list)

    # ----元信息----
    raw_size: int = 0  # 原始字节数
    parse_warnings: list[str] = field(default_factory=list)  # 解析时遇到的问题

    def header(self, name: str) -> list[str]:
        """按名字取头部值，**不区分大小写**，返回全部（可能多条）。

        ⚠️ 不要写 mail.headers.get("Reply-To")。headers 的键保留邮件里的
        **原始大小写**，一封把头部写成小写 `reply-to:` 的邮件会让
        `.get("Reply-To")` 静默返回空——规则不触发，报告显示"一切正常"。
        对检测工具来说，假阴性比假阳性更糟。

        返回多条有两种来源：
          ① 同一个键下有多个值（Received 有十几条）
          ② 多个只差大小写的键（From 和 FROM 被 _collect_headers 分开存）
        后者正是「存在多个发件人字段」那条规则要数的东西。
        """
        wanted = name.lower()
        found: list[str] = []
        for key, values in self.headers.items():
            if key.lower() == wanted:
                found.extend(values)
        return found


class Severity(Enum):
    INFO = "提示"
    LOW = "低"
    MEDIUM = "中"
    HIGH = "高"
    CRITICAL = "严重"


@dataclass
class Finding:
    rule: str  # 规则中文名，同时是唯一标识（见 rules.RULES）
    severity: Severity
    summary: str  # 一句话结论，直接展示给用户
    evidence: str  # 触发它的原始内容，可解释性的关键
    detail: str = ""  # 为什么可疑（给非专业读者看的解释）

    def __post_init__(self) -> None:
        """校验规则名已在 rules.RULES 注册。

        校验放在构造时而不是评分时：「规则名拼错」是写代码时的错误，
        应该在第一次构造就炸出来（测试里立刻能看见），
        而不是等第 6 周按名字查权重时静默变成 0 分。
        """
        if self.rule not in RULES:
            raise ValueError(
                f"未注册的规则名：{self.rule!r}。"
                "新规则要先加到 phishscope/rules.py 的 RULES 里"
            )
