from dataclasses import dataclass, field


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
