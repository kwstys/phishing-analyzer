### ----邮件解析层----

from __future__ import annotations

import email
import sys
from email import policy
from email.header import decode_header, make_header
from email.utils import parseaddr
from pathlib import Path

from .models import Attachment, ParsedEmail

MAX_FILE_SIZE = 50 * 1024 * 1024


class ParseError(Exception):
    """解析层拒绝处理这个输入。

    为什么不写成 parse_warnings 里的一条？
    ────────────────────────────────────────
    parse_warnings 记的是"这封信能解析，但某处不对劲"（缺字符集、文件名乱码）。
     "根本不是邮件"是另一类问题：这时候造出来的 ParsedEmail 全是空字段，
    交给第 2 周的分析器只会得出一堆无意义的"没问题"——比报错更误导人。
    所以这里直接拒绝，由 CLI 接住并打印人话（验收标准：清晰报错而非堆栈）。
    """


def _decode_header_value(raw) -> str:
    """把头部值统一变成 str。

    policy=default 下 msg["Subject"] 已经是解码好的对象（str 子类），
    所以这里主要是兜底：万一拿到没解码的 =?utf-8?B?...?= 再解一次。
    """
    if raw is None:
        return ""
    text = str(raw)
    if "=?" in text:
        try:
            return str(make_header(decode_header(text)))
        except Exception:
            return text
    return text


def _split_address(value: str) -> tuple[str, str]:
    """ "微软账户团队 <a@b.com>" → ("微软账户团队", "a@b.com")"""
    display, addr = parseaddr(value)
    if not addr and value.strip():
        return value.strip(), ""
    return display.strip(), addr.strip()


def _domain_of(addr: str) -> str:
    """ "a@b.com" → "b.com"；没有 @ 时返回空串（别抛异常）"""
    if "@" not in addr:
        return ""
    return addr.rpartition("@")[2].strip().lower()  # 读取@后面部分即域名并转换成小写


def _collect_headers(msg) -> dict[str, list[str]]:
    """把全部头部收成 名字 → 值列表。

    只收最外层（msg.items()），不递归进内层邮件——
    Received 投递链、Authentication-Results 这些都在最外层。
    """
    headers: dict[str, list[str]] = {}
    for name, value in msg.items():
        headers.setdefault(name, []).append(str(value))
    return headers


def _walk_parts(msg):
    """遍历所有 part，但**不钻进嵌套邮件**（坑 6）。

    不能用 msg.walk()：它会把 message/rfc822（转发邮件）里的内层邮件
    也展开，内层的 From/Subject 会混进外层结果里。
    这里自己写一个递归：遇到 message/rfc822 就当普通 part 交出去，不再往下走。
    """
    if not msg.is_multipart():
        yield msg
        return
    for part in msg.iter_parts():
        if part.get_content_type() == "message/rfc822":
            yield part
        else:
            yield from _walk_parts(part)


def _decode_part_text(part, warnings: list[str]) -> str:
    """把一个 part 的正文解码成 str，带乱码兜底。"""
    payload = part.get_payload(decode=True)
    if payload is None:
        return ""

    charset = part.get_content_charset() or "utf-8"
    try:
        text = payload.decode(charset, errors="replace")
    except LookupError:
        # charset 本身是一个无效名字，比如charset="unknown-8bit"
        warnings.append(f"未知字符集{charset!r},已回退utf-8")
        text = payload.decode("utf-8", errors="replace")

    if "\ufffd" in text:
        # 能解码但解码结果是替换字符 → 声明于实际字节不符（钓鱼邮件常见手法）
        warnings.append(f"正文有无法按{charset!r}解码的字节，已替换为U+FFFD")
    return text


def _iter_attachments(msg, warnings: list[str]) -> list[Attachment]:
    """挑出附件和内嵌资源）。"""
    result: list[Attachment] = []

    for part in _walk_parts(msg):
        if part.get_content_maintype() == "multipart":
            continue  # 容器，不是附件

        ctype = part.get_content_type()
        disposition = part.get_content_disposition()  # "attachment" / "inline" / None
        raw_name = part.get_filename()
        is_nested_mail = ctype == "message/rfc822"

        # 没有disposition，没有文件名，也不是嵌套邮件：这是正文，跳过
        if disposition is None and raw_name is None and not is_nested_mail:
            continue
        if is_nested_mail and disposition is None:
            disposition = "attachment"  # 转发的内层邮件按附件对待

        if raw_name is None:
            warnings.append(f"有一个{ctype}附件没有文件名")
            filename = "(无文件名)"
        else:
            filename = _decode_header_value(raw_name).strip() or "(无文件名)"

        if is_nested_mail:
            inner = part.get_payload()
            content = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
        else:
            content = part.get_payload(decode=True) or b""

        result.append(
            Attachment(
                filename=filename,
                content_type=ctype,
                size=len(content),
                content=content,
                is_inline=(disposition == "inline"),
            )
        )
    return result


def _looks_like_email(msg, data: bytes) -> bool:
    """判断这到底是不是一封邮件。

    message_from_bytes 对任何字节都不会报错——传个 PDF 进去它也会当成
    "没有头部的正文"。所以这里做一次合理性检查。
    """
    if len(msg.items()) == 0:  # 一个头部字段都没有，不是邮件
        return False
    if any(msg.get(name) for name in ("From", "To", "Subject", "Date", "Message-ID")):
        return True
    # 如果头部字段没有，查看一下第一行像不像
    first_line = data.split(b"\n", 1)[0]
    return b":" in first_line and not first_line.lstrip().startswith(b"%")


# ======================================
# 对外 4 个入口
# ======================================


def parse_bytes(data: bytes, source: str = "<bytes>") -> ParsedEmail:
    """
    核心函数。所有输入方式最后都走这里。
    参数必须是 bytes，不能是 str
    message_from_bytes 必须带 policy=policy.default，否则中文头部
    会退回成 =?utf-8?B?...?= 那串编码字
    """
    warnings: list[str] = []
    msg = email.message_from_bytes(data, policy=policy.default)

    if not _looks_like_email(msg, data):
        raise ParseError(
            f"{source}看起来不是一封邮件"
            f"(开头字节{data[:8]!r},解析后没有任何可识别的头部)。"
            "本工具只接受 .eml 文件或原始邮件文本"
        )

    from_raw = _decode_header_value(msg.get("From"))
    from_display, from_addr = _split_address(from_raw)
    if not from_addr:
        warnings.append("缺少或无法解析 From 头")

    body_text = ""
    body_html = ""
    for part in _walk_parts(msg):
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_disposition() == "attachment" or part.get_filename():
            continue
        if part.get_content_type() == "message/rfc822":
            warnings.append("含转发的嵌套邮件，内层内容未展开（已按附件处理）")
            continue
        ctype = part.get_content_type()
        # 只取第一个：正文既可能是 multipart/alternative 的两个版本
        # 也可能是重复的 text/plain(取第一个更像原文)
        if ctype == "text/plain" and not body_text:
            body_text = _decode_part_text(part, warnings)
        elif ctype == "text/html" and not body_html:
            body_html = _decode_part_text(part, warnings)

    return ParsedEmail(
        source=source,
        from_display=from_display,
        from_addr=from_addr,
        from_domain=_domain_of(from_addr),
        reply_to=_decode_header_value(msg.get("Reply-to")),
        return_path=_decode_header_value(msg.get("Return-Path")),
        to=_decode_header_value(msg.get("To")),
        subject=_decode_header_value(msg.get("Subject")),
        date=_decode_header_value(msg.get("Date")),
        message_id=_decode_header_value(msg.get("Message-ID")),
        headers=_collect_headers(msg),
        body_text=body_text,
        body_html=body_html,
        attachments=_iter_attachments(msg, warnings),
        raw_size=len(data),
        parse_warnings=warnings,
    )


def parse_file(path: str | Path) -> ParsedEmail:
    """读 .eml 文件。各种读不了的情况给清晰提示，不抛原始堆栈。"""
    p = Path(path)

    if not p.exists():
        raise ParseError(f"文件不存在：{p}")
    if not p.is_file():
        raise ParseError(f"这不是一个文件：{p}")

    size = p.stat().st_size
    if size == 0:
        raise ParseError(f"文件是空的：{p}")
    if size > MAX_FILE_SIZE:
        raise ParseError(
            f"文件太大：{size / 1024 / 1024:.1f} MB，上限 {MAX_FILE_SIZE // 1024 // 1024} MB"
        )

    try:
        # 必须按 bytes 读。按文本读会先按控制台编码解码，中文直接坏掉
        data = p.read_bytes()
    except OSError as exc:
        raise ParseError(f"读取文件失败：{p}（{exc}）") from exc

    return parse_bytes(data, source=p.name)


def parse_text(text: str) -> ParsedEmail:
    """从原始邮件文本解析（用户从网页邮箱复制粘贴的）。

    str → bytes 只能挑一种编码，这里选 utf-8。原因：
    头部里的 =?charset?B?...?= 编码字全是 ASCII，重新编码不会破坏它；
    真正的风险在"charset 声明与实际字节不符"的正文上，那条路已由
    _decode_part_text 的乱码兜底 + parse_warnings 覆盖。
    """
    if not text.strip():
        raise ParseError("文本是空的")
    return parse_bytes(text.encode("utf-8"), source="<text>")


def parse_stdin() -> ParsedEmail:
    """从标准输入读 bytes（坑 8）。"""
    stream = getattr(sys.stdin, "buffer", None)
    if stream is None:
        raise ParseError("当前标准输入不可用（没有二进制流）")
    data = stream.read()
    if not data:
        raise ParseError("标准输入是空的")
    return parse_bytes(data, source="<stdin>")
