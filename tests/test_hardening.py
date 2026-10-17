"""硬化测试：对抗性输入的防护。

这里每条输入都是**攻击者能构造出来的**。测的不是功能正确，
而是不崩、不挂、不把控制字符打到分析员脸上。
"""

from __future__ import annotations

from email.message import EmailMessage

import pytest

import phishscope.parser as parser_mod
from phishscope.__main__ import format_summary, main
from phishscope.parser import MAX_FILE_SIZE, MAX_MIME_DEPTH, MAX_PARTS, ParseError, parse_bytes


def _nested(depth: int) -> bytes:
    """造一封嵌套 depth 层的 multipart 邮件。"""
    root = EmailMessage()
    root["From"] = "a@b.com"
    root["Subject"] = "deep"
    current = root
    for _ in range(depth):
        child = EmailMessage()
        child.set_content("hi")
        current.make_mixed()
        current.attach(child)
        current = child
    return root.as_bytes()


def _mail_with(**headers: str) -> bytes:
    """用标准库构造一封单头部可自定义的邮件（头部会被正确编码）。"""
    msg = EmailMessage()
    msg["From"] = headers.get("From", "x@y.com")
    msg["Subject"] = headers["Subject"]
    msg["Date"] = "Mon, 1 Jan 2026 00:00:00 +0800"
    msg["Message-ID"] = "<1@y.com>"
    msg.set_content("body")
    return msg.as_bytes()


# ──────────────────────────────────────────── P0-1 递归
def test_deep_nesting_raises_parse_error():
    """P0-1：深层嵌套必须是清晰报错，而不是 RecursionError 带着堆栈冲出去。

    深度只取 70（刚过上限）而不是更大值，是因为**构造**这个样本时
    `as_bytes()` 自己也是递归的，深度太大在测试代码里就先爆了。
    """
    with pytest.raises(ParseError, match="嵌套太深"):
        parse_bytes(_nested(MAX_MIME_DEPTH + 20), source="<deep>")


def test_very_deep_nesting_is_converted_to_parse_error():
    """比 stdlib 递归极限还深的输入，也必须落到 ParseError。

    构造阶段本身可能就递归爆掉（取决于 Python 版本），那种情况跳过——
    我们测的是**解析**阶段的防护，不是标准库的构造能力。
    """
    try:
        data = _nested(500)
    except RecursionError:
        pytest.skip("构造阶段就递归爆掉，无法造出这个样本")
    with pytest.raises(ParseError):
        parse_bytes(data, source="<depth500>")


def test_normal_nesting_still_parses():
    """别把正常的嵌套也拦掉了。"""
    mail = parse_bytes(_nested(3), source="<ok>")
    assert mail.from_addr == "a@b.com"


# ──────────────────────────────────────────── P1-3 输入预算
def test_oversized_input_is_rejected(monkeypatch: pytest.MonkeyPatch):
    """P1-3：尺寸上限设在唯一收窄点 parse_bytes，三个入口自动都被保护。"""
    monkeypatch.setattr(parser_mod, "MAX_FILE_SIZE", 1024)
    with pytest.raises(ParseError, match="太大"):
        parse_bytes(b"From: a@b.com\r\n\r\n" + b"x" * 2000, source="<big>")


def test_too_many_parts_is_rejected():
    """P1-3：几千个部件这种廉价构造要挡住。"""
    parts = "".join(
        f"--B\r\nContent-Type: text/plain\r\n\r\npart{i}\r\n" for i in range(MAX_PARTS + 10)
    )
    raw = (
        "From: a@b.com\r\n"
        "Subject: many\r\n"
        'Content-Type: multipart/mixed; boundary="B"\r\n'
        "\r\n" + parts + "--B--\r\n"
    ).encode()
    with pytest.raises(ParseError, match="部件太多"):
        parse_bytes(raw, source="<many>")


def test_size_limit_constant_is_sane():
    """上限本身别被改成一个荒唐的值。"""
    assert MAX_FILE_SIZE == 50 * 1024 * 1024
    assert 0 < MAX_MIME_DEPTH <= 100
    assert 0 < MAX_PARTS <= 5000


# ──────────────────────────────────────────── P0-2 控制字符
def test_ansi_escape_is_kept_at_parse_time_but_stripped_at_display_time():
    """P0-2：解析层保留控制字符（那是混淆特征），展示层必须清掉。"""
    evil = "Invoice \x1b[31mRED\x1b[0m\x07 通知"
    mail = parse_bytes(_mail_with(Subject=evil), source="<ansi>")

    assert "\x1b" in mail.subject, "解析层不该丢弃控制字符——分析器要看它"

    out = format_summary(mail)
    assert "\x1b" not in out, "ANSI 转义漏到终端了，攻击者可以清屏/覆盖输出"
    assert "\x07" not in out, "BEL 漏到终端了"
    assert "RED" in out, "文字本身不该被一起删掉"


def test_bidi_override_is_stripped_at_display_time():
    """U+202E 能翻转后续文字的显示顺序，同样属于展示层污染。"""
    evil = "invoice\u202egnp.exe"
    mail = parse_bytes(_mail_with(Subject=evil), source="<bidi>")

    assert "\u202e" in mail.subject
    assert "\u202e" not in format_summary(mail)


@pytest.mark.parametrize(
    "char",
    # 注意没有 \r：标准库的 EmailMessage 直接拒绝把 CR/LF 写进头部，
    # 所以"解析出来的头部值里含 \r"这种情况实际构造不出来。
    ["\x1b[2J\x1b[H", "\x07", "\x08", "\u202e", "\u200b"],
)
def test_common_terminal_hazards_are_stripped(char: str):
    mail = parse_bytes(_mail_with(Subject=f"A{char}B"), source="<hazard>")
    assert char not in format_summary(mail)


# ──────────────────────────────────────────── CLI 层面：不吐堆栈
def test_cli_reports_deep_nesting_without_traceback(tmp_path, capsys):
    """验收标准：错误的输入给清晰报错，不是一屏堆栈。"""
    target = tmp_path / "deep.eml"
    target.write_bytes(_nested(MAX_MIME_DEPTH + 20))

    exit_code = main([str(target)])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "错误" in captured.err
    assert "Traceback" not in captured.err
    assert "RecursionError" not in captured.err
