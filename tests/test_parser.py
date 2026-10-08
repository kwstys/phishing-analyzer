"""解析层单元测试。

覆盖四块：头部解码、正文提取、附件识别、畸形兜底。

其中两个测试是**回归测试**，对应开发过程中真实出现过的 bug：
  - test_repeated_headers_collected_as_list  → 曾经因为 return 缩进在循环里，只收到 1 个头部
  - test_body_is_always_str                  → 曾经因为 return 在 except 里，正常路径返回 None
改动这两个函数附近时，务必让它们保持绿色。
"""

from __future__ import annotations

import io

import pytest

from phishscope.models import ParsedEmail
from phishscope.parser import (
    ParseError,
    parse_bytes,
    parse_file,
    parse_stdin,
    parse_text,
)


# ==================================================================== 头部
class TestHeaders:
    def test_subject_chinese_decoded(self, simple_eml: bytes) -> None:
        """RFC 2047 编码的中文主题要解成可读中文，而不是 =?utf-8?B?...?=。"""
        mail = parse_bytes(simple_eml)
        assert mail.subject == "季度报表"

    def test_display_name_and_address_split(self, simple_eml: bytes) -> None:
        """'张三 <zhangsan@example.cn>' 要拆成显示名和地址两部分。"""
        mail = parse_bytes(simple_eml)
        assert mail.from_display == "张三"
        assert mail.from_addr == "zhangsan@example.cn"

    def test_domain_extracted(self, phishing_eml: bytes) -> None:
        mail = parse_bytes(phishing_eml)
        assert mail.from_domain == "micros0ft-support.com"

    def test_domain_is_lowercased(self) -> None:
        """域名大小写不敏感，统一小写方便后续比对。"""
        mail = parse_bytes(
            b"From: a@EXAMPLE.CN\r\nSubject: t\r\n\r\nbody\r\n",
        )
        assert mail.from_domain == "example.cn"

    def test_missing_from_records_warning(self, no_from_eml: bytes) -> None:
        """缺 From 不算致命错误，但必须留下痕迹（第 2 周的规则依赖这个字段）。"""
        mail = parse_bytes(no_from_eml)
        assert mail.from_addr == ""
        assert any("From" in w for w in mail.parse_warnings)

    def test_reply_to_collected(self, phishing_eml: bytes) -> None:
        mail = parse_bytes(phishing_eml)
        assert mail.reply_to == "harvest@evil-collect.top"

    # ---- 回归测试：曾经只收到 1 个头部 ----
    def test_repeated_headers_collected_as_list(self) -> None:
        """重复出现的头部（如 Received 投递链）必须收成一个 list，一条都不能丢。"""
        raw = b"".join(
            [
                b"Received: from a.example by b.example; Mon, 1 Jan 2026 00:00:00 +0000\r\n",
                b"Received: from c.example by a.example; Mon, 1 Jan 2026 00:00:01 +0000\r\n",
                b"Received: from d.example by c.example; Mon, 1 Jan 2026 00:00:02 +0000\r\n",
                b"From: x@example.com\r\n",
                "Subject: 投递链测试\r\n".encode(),
                b"\r\n",
                b"body\r\n",
            ]
        )
        mail = parse_bytes(raw)
        assert len(mail.headers["Received"]) == 3
        assert len(mail.headers) == 3, f"头部总数不对：{list(mail.headers)}"

    def test_authentication_results_available(self, phishing_eml: bytes) -> None:
        """认证结果头是第 3 周的核心输入，必须原样保留。"""
        raw = phishing_eml.replace(
            b"Subject: ",
            b"Authentication-Results: mx.example.cn; dmarc=fail\r\nSubject: ",
            1,
        )
        mail = parse_bytes(raw)
        assert "Authentication-Results" in mail.headers


# ==================================================================== 正文
class TestBody:
    def test_plain_text_body(self, simple_eml: bytes) -> None:
        mail = parse_bytes(simple_eml)
        assert "季度报表" in mail.body_text
        assert mail.body_html == ""

    def test_html_only_body(self, html_only_eml: bytes) -> None:
        """只有 HTML 的邮件：body_text 为空串，body_html 有内容。"""
        mail = parse_bytes(html_only_eml)
        assert mail.body_text == ""
        assert "账户需要验证" in mail.body_html

    def test_both_bodies(self, phishing_eml: bytes) -> None:
        mail = parse_bytes(phishing_eml)
        assert "账户存在异常" in mail.body_text
        assert "login.microsoftonline.com" in mail.body_html

    # ---- 回归测试：曾经正常路径返回 None ----
    @pytest.mark.parametrize("fixture_name", ["simple_eml", "html_only_eml", "phishing_eml"])
    def test_body_is_always_str(self, fixture_name: str, request: pytest.FixtureRequest) -> None:
        """正文永远是 str，绝不是 None —— 否则下游 .strip() 会 AttributeError。"""
        raw = request.getfixturevalue(fixture_name)
        mail = parse_bytes(raw)
        assert isinstance(mail.body_text, str)
        assert isinstance(mail.body_html, str)


# ==================================================================== 附件
class TestAttachments:
    def test_attachment_name_size_type(self, phishing_eml: bytes) -> None:
        mail = parse_bytes(phishing_eml)
        assert len(mail.attachments) == 1
        att = mail.attachments[0]
        assert att.filename == "Invoice_2026.pdf.exe"
        assert att.size == 56
        assert att.content_type == "application/octet-stream"
        assert att.is_inline is False

    def test_attachment_content_is_raw_bytes(self, phishing_eml: bytes) -> None:
        """附件内容是解码后的原始字节，第 5 周要靠它判真实文件类型。"""
        att = parse_bytes(phishing_eml).attachments[0]
        assert att.content[:2] == b"MZ"

    def test_no_attachments_for_plain_mail(self, simple_eml: bytes) -> None:
        assert parse_bytes(simple_eml).attachments == []

    def test_inline_image_flagged(self, inline_image_eml: bytes) -> None:
        """内嵌图片要标成 inline —— 否则报告里会把它当成「附件」误导用户。"""
        mail = parse_bytes(inline_image_eml)
        inline = [a for a in mail.attachments if a.is_inline]
        assert len(inline) == 1, f"没识别出内嵌图片：{mail.attachments}"
        assert inline[0].filename == "logo.png"

    def test_nested_mail_treated_as_attachment(self, nested_eml: bytes) -> None:
        """转发的内层邮件按附件处理，且**内层的主题不能覆盖外层**。"""
        mail = parse_bytes(nested_eml)
        assert mail.subject == "转发：内层主题"
        assert any(a.content_type == "message/rfc822" for a in mail.attachments)

    def test_nested_mail_body_not_leaked(self, nested_eml: bytes) -> None:
        """内层正文不能混进外层的 body_text。"""
        mail = parse_bytes(nested_eml)
        assert "请看下面的转发邮件" in mail.body_text
        assert "内层正文内容" not in mail.body_text


# ================================================================== 编码兜底
class TestEncodingFallback:
    def test_wrong_charset_does_not_crash(self, wrong_charset_eml: bytes) -> None:
        """声明 utf-8、实际是 GBK —— 不能崩，且要留下告警。"""
        mail = parse_bytes(wrong_charset_eml)
        assert isinstance(mail.body_text, str)
        assert mail.parse_warnings, "乱码了却没有告警"

    def test_invalid_charset_name_does_not_crash(self, bad_charset_name_eml: bytes) -> None:
        """charset 名字无效（如 unknown-8bit）要回退到 utf-8，并记录告警。"""
        mail = parse_bytes(bad_charset_name_eml)
        assert "hello world" in mail.body_text
        assert any("字符集" in w for w in mail.parse_warnings)

    def test_replacement_char_flagged(self, wrong_charset_eml: bytes) -> None:
        """出现 U+FFFD 说明声明与实际不符，必须记下来。"""
        mail = parse_bytes(wrong_charset_eml)
        assert any("FFFD" in w or "替换" in w for w in mail.parse_warnings)


# ==================================================================== 入口
class TestEntrypoints:
    def test_parse_bytes_source_default(self, simple_eml: bytes) -> None:
        assert parse_bytes(simple_eml).source == "<bytes>"

    def test_parse_bytes_source_custom(self, simple_eml: bytes) -> None:
        assert parse_bytes(simple_eml, source="x.eml").source == "x.eml"

    def test_raw_size_recorded(self, simple_eml: bytes) -> None:
        assert parse_bytes(simple_eml).raw_size == len(simple_eml)

    def test_parse_text(self) -> None:
        mail = parse_text("From: a@b.com\nSubject: test\n\nhello")
        assert mail.subject == "test"
        assert mail.source == "<text>"

    def test_parse_text_empty_rejected(self) -> None:
        with pytest.raises(ParseError):
            parse_text("   \n  ")


# ==================================================================== 错误
class TestErrors:
    def test_empty_bytes_rejected(self) -> None:
        with pytest.raises(ParseError):
            parse_bytes(b"")

    def test_not_an_email_rejected(self, not_an_email: bytes) -> None:
        """传个 PDF 进来必须被拦住，而不是产出一堆空字段。"""
        with pytest.raises(ParseError):
            parse_bytes(not_an_email)

    def test_random_binary_rejected(self) -> None:
        with pytest.raises(ParseError):
            parse_bytes(bytes(range(256)) * 4)

    def test_parse_file_missing(self, tmp_path) -> None:
        with pytest.raises(ParseError, match="不存在"):
            parse_file(tmp_path / "没有这个文件.eml")

    def test_parse_file_is_directory(self, tmp_path) -> None:
        with pytest.raises(ParseError, match="不是一个文件"):
            parse_file(tmp_path)

    def test_parse_file_empty(self, tmp_path) -> None:
        empty = tmp_path / "empty.eml"
        empty.write_bytes(b"")
        with pytest.raises(ParseError, match="空"):
            parse_file(empty)

    def test_parse_file_too_large(self, tmp_path, monkeypatch) -> None:
        """上限用 monkeypatch 调小，避免真去造一个 50MB 的文件。"""
        monkeypatch.setattr("phishscope.parser.MAX_FILE_SIZE", 10)
        big = tmp_path / "big.eml"
        big.write_bytes(b"x" * 100)
        with pytest.raises(ParseError, match="太大"):
            parse_file(big)

    def test_parse_file_ok(self, tmp_path, simple_eml: bytes) -> None:
        path = tmp_path / "正常邮件.eml"
        path.write_bytes(simple_eml)
        mail = parse_file(path)
        assert mail.source == "正常邮件.eml"
        assert mail.subject == "季度报表"

    def test_parse_file_returns_parsed_email_type(self, tmp_path, simple_eml: bytes) -> None:
        path = tmp_path / "a.eml"
        path.write_bytes(simple_eml)
        assert isinstance(parse_file(path), ParsedEmail)


# ==================================================================== stdin
class _FakeStdin:
    """只提供 parse_stdin 需要的那一个属性：buffer（二进制流）。"""

    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)


class TestStdin:
    def test_parse_stdin(self, monkeypatch, simple_eml: bytes) -> None:
        monkeypatch.setattr("sys.stdin", _FakeStdin(simple_eml))
        mail = parse_stdin()
        assert mail.subject == "季度报表"
        assert mail.source == "<stdin>"

    def test_parse_stdin_empty_rejected(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.stdin", _FakeStdin(b""))
        with pytest.raises(ParseError, match="空"):
            parse_stdin()

    def test_parse_stdin_without_buffer(self, monkeypatch) -> None:
        """没有 .buffer 的 stdin（比如被替换成普通对象）要给清晰报错。"""

        class NoBuffer:
            pass

        monkeypatch.setattr("sys.stdin", NoBuffer())
        with pytest.raises(ParseError, match="不可用"):
            parse_stdin()
