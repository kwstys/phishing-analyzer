"""命令行入口测试。

CLI 的价值一半在「正常时输出对不对」，另一半在「出错时是不是人话、退出码对不对」。
两边都测。
"""

from __future__ import annotations

import io

import pytest

from phishscope.__main__ import html_to_text, main


class _FakeStdin:
    def __init__(self, data: bytes) -> None:
        self.buffer = io.BytesIO(data)

    def isatty(self) -> bool:
        return False


class _FakeTty:
    """假装是交互式终端。"""

    def isatty(self) -> bool:
        return True


# ==================================================================== 正常路径
class TestSuccess:
    def test_file_success_exit_zero(self, tmp_path, capsys, simple_eml: bytes) -> None:
        path = tmp_path / "mail.eml"
        path.write_bytes(simple_eml)
        assert main([str(path)]) == 0

    def test_file_output_contains_key_fields(self, tmp_path, capsys, phishing_eml: bytes) -> None:
        path = tmp_path / "mail.eml"
        path.write_bytes(phishing_eml)
        main([str(path)])
        out = capsys.readouterr().out
        assert "微软账户团队" in out
        assert "【立即验证】您的账户将被停用" in out
        assert "micros0ft-support.com" in out
        assert "Invoice_2026.pdf.exe" in out

    def test_text_input(self, capsys) -> None:
        assert main(["--text", "From: a@b.com\nSubject: 来自文本\n\nhello"]) == 0
        assert "来自文本" in capsys.readouterr().out

    def test_stdin_input(self, monkeypatch, capsys, simple_eml: bytes) -> None:
        monkeypatch.setattr("sys.stdin", _FakeStdin(simple_eml))
        assert main([]) == 0
        assert "季度报表" in capsys.readouterr().out

    def test_version(self, capsys) -> None:
        # argparse 的 version action 靠抛 SystemExit(0) 结束
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0
        assert "PhishScope" in capsys.readouterr().out


# ==================================================================== 错误路径
class TestErrors:
    def test_missing_file_returns_2(self, tmp_path, capsys) -> None:
        assert main([str(tmp_path / "没有.eml")]) == 2
        err = capsys.readouterr().err
        assert "错误" in err
        assert "不存在" in err

    def test_not_an_email_returns_2(self, tmp_path, capsys, not_an_email: bytes) -> None:
        path = tmp_path / "fake.pdf"
        path.write_bytes(not_an_email)
        assert main([str(path)]) == 2
        assert "错误" in capsys.readouterr().err

    def test_path_and_text_conflict(self, capsys, simple_eml: bytes) -> None:
        """同时给路径和 --text 是用法错误。"""
        assert main(["a.eml", "--text", "x"]) == 2
        assert "只能给一个" in capsys.readouterr().err

    def test_empty_stdin_returns_2(self, monkeypatch, capsys) -> None:
        monkeypatch.setattr("sys.stdin", _FakeStdin(b""))
        assert main([]) == 2
        assert "错误" in capsys.readouterr().err

    def test_tty_without_args_returns_2(self, monkeypatch, capsys) -> None:
        """交互式终端下不给参数：不能干等着读输入，要直接报用法。"""
        monkeypatch.setattr("sys.stdin", _FakeTty())
        assert main([]) == 2
        assert "用法" in capsys.readouterr().err

    def test_error_goes_to_stderr_not_stdout(self, tmp_path, capsys) -> None:
        """错误信息必须走 stderr，这样 stdout 才能被干净地重定向。"""
        main([str(tmp_path / "没有.eml")])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err != ""


# ================================================================ HTML 去标签
class TestHtmlToText:
    """html_to_text 只用于终端预览，宁可粗糙也不能把内容吃掉。"""

    @pytest.mark.parametrize(
        ("markup", "expected", "why"),
        [
            ("<style>body{color:red}</style><p>正文在这里</p>", "正文在这里", "style 整块要丢掉"),
            ("<script>alert(1)</script>考核通知", "考核通知", "script 内容要丢掉，正文保留"),
            ("<td>金额</td><td>&nbsp;100&amp;200</td>", "金额 100&200", "HTML 实体要还原"),
            (
                "被转义的 &lt;script&gt; 应保留",
                "被转义的 <script> 应保留",
                "转义过的标签是给人看的文字，不能删",
            ),
            ("<div>第一行</div><div>第二行</div>", "第一行 第二行", "块级标签换空格，不粘连"),
        ],
    )
    def test_html_to_text(self, markup: str, expected: str, why: str) -> None:
        assert html_to_text(markup) == expected, why

    def test_plain_text_passthrough(self) -> None:
        assert html_to_text("没有任何标签") == "没有任何标签"

    def test_empty_input(self) -> None:
        assert html_to_text("") == ""


# ================================================================ HTML 预览
class TestHtmlPreview:
    # ---- 回归测试：预览曾经直接打印原始 HTML 标签 ----
    def test_preview_has_no_tags(self, tmp_path, capsys, html_only_eml: bytes) -> None:
        path = tmp_path / "html.eml"
        path.write_bytes(html_only_eml)
        main([str(path)])
        out = capsys.readouterr().out
        assert "<html>" not in out
        assert "<p>" not in out
        assert "您的账户需要验证" in out

    def test_full_body_flag(self, tmp_path, capsys, html_only_eml: bytes) -> None:
        path = tmp_path / "html.eml"
        path.write_bytes(html_only_eml)
        main([str(path)])
        clipped = capsys.readouterr().out
        main([str(path), "--full-body"])
        full = capsys.readouterr().out
        # 这封信正文很短，两种模式内容应当一致
        assert "您的账户需要验证" in clipped
        assert "您的账户需要验证" in full
