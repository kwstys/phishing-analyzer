"""命令行入口：python -m phishscope 收件.eml

三种输入方式：
    python -m phishscope suspect.eml      读文件
    python -m phishscope --text "..."     直接给文本（正文里带换行用引号包住即可）
    type suspect.eml | python -m phishscope    管道（未给参数时自动读 stdin）
"""

from __future__ import annotations

import argparse
import html
import re
import sys

from . import __version__
from .models import ParsedEmail
from .parser import ParseError, parse_file, parse_stdin, parse_text

# 正文预览取多少个字符。这是验收标准写死的数字（"正文前 200 字"），改它要同步改文档。
BODY_PREVIEW_CHARS = 200

# 打印用的分隔线。全文件都用这一条，换风格时只改这里。
RULE = "-" * 60


def force_utf8_stdout() -> None:
    """把标准输出切成 UTF-8，编码不了的字符替换掉而不是抛异常。

    坑 1：Windows 控制台默认 GBK，直接 print 中文/日文/emoji 会抛
    UnicodeEncodeError 把程序打崩。errors="replace" 保证最差是乱码，绝不崩溃。

    reconfigure 不是所有流都有（被重定向成普通对象时没有），所以用 getattr 探测。
    """
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        reconfigure(encoding="utf-8", errors="replace")


def human_size(num_bytes: int) -> str:
    """字节数 → 人读的大小：3174 → '3.1 KB'。"""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"  # 走不到，兜底而已


def clean_preview(text: str) -> str:
    """把正文压成一行，方便看开头。

    为什么要压：HTML 转出来的正文、以及 78 字符硬折行的邮件，
    直接截 200 字可能只看到几个词。这里把所有空白折成单个空格。
    """
    return " ".join(text.split())


# 整块丢掉的标签：script / style 的内容不是给人看的正文
_DROP_BLOCKS = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
# 其余标签一律换成空格：直接删掉会让相邻文字粘成一个词（word<b>x</b>word → wordxword）
_ANY_TAG = re.compile(r"<[^>]*>")


def html_to_text(markup: str) -> str:
    """把 HTML 粗加工成可读文本，只用于终端预览。

    ⚠️ 这是第 1 周的临时办法，已知短板（第 4 周会用 BeautifulSoup 重做）：
      - 属性里含 ">" 的畸形 HTML 会处理不干净
      - 不还原 <br> / <table> 的换行与排版，全部压成一行
      - 行内标签会被换成空格，"word<b>bold</b>word" 变成 "word bold word"
    """
    text = _DROP_BLOCKS.sub(" ", markup)
    text = _ANY_TAG.sub(" ", text)
    # 实体必须最后还原：先还原的话，被转义的 &lt;script&gt; 会被当成真标签删掉
    text = html.unescape(text)
    return " ".join(text.split())


def clip(text: str, limit: int = BODY_PREVIEW_CHARS) -> str:
    """超长就截断并加省略号。"""
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def format_summary(mail: ParsedEmail, full_body: bool = False) -> str:
    """把 ParsedEmail 拼成一段可打印的报告。返回字符串，不直接 print。

    拆成"拼字符串"和"打印"两步，是为了以后想同时输出到文件/JSON 时不用重写。
    """
    lines: list[str] = [f"来源: {mail.source}", f"大小: {human_size(mail.raw_size)}", RULE]

    # ---- 发件人 ----
    if mail.from_display and mail.from_addr:
        lines.append(f"发件人: {mail.from_display} <{mail.from_addr}>")
    else:
        lines.append(f"发件人: {mail.from_addr or mail.from_display or '(缺失)'}")

    if mail.from_domain:
        lines.append(f"发件域名: {mail.from_domain}")

    # 有才打印。这两条第 2 周要拿来和 From 做比对，现在先让人看见
    if mail.reply_to:
        lines.append(f"回复地址: {mail.reply_to}")
    if mail.return_path:
        lines.append(f"退回地址: {mail.return_path}")

    lines.append(f"收件人: {mail.to or '(缺失)'}")

    # ---- 主题 ----
    # 主题单独一行并加空行分隔：它是人扫一眼最先看的东西
    lines.append("")
    lines.append(f"主题: {mail.subject or '(无主题)'}")

    if mail.date:
        lines.append(f"日期: {mail.date}")
    if mail.message_id:
        lines.append(f"消息 ID: {mail.message_id}")

    # ---- 正文 ----
    lines.append("")
    if mail.body_text.strip():
        body = clean_preview(mail.body_text)
        shown = body if full_body else clip(body)
        lines.append(f"正文:text/plain（{len(mail.body_text)} 字符）：")
        lines.append(shown)
    else:
        lines.append("正文:text/plain（无）")

    if mail.body_html.strip():
        html_text = html_to_text(mail.body_html)
        lines.append("")
        lines.append(f"正文:text/html（{len(mail.body_html)} 字符）：")
        shown = html_text if full_body else clip(html_text)
        lines.append("  " + shown + "   [已去标签]")

    # ---- 附件 ----
    lines.append("")
    if not mail.attachments:
        lines.append("附件: 无")
    else:
        lines.append(f"附件: {len(mail.attachments)} 个")
        for att in mail.attachments:
            kind = "内嵌资源" if att.is_inline else "附件"
            lines.append(
                f"  - [{kind}] {att.filename}  ({att.content_type}, {human_size(att.size)})"
            )

    # ---- 解析告警 ----
    # 这是坑 3 / 坑 4 的出口：不崩，但把可疑之处记下来给人看
    if mail.parse_warnings:
        lines.append("")
        lines.append(f"解析告警（{len(mail.parse_warnings)} 条）：")
        for warning in mail.parse_warnings:
            lines.append(f"  ! {warning}")

    return "\n".join(lines)


def build_arg_parser() -> argparse.ArgumentParser:
    """
    定义命令行参数。
    """
    parser = argparse.ArgumentParser(
        prog="phishscope",
        description="PhishScope —— 离线优先、结论可解释的钓鱼邮件分析器（第 1 周：仅解析预览）",
        epilog=(
            "示例：\n"
            "  python -m phishscope suspect.eml\n"
            '  python -m phishscope --text "From: a@b.com"\n'
            "  type suspect.eml | python -m phishscope"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="要分析的 .eml 文件路径；不填则从标准输入读",
    )
    parser.add_argument(
        "--text",
        metavar="文本",
        help="直接分析一段原始邮件文本，而不是文件",
    )
    parser.add_argument(
        "--full-body",
        action="store_true",
        help="打印完整正文，而不是只显示前 200 字",
    )
    parser.add_argument("--version", action="version", version=f"PhishScope {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    CLI 主函数。返回退出码：0 = 成功，2 = 输入有问题。
    """
    force_utf8_stdout()
    args = build_arg_parser().parse_args(argv)

    # 一次只能有一种输入方式
    given = [name for name, value in (("path", args.path), ("--text", args.text)) if value]
    if len(given) > 1:
        print("错误：文件路径和 --text 只能给一个。", file=sys.stderr)
        return 2

    try:
        if args.text is not None:
            mail = parse_text(args.text)
        elif args.path is not None:
            mail = parse_file(args.path)
        else:
            if sys.stdin.isatty():
                # 交互式终端下干等着读输入，人会以为程序卡死
                print(
                    "错误：没有输入。用法：python -m phishscope <文件.eml>\n"
                    "      管道用法：type 文件.eml | python -m phishscope",
                    file=sys.stderr,
                )
                return 2
            mail = parse_stdin()
    except ParseError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # 预期外的 IO 问题（磁盘、权限）。也不要吐堆栈
        print(f"错误：读取失败（{exc}）", file=sys.stderr)
        return 2

    print(format_summary(mail, full_body=args.full_body))
    return 0


if __name__ == "__main__":
    sys.exit(main())
