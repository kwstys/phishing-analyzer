"""头部欺诈检测：13 条规则。

每条规则是一个 `_check_xxx(mail) -> Finding | None` 的**纯函数**：
命中就返回一个 Finding，没命中返回 None。这样每条都能单独测，
不用经过 analyze_headers()。

每个口径为什么这么定，都写在对应函数的注释里——单看这个文件就能读懂，
不需要另找别的文档。
"""

from __future__ import annotations

import re
import unicodedata

from ..models import Finding, ParsedEmail, Severity
from ..util import domain_of, split_address, top_domain, unfold
from . import knowledge

# 会用来冒充拉丁字母的「可疑」文字系统。只在同一个标签内部才比较——
# 整串比较会把 中国.cn 这种合法国际化域名里的拉丁后缀也算进去。
_SUSPICIOUS_SCRIPTS = frozenset({"CYRILLIC", "GREEK", "ARMENIAN", "HANGUL", "CHEROKEE"})


# ---------------------------------------------------------------- 公共小工具
def _from_top(mail: ParsedEmail) -> str:
    """发件地址的**注册域**。所有域比较都走它，别用 mail.from_domain 直接比。"""
    return top_domain(mail.from_domain)


def _top_of_header_address(value: str) -> str:
    """从可能带显示名的地址值里取注册域（Reply-To / Return-Path 用）。"""
    _, addr = split_address(unfold(value))
    return top_domain(domain_of(addr))


def _decode_idn(domain: str) -> str:
    """xn-- 开头的标签解码成可读形式；不是国际化域名或解码失败就原样返回。"""
    if "xn--" not in domain:
        return domain
    try:
        return domain.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        return domain


def _scripts_of(text: str) -> set[str]:
    """字符串里出现了哪些文字系统（粗略判断：取 Unicode 名字的第一个词）。"""
    scripts: set[str] = set()
    for char in text:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        if name:
            scripts.add(name.split(" ")[0])
    return scripts


def _homoglyph_reason(label: str, table: dict[str, str]) -> str | None:
    """判断单个域名标签是不是同形异义伪装。是就返回一句人话理由。

    两条判据缺一不可：
      ① 混用：既有 ASCII 拉丁字母，又有形近字符
      ② 整词同形：整个标签全由形近字符拼成（аррӏе.com 这种，判据①抓不到）
    """
    if len(label) < 3:
        return None

    lowered = label.lower()
    hits = [char for char in lowered if char in table]
    has_ascii = any("a" <= char <= "z" for char in lowered)

    if has_ascii and hits:
        return f"混用了拉丁字母和形近字符 {' '.join(sorted(set(hits)))}"
    if len(hits) == len(lowered) and not has_ascii:
        return f"整个标签都由形近字符拼成（{' '.join(sorted(set(hits)))}）"
    scripts = _scripts_of(lowered)
    if "LATIN" in scripts and scripts & _SUSPICIOUS_SCRIPTS:
        others = "、".join(sorted(scripts & _SUSPICIOUS_SCRIPTS))
        return f"在同一个标签里混用了拉丁字母和 {others} 文字"
    return None


def _brand_matched_by_display(display: str) -> tuple[str, str] | None:
    """显示名命中了哪个品牌的哪个别名。返回 (品牌名, 别名)。"""
    lowered = display.strip().lower()
    if not lowered:
        return None
    for brand, (aliases, _domains) in knowledge.brands().items():
        for alias in sorted(aliases):
            if alias and alias in lowered:
                return brand, alias
    return None


# ---------------------------------------------------------------- 规则 1
def _check_reply_to_mismatch(mail: ParsedEmail) -> Finding | None:
    """回复地址与发件人不一致（中）"""
    if not mail.reply_to:
        return None
    reply_top = _top_of_header_address(mail.reply_to)
    from_top = _from_top(mail)
    if not reply_top or not from_top or reply_top == from_top:
        return None
    return Finding(
        rule="回复地址与发件人不一致",
        severity=Severity.MEDIUM,
        summary=f"回信会被发往 {reply_top}，而发件方是 {from_top}",
        evidence=f"Reply-To: {unfold(mail.reply_to)}；发件域: {from_top}",
        detail=(
            "正常邮件让回复地址和发件地址落在同一家机构的域下。"
            "回复地址指向另一个域时，受害者的回信会寄给与发件人无关的一方，"
            "这是钓鱼邮件常见的引流手段。邮件列表等正常服务也会这样，所以只算「中」。"
        ),
    )


# ---------------------------------------------------------------- 规则 2
def _check_return_path_mismatch(mail: ParsedEmail) -> Finding | None:
    """信封发件人与发件人不一致（中）"""
    if not mail.return_path:
        return None
    path_top = _top_of_header_address(mail.return_path)
    from_top = _from_top(mail)
    if not path_top or not from_top or path_top == from_top:
        return None
    return Finding(
        rule="信封发件人与发件人不一致",
        severity=Severity.MEDIUM,
        summary=f"退信会寄往 {path_top}，与发件域 {from_top} 不一致",
        evidence=f"Return-Path: {unfold(mail.return_path)}；发件域: {from_top}",
        detail=(
            "Return-Path 是信封发件地址，由收件方服务器收信时写入，正常应与 From 同属一家。"
            "两者不一致说明发件方在 SMTP 信封和邮件头部声称了不同身份——伪造发件人时常见。"
            "代发服务（新闻邮件、工单系统）也会这样，所以只算「中」。"
        ),
    )


# ---------------------------------------------------------------- 规则 3
def _check_display_name_is_address(mail: ParsedEmail) -> Finding | None:
    """显示名伪装为邮箱地址（高）"""
    display = mail.from_display.strip()
    if "@" not in display:
        return None
    _, claimed = split_address(unfold(display))
    if not claimed or "@" not in claimed:
        return None
    if claimed.lower() == mail.from_addr.strip().lower():
        return None
    return Finding(
        rule="显示名伪装为邮箱地址",
        severity=Severity.HIGH,
        summary=f"显示名本身是个邮箱地址「{display}」，真实发件地址却是 {mail.from_addr}",
        evidence=f"显示名: {display}；真实地址: {mail.from_addr}",
        detail=(
            "很多邮件客户端只把显示名展示给用户，不展开真实地址。"
            "把显示名写成另一个邮箱地址，收件人会以为发件人就是那个地址。"
        ),
    )


# ---------------------------------------------------------------- 规则 4
def _check_display_name_brand(mail: ParsedEmail) -> Finding | None:
    """显示名仿冒品牌（高）"""
    matched = _brand_matched_by_display(mail.from_display)
    if matched is None:
        return None
    brand, alias = matched
    _aliases, brand_domains = knowledge.brands()[brand]
    from_top = _from_top(mail)

    # 发件域确实属于这个品牌 → 正常，不报
    if from_top and from_top in brand_domains:
        return None

    return Finding(
        rule="显示名仿冒品牌",
        severity=Severity.HIGH,
        summary=f"显示名冒充 {brand}，但发件域 {from_top or '(缺失)'} 不属于它",
        evidence=(
            f"显示名: {mail.from_display}（命中别名「{alias}」）；"
            f"发件域: {from_top or '(缺失)'}；{brand} 的合法域: {', '.join(sorted(brand_domains))}"
        ),
        detail=(
            "显示名声称是某品牌，发件域名却不是该品牌的任何域名，是典型的品牌冒充。"
            "注意：即使发件域是 @outlook.com 这类该品牌自家的免费邮箱也照样可疑——"
            "因为任何人都能注册一个这样的邮箱。"
        ),
    )


# ---------------------------------------------------------------- 规则 5
def _check_homoglyph_domain(mail: ParsedEmail) -> Finding | None:
    """域名同形异义字（高）"""
    domain = mail.from_domain
    if not domain:
        return None

    readable = _decode_idn(domain)
    table = knowledge.script_confusables()

    for label in readable.split("."):
        reason = _homoglyph_reason(label, table)
        if reason is None:
            continue
        return Finding(
            rule="域名同形异义字",
            severity=Severity.HIGH,
            summary=f"发件域 {readable} 含同形异义字符：{reason}",
            evidence=f"发件域原文: {domain}；可读形式: {readable}；{reason}",
            detail=(
                "攻击者用其他文字系统里长得像拉丁字母的字符伪造域名，"
                "在地址栏里与真域名肉眼难分，但它们是不同的域名，"
                "证书、SPF、DMARC 全都对不上。"
            ),
        )
    return None


# ---------------------------------------------------------------- 规则 6
def _check_punycode_domain(mail: ParsedEmail) -> Finding | None:
    """域名使用 Punycode（中）

    为什么是「中」而不是「高」：xn-- 只说明这是个国际化域名，
    .中国 / .公司 也是 xn--，单独看不构成恶意证据。
    真正的恶意信号是"解码后发现是伪装的拉丁品牌"，那个由规则 5 报「高」。
    """
    domain = mail.from_domain
    if "xn--" not in domain:
        return None
    readable = _decode_idn(domain)
    return Finding(
        rule="域名使用 Punycode",
        severity=Severity.MEDIUM,
        summary=f"发件域用了 Punycode 编码，解码后是 {readable}",
        evidence=f"发件域原文: {domain}；解码后: {readable}",
        detail=(
            "Punycode（xn-- 开头）用来表示非英文字符的域名，本身是合法技术，"
            "中文、日文、俄文域名都用它。但它也常被用来藏同形异义域名——"
            "所以这里只提示「中」，解码后的样子给人看一眼，是否伪装由「域名同形异义字」判定。"
        ),
    )


# ---------------------------------------------------------------- 规则 7
def _check_message_id_mismatch(mail: ParsedEmail) -> Finding | None:
    """邮件 ID 域名与发件域不符（低）"""
    message_id = mail.message_id.strip()
    if "@" not in message_id:
        return None

    host = message_id.rpartition("@")[2].rstrip(">").strip().strip('"')
    # 关键：主机部分必须含 "." 才当成域名。
    # JavaMail 等发信程序常用本机名生成 Message-ID（实测：WIN-7NMETV5JCU5），
    # 那是完全合规的行为，按"域名"去比会误报合法邮件。
    if "." not in host:
        return None

    message_top = top_domain(host)
    from_top = _from_top(mail)
    if not message_top or not from_top or message_top == from_top:
        return None
    return Finding(
        rule="邮件 ID 域名与发件域不符",
        severity=Severity.LOW,
        summary=f"Message-ID 的域是 {message_top}，与发件域 {from_top} 不一致",
        evidence=f"Message-ID: {message_id}；Message-ID 域: {message_top}；发件域: {from_top}",
        detail=(
            "Message-ID 通常由发件方自己的邮件服务器生成，所以域名一般与发件域一致。"
            "不一致说明这封信是经由第三方基础设施代发的。代发很常见，所以只算「低」。"
        ),
    )


# ---------------------------------------------------------------- 规则 8
def _check_missing_id_or_date(mail: ParsedEmail) -> Finding | None:
    """缺少邮件 ID 或日期（低）"""
    missing = []
    if not mail.message_id.strip():
        missing.append("Message-ID")
    if not mail.date.strip():
        missing.append("Date")
    if not missing:
        return None
    return Finding(
        rule="缺少邮件 ID 或日期",
        severity=Severity.LOW,
        summary=f"缺少 {' 和 '.join(missing)} 头部",
        evidence=f"缺失的头部: {', '.join(missing)}",
        detail=(
            "正常的邮件客户端和服务器都会写这两个头部。"
            "缺失常见于脚本直接群发、或发信程序配置不全——不是恶意的证据，只是可疑。"
        ),
    )


# ---------------------------------------------------------------- 规则 9
def _check_free_mail_claiming_brand(mail: ParsedEmail) -> Finding | None:
    """使用免费邮箱却声称企业身份（低）

    "声称企业身份"这个模糊说法这里收敛成可测的判据：显示名命中了品牌表。
    """
    from_top = _from_top(mail)
    if not from_top or from_top not in knowledge.free_mail_domains():
        return None

    matched = _brand_matched_by_display(mail.from_display)
    if matched is None:
        return None
    brand, alias = matched
    return Finding(
        rule="使用免费邮箱却声称企业身份",
        severity=Severity.LOW,
        summary=f"发件域是免费邮箱 {from_top}，显示名却自称 {brand}",
        evidence=f"发件域: {from_top}；显示名: {mail.from_display}（命中别名「{alias}」）",
        detail=(
            "免费邮箱本身完全正常，大量真实用户都在用。"
            "但正规企业不会用免费邮箱发业务邮件——域名不属于自己、无法配置 SPF/DKIM、也无法追责。"
            "所以「自称是某机构」加上「用的是免费邮箱」合起来才可疑。"
        ),
    )


# ---------------------------------------------------------------- 规则 10
def _check_multiple_from(mail: ParsedEmail) -> Finding | None:
    """存在多个发件人字段（低）"""
    values = mail.header("From")
    if len(values) <= 1:
        return None
    return Finding(
        rule="存在多个发件人字段",
        severity=Severity.LOW,
        summary=f"这封邮件里有 {len(values)} 个 From 头",
        evidence=" | ".join(values),
        detail=(
            "正常邮件只有一个 From。出现多个时，不同的邮件客户端可能显示出不同的发件人——"
            "攻击者借此让一个客户端显示可信的发件人、另一个显示真实的。"
        ),
    )


# ---------------------------------------------------------------- 规则 11
def _check_no_received_chain(mail: ParsedEmail) -> Finding | None:
    """投递链缺失（低）

    范围裁剪：这里只判"完全没有 Received"。"跳数与声称来源矛盾"那一条需要
    完整解析投递链，与第 3 周的认证规则重叠，放到后面再做。
    """
    if mail.header("Received"):
        return None
    return Finding(
        rule="投递链缺失",
        severity=Severity.LOW,
        summary="这封邮件没有任何 Received 头",
        evidence="Received 头数量: 0",
        detail=(
            "每经过一台邮件服务器都会加一条 Received。完全没有说明这封信不是正常投递来的——"
            "可能是本地生成的样本，也可能是直接塞进邮箱的。"
        ),
    )


# ---------------------------------------------------------------- 规则 12
def _check_subject_lure_words(mail: ParsedEmail) -> Finding | None:
    """主题含诱导性话术（低 / 中）"""
    # ★ 必须先 unfold：长主题会折行，TAB 会把诱导短语从中间劈开，
    # 实测 "Please verify your\\taccount" 直接匹配会漏掉。
    subject = unfold(mail.subject)
    if not subject:
        return None

    lowered = subject.lower()
    hits: list[tuple[str, str]] = []
    for category, phrases in knowledge.lure_words().items():
        for phrase in phrases:
            if phrase and phrase.lower() in lowered:
                hits.append((category, phrase))
    if not hits:
        return None

    # 级别随命中数提升。类别→级别的映射留给第 6 周的正文规则，
    # 因为主题里出现"点击此处"在正常的营销邮件里也很常见。
    severity = Severity.MEDIUM if len(hits) >= 2 else Severity.LOW
    evidence = "；".join(f"「{phrase}」（{category}）" for category, phrase in sorted(hits))
    return Finding(
        rule="主题含诱导性话术",
        severity=severity,
        summary=f"主题命中 {len(hits)} 条诱导话术",
        evidence=f"主题: {subject}；命中: {evidence}",
        detail=(
            "主题里出现催促、威胁或索要凭据的说法，是钓鱼邮件最直观的特征。"
            "命中数量越多越可疑，但正经的通知类邮件也会有一两条，所以最高只到「中」。"
        ),
    )


# ---------------------------------------------------------------- 规则 13
def _check_brand_in_from_domain(mail: ParsedEmail) -> Finding | None:
    """发件域名仿冒品牌（高）

    为什么需要这条：规则 4 依赖显示名，而真实邮件经常**没有显示名**
    （实测那封政府通知邮件就是裸地址）。From: a@micros0ft-support.com
    这种情况规则 4 永远抓不到。
    """
    from_top = _from_top(mail)
    if not from_top:
        return None

    # 归一化：同形字 + 数字 → 拉丁字符，把 micros0ft 还原成 microsoft
    table = knowledge.domain_lookalikes()
    lowered = from_top.lower()
    normalized = "".join(table.get(char, char) for char in lowered)

    # 两种形式都要检查：
    #   原文   —— microsoft365 这种「品牌名 + 数字」，按原文才认得出
    #   归一化 —— micros0ft 这种「数字冒充字母」，归一化后才变回 microsoft
    # 只做归一化会把 365 里的 3 和 5 也替换掉，反而认不出 microsoft365。
    segments = sorted(
        {
            segment
            for form in (lowered, normalized)
            for segment in re.split(r"[-.]", form)
            if segment
        }
    )

    for brand, (_aliases, brand_domains) in knowledge.brands().items():
        name = brand.lower()
        if not name or not name.isascii():
            continue  # 中文品牌名不可能出现在 ASCII 域名里
        if from_top in brand_domains:
            continue  # 这个域本来就属于该品牌

        for segment in segments:
            if segment == name:
                return _brand_domain_finding(mail, brand, normalized, from_top, segment)
            # microsoft365 这种「品牌名 + 数字」，但排除 pineapple / applepie 这类
            tail = segment[len(name):]
            if segment.startswith(name) and tail[:1].isdigit():
                return _brand_domain_finding(mail, brand, normalized, from_top, segment)
    return None


def _brand_domain_finding(
    mail: ParsedEmail, brand: str, normalized: str, from_top: str, segment: str
) -> Finding:
    return Finding(
        rule="发件域名仿冒品牌",
        severity=Severity.HIGH,
        summary=f"发件域 {from_top} 归一化后是 {normalized}，含品牌名 {brand}",
        evidence=f"发件域: {from_top}；归一化: {normalized}；命中片段: {segment}",
        detail=(
            "域名里塞品牌名、但注册域又不属于该品牌，靠的是收件人扫一眼就信。"
            "有时还会把字母换成形近的数字（0 冒充 o、1 冒充 l）来绕过简单比对，"
            "所以这里先把数字和同形字归一化再比。"
        ),
    )


# ---------------------------------------------------------------- 汇总
# 顺序即输出的稳定顺序。新增规则在这里加一行，同时要在 rules.py 注册。
_CHECKS = (
    _check_reply_to_mismatch,
    _check_return_path_mismatch,
    _check_display_name_is_address,
    _check_display_name_brand,
    _check_homoglyph_domain,
    _check_punycode_domain,
    _check_message_id_mismatch,
    _check_missing_id_or_date,
    _check_free_mail_claiming_brand,
    _check_multiple_from,
    _check_no_received_chain,
    _check_subject_lure_words,
    _check_brand_in_from_domain,
)


def analyze_headers(mail: ParsedEmail) -> list[Finding]:
    """跑全部头部规则，返回命中的 Finding（没命中的不返回）。"""
    findings: list[Finding] = []
    for check in _CHECKS:
        finding = check(mail)
        if finding is not None:
            findings.append(finding)
    return findings
