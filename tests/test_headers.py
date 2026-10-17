"""13 条头部规则的测试。

每条规则至少一个正例 + 一个反例。**反例比正例重要**——
一个只会喊"可疑"的工具没人用，误报率决定这个项目有没有价值。

测试直接用 `email_factory` 造 ParsedEmail，不经过解析层：
这样一条规则的正反例只写它关心的字段，测的是规则本身，不是解析。
"""

from __future__ import annotations

from phishscope.analyzer import analyze
from phishscope.analyzers.headers import analyze_headers
from phishscope.models import Severity


def rules_of(mail) -> set[str]:
    """这封邮件命中了哪些规则（只关心名字）。"""
    return {finding.rule for finding in analyze_headers(mail)}


def finding_of(mail, rule: str):
    """取某条规则的 Finding；没命中就 AssertionError，顺便把实际命中的都打出来。"""
    findings = analyze_headers(mail)
    for finding in findings:
        if finding.rule == rule:
            return finding
    raise AssertionError(f"没命中「{rule}」；实际命中: {sorted(f.rule for f in findings)}")


# ──────────────────────────────────────── 1 回复地址与发件人不一致
def test_reply_to_mismatch_fires(email_factory):
    mail = email_factory(from_addr="svc@bank.com", reply_to="harvest@evil-collect.top")
    assert "回复地址与发件人不一致" in rules_of(mail)


def test_reply_to_same_registered_domain_does_not_fire(email_factory):
    """mail.bank.com 和 bank.com 是同一家 —— 不能报。"""
    mail = email_factory(from_addr="svc@mail.bank.com", reply_to="help@bank.com")
    assert "回复地址与发件人不一致" not in rules_of(mail)


def test_reply_to_absent_does_not_fire(email_factory):
    assert "回复地址与发件人不一致" not in rules_of(email_factory(from_addr="a@bank.com"))


# ──────────────────────────────────────── 2 信封发件人与发件人不一致
def test_return_path_mismatch_fires(email_factory):
    mail = email_factory(from_addr="svc@bank.com", return_path="<bounce@relay.xyz>")
    assert "信封发件人与发件人不一致" in rules_of(mail)


def test_return_path_same_domain_does_not_fire(email_factory):
    mail = email_factory(from_addr="svc@bank.com", return_path="<bounce@bank.com>")
    assert "信封发件人与发件人不一致" not in rules_of(mail)


# ──────────────────────────────────────── 3 显示名伪装为邮箱地址
def test_display_name_as_address_fires(email_factory):
    mail = email_factory(from_display="security@paypal.com", from_addr="steal@evil.top")
    assert "显示名伪装为邮箱地址" in rules_of(mail)


def test_normal_display_name_does_not_fire(email_factory):
    mail = email_factory(from_display="微软账户团队", from_addr="a@evil.top")
    assert "显示名伪装为邮箱地址" not in rules_of(mail)


def test_display_name_equal_to_real_address_does_not_fire(email_factory):
    mail = email_factory(from_display="a@bank.com", from_addr="a@bank.com")
    assert "显示名伪装为邮箱地址" not in rules_of(mail)


# ──────────────────────────────────────── 4 显示名仿冒品牌
def test_display_name_brand_fires(email_factory):
    mail = email_factory(from_display="Microsoft 账户团队", from_addr="a@micros0ft-support.com")
    finding = finding_of(mail, "显示名仿冒品牌")
    assert finding.severity is Severity.HIGH


def test_display_name_brand_from_real_domain_does_not_fire(email_factory):
    mail = email_factory(from_display="Microsoft 账户团队", from_addr="a@microsoft.com")
    assert "显示名仿冒品牌" not in rules_of(mail)


def test_empty_display_name_does_not_fire(email_factory):
    """真实邮件经常根本没有显示名——不能因此报什么。"""
    mail = email_factory(from_display="", from_addr="a@evil.top")
    assert "显示名仿冒品牌" not in rules_of(mail)


# ──────────────────────────────────────── 5 域名同形异义字
def test_whole_label_homoglyph_fires(email_factory):
    """аррӏе.com —— 整个标签全是西里尔字母，没有任何拉丁字符。

    只判"混用文字系统"会漏掉这种最经典的整词同形攻击。
    """
    mail = email_factory(from_addr="a@xn--80ak6aa92e.com")
    assert "域名同形异义字" in rules_of(mail)


def test_mixed_script_homoglyph_fires(email_factory):
    """раypal.com —— 西里尔 р / а 混着拉丁 ypal。"""
    mail = email_factory(from_addr="a@\u0440\u0430ypal.com")
    assert "域名同形异义字" in rules_of(mail)


def test_legitimate_cyrillic_domain_does_not_fire(email_factory):
    """яндекс.рф 是合法的俄文域名，不是伪装。"""
    mail = email_factory(from_addr="a@яндекс.рф")
    assert "域名同形异义字" not in rules_of(mail)


def test_ascii_domain_does_not_fire(email_factory):
    assert "域名同形异义字" not in rules_of(email_factory(from_addr="a@microsoft.com"))


# ──────────────────────────────────────── 6 域名使用 Punycode
def test_punycode_domain_fires(email_factory):
    finding = finding_of(email_factory(from_addr="a@xn--fiqs8s.cn"), "域名使用 Punycode")
    assert finding.severity is Severity.MEDIUM
    assert "中国.cn" in finding.evidence


def test_ascii_domain_does_not_trigger_punycode(email_factory):
    assert "域名使用 Punycode" not in rules_of(email_factory(from_addr="a@example.com"))


# ──────────────────────────────────────── 7 邮件 ID 域名与发件域不符
def test_message_id_mismatch_fires(email_factory):
    mail = email_factory(from_addr="a@paypal.com", message_id="<x@mail.ru>")
    assert "邮件 ID 域名与发件域不符" in rules_of(mail)


def test_bare_hostname_message_id_does_not_fire(email_factory):
    """JavaMail 用本机名生成 Message-ID，没有点——那是主机名，不是域名。"""
    mail = email_factory(from_addr="a@paypal.com", message_id="<x@WIN-7NMETV5JCU5>")
    assert "邮件 ID 域名与发件域不符" not in rules_of(mail)


def test_matching_message_id_does_not_fire(email_factory):
    mail = email_factory(from_addr="a@paypal.com", message_id="<x@paypal.com>")
    assert "邮件 ID 域名与发件域不符" not in rules_of(mail)


# ──────────────────────────────────────── 8 缺少邮件 ID 或日期
def test_missing_message_id_fires(email_factory):
    mail = email_factory(message_id="", headers={"Date": ["Mon, 1 Jan 2026 00:00:00 +0800"]})
    finding = finding_of(mail, "缺少邮件 ID 或日期")
    assert "Message-ID" in finding.evidence


def test_missing_date_fires(email_factory):
    mail = email_factory(date="", headers={"Message-ID": ["<1@a.com>"]})
    assert "缺少邮件 ID 或日期" in rules_of(mail)


def test_both_present_does_not_fire(email_factory):
    assert "缺少邮件 ID 或日期" not in rules_of(email_factory())


# ──────────────────────────────────────── 9 使用免费邮箱却声称企业身份
def test_free_mail_with_brand_fires(email_factory):
    mail = email_factory(from_addr="someone@outlook.com", from_display="Microsoft 账户团队")
    assert "使用免费邮箱却声称企业身份" in rules_of(mail)


def test_free_mail_without_brand_does_not_fire(email_factory):
    """免费邮箱 + 正常显示名 → 完全正常。"""
    mail = email_factory(from_addr="someone@outlook.com", from_display="张三")
    assert "使用免费邮箱却声称企业身份" not in rules_of(mail)


def test_brand_domain_is_not_free_mail(email_factory):
    mail = email_factory(from_addr="a@microsoft.com", from_display="Microsoft 账户团队")
    assert "使用免费邮箱却声称企业身份" not in rules_of(mail)


# ──────────────────────────────────────── 10 存在多个发件人字段
def test_multiple_from_fires(email_factory):
    mail = email_factory(headers={"From": ["a@x.com"], "FROM": ["b@y.com"]})
    finding = finding_of(mail, "存在多个发件人字段")
    assert "2" in finding.summary


def test_single_from_does_not_fire(email_factory):
    assert "存在多个发件人字段" not in rules_of(email_factory(headers={"From": ["a@x.com"]}))


# ──────────────────────────────────────── 11 投递链缺失
def test_no_received_fires(email_factory):
    assert "投递链缺失" in rules_of(email_factory(headers={"From": ["a@x.com"]}))


def test_received_present_does_not_fire(email_factory):
    mail = email_factory(headers={"Received": ["from a by b; Mon, 1 Jan 2026 00:00:00 +0800"]})
    assert "投递链缺失" not in rules_of(mail)


# ──────────────────────────────────────── 12 主题含诱导性话术
def test_two_lure_phrases_give_medium(email_factory):
    finding = finding_of(email_factory(subject="【立即验证】账户将被停用"), "主题含诱导性话术")
    assert finding.severity is Severity.MEDIUM


def test_one_lure_phrase_gives_low(email_factory):
    finding = finding_of(email_factory(subject="请立即验证"), "主题含诱导性话术")
    assert finding.severity is Severity.LOW


def test_folded_subject_still_matches(email_factory):
    """★ 主题被折行时，TAB 会把短语劈开——必须先 unfold 才能匹配上。"""
    finding = finding_of(
        email_factory(subject="Please verify your\taccount immediately"), "主题含诱导性话术"
    )
    assert "verify your account" in finding.evidence


def test_plain_subject_does_not_fire(email_factory):
    assert "主题含诱导性话术" not in rules_of(email_factory(subject="季度报表"))


# ──────────────────────────────────────── 13 发件域名仿冒品牌
def test_brand_in_from_domain_fires_without_display_name(email_factory):
    """没有显示名时，只有这条规则抓得到。"""
    mail = email_factory(from_display="", from_addr="a@micros0ft-support.com")
    assert "发件域名仿冒品牌" in rules_of(mail)
    assert "显示名仿冒品牌" not in rules_of(mail)


def test_brand_as_substring_of_a_word_does_not_fire(email_factory):
    """pineapple.com 里含 apple，但它不是品牌冒充。"""
    assert "发件域名仿冒品牌" not in rules_of(email_factory(from_addr="a@pineapple.com"))


def test_brand_digit_variant_fires(email_factory):
    """microsoft365.com 这种「品牌名 + 数字」要报。"""
    assert "发件域名仿冒品牌" in rules_of(email_factory(from_addr="a@microsoft365-support.top"))


def test_real_brand_domain_does_not_fire(email_factory):
    assert "发件域名仿冒品牌" not in rules_of(email_factory(from_addr="a@microsoft.com"))


# ──────────────────────────────────────── 真实邮件回归（最重要的一条）
def test_real_world_government_email_has_no_findings(email_factory):
    """把真实政府机关邮件的 6 个坑合成成一份样本，断言零可疑点。

    原始邮件在 _private-notes/ 里（含真实邮箱，不能进仓库），这里把它踩过的坑
    全部复现：没有显示名、发件域是子域、Message-ID 主机没有点、没有 Reply-To
    和 Return-Path、有 Received、主题不含诱导词。

    **这一条守住的误报，比 13 条规则的正例加起来都值钱。**
    """
    mail = email_factory(
        from_display="",
        from_addr="notice@mail.example.gov.cn",
        reply_to="",
        return_path="",
        subject="报名通知- 考试院用户注册成功",
        message_id='<2112758455.311153.JavaMail."LOCAL SERVICE"@WIN-7NMETV5JCU5>',
        headers={
            "Received": [
                "from mail.example.gov.cn by mx.example.com; Mon, 1 Jan 2026 00:00:00 +0800",
                "from WIN-7NMETV5JCU5 by mail.example.gov.cn; Mon, 1 Jan 2026 00:00:00 +0800",
            ],
            "From": ["notice@mail.example.gov.cn"],
        },
    )
    assert analyze_headers(mail) == []


# ──────────────────────────────────────── 编排层
def test_analyze_sorts_by_severity(email_factory):
    """级别高的必须排在前面，同一封邮件两次运行顺序一致。"""
    mail = email_factory(
        from_display="Microsoft 账户团队",
        from_addr="a@micros0ft-support.com",
        reply_to="harvest@evil-collect.top",
        subject="【立即验证】账户将被停用",
    )
    findings = analyze(mail)
    ranks = {"严重": 0, "高": 1, "中": 2, "低": 3, "提示": 4}
    values = [ranks[finding.severity.value] for finding in findings]
    assert values == sorted(values), f"排序不对: {values}"


def test_analyze_is_deterministic(email_factory):
    mail = email_factory(from_addr="a@micros0ft-support.com", reply_to="harvest@evil.top")
    assert [f.rule for f in analyze(mail)] == [f.rule for f in analyze(mail)]
