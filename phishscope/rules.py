"""规则注册表：规则中文名 → 分析类别。

为什么需要这张表：

1. `Finding.rule` 是自由字符串，写到哪算哪，拼错不会报错。但第 6 周的
   `weights.yaml` 要按规则名查权重——拼错的规则权重会**静默**变成 0 分，
   报告上看不出任何异常。所以 `Finding` 构造时会来这里核对，拼错直接炸。
2. 第 7 周的报告要按「头部 / 认证 / 链接 / 附件 / 正文」分组。分类放在这里，
   不用往 `Finding` 上加字段（Finding 每加一个字段，三种报告都要跟着改）。

新增一条规则 = 在这里加一行。忘了加，构造 Finding 时立刻抛错。
"""

from enum import Enum


class Category(Enum):
    """规则所属的分析类别。值是给人看的中文名。"""

    HEADER = "头部"
    AUTH = "认证"
    URL = "链接"
    ATTACHMENT = "附件"
    BODY = "正文"


# 规则中文名 → 分类。
# 规则名一旦定了就是唯一标识（测试、权重表、报告都靠它），改名等于改标识。
RULES: dict[str, Category] = {
    # ---- 头部欺诈（第 2 周）----
    "回复地址与发件人不一致": Category.HEADER,
    "信封发件人与发件人不一致": Category.HEADER,
    "显示名伪装为邮箱地址": Category.HEADER,
    "显示名仿冒品牌": Category.HEADER,
    "域名同形异义字": Category.HEADER,
    "域名使用 Punycode": Category.HEADER,
    "邮件 ID 域名与发件域不符": Category.HEADER,
    "缺少邮件 ID 或日期": Category.HEADER,
    "使用免费邮箱却声称企业身份": Category.HEADER,
    "存在多个发件人字段": Category.HEADER,
    "投递链缺失": Category.HEADER,
    "主题含诱导性话术": Category.HEADER,
    "发件域名仿冒品牌": Category.HEADER,
}
