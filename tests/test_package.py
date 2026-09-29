"""冒烟测试：确认包结构、打包配置与测试工具链本身是通的。

后续会补充真正的单元测试。
"""

import re

import phishscope


def test_package_importable() -> None:
    """包能被导入，且模块文档字符串存在（说明不是空包）。"""
    assert phishscope.__doc__ is not None
    assert phishscope.__doc__.strip() != ""


def test_version_looks_like_semver() -> None:
    """版本号是 X.Y.Z 形式 —— 打包与发布脚本都依赖这个约定。"""
    assert re.fullmatch(r"\d+\.\d+\.\d+", phishscope.__version__), phishscope.__version__
