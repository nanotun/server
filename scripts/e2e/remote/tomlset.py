#!/usr/bin/env python3
"""把一个 key 设进 TOML 的指定 section:已存在就改值,不存在就插在段首。

用法:tomlset.py <path> <section> <key> <value>
      tomlset.py /etc/nanotun/config.toml tun forward_block_bt true

为什么不用 sed:这里要改的是「段内的某个 key」,而 sed 只会按行匹配 ——
key 名在别的段里同名(或出现在注释里)就会改错地方。更要紧的是**重复 key 会让整个
TOML 解析失败**,而那时 nanotund 走的是「保留旧配置」分支:断言会红,但红的原因跟
它要测的东西毫无关系,排查方向从一开始就错了。所以这里做两件 sed 做不到的事:
  - 只在目标段的范围内找 key(段的范围 = 从段头到下一个 `[` 开头的行);
  - 改完自己用 tomllib 解析一遍,坏了就非零退出并把错误打出来。

只处理这套 e2e 需要的形状(顶层段 + 简单标量/数组字面量),不是通用 TOML 编辑器。
"""

import sys

try:
    import tomllib  # 3.11+
except ImportError:  # 老 python 上没有,只能跳过自证 —— 但要说出来,别让人以为验过了
    tomllib = None


def main() -> int:
    if len(sys.argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    path, section, key, val = sys.argv[1:5]

    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().split("\n")

    header = "[%s]" % section
    start = None
    for i, ln in enumerate(lines):
        if ln.strip() == header:
            start = i
            break
    if start is None:
        print("找不到段 %s" % header, file=sys.stderr)
        return 1

    # 段的结束 = 下一个以 [ 开头的行(即下一个段头,含 [section.sub])。
    end = len(lines)
    for i in range(start + 1, len(lines)):
        if lines[i].lstrip().startswith("["):
            end = i
            break

    newline = "%s = %s" % (key, val)
    replaced = False
    for i in range(start + 1, end):
        stripped = lines[i].lstrip()
        if stripped.startswith("#"):
            continue  # 注释掉的同名 key 不算存在,否则会把注释改成生效的配置
        name = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if name == key:
            lines[i] = newline
            replaced = True
            break
    if not replaced:
        lines.insert(start + 1, newline)

    out = "\n".join(lines)

    # 落盘前先自证:坏 TOML 会让 nanotund 走「保留旧配置」,断言就测不到本来要测的东西。
    note = ""
    if tomllib is None:
        note = "(未校验:该 python 无 tomllib)"
    else:
        try:
            tomllib.loads(out)
        except Exception as exc:  # noqa: BLE001 —— 任何解析失败都要原样报出来
            print("改完之后 TOML 解析不过,未写入:%s" % exc, file=sys.stderr)
            return 1

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)
    print("%s [%s] %s = %s %s" % ("改" if replaced else "插", section, key, val, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
