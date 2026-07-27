#!/usr/bin/env python3
"""把「单测」与「三机 e2e」两份覆盖剖面合成一张账。

用法:
    scripts/coverage/merge-coverage.py <单测剖面> <e2e剖面> [空白清单输出路径]

两边的 covermode 不同(单测通常 set,e2e 插桩二进制用 atomic),计数值没有可比性,
所以一律只看「这个语句块有没有被执行过」。输出四类归属:

    两边   两边都覆盖
    仅单测 只有进程内单测覆盖
    仅e2e  只有三机真实流量覆盖 —— 这是 e2e 不可替代的那部分
    都没有 两边都没碰过 —— 只有这类才是真正的空白

注意:两份剖面必须来自**同一份源码**。任何一侧采集后又改动了文件(哪怕只是插入
一个函数导致行号位移),该文件的语句块 key 就对不上,合并结果会把它整片算成
「仅单侧覆盖」。改完代码要重新采集两边,别拿旧剖面凑。
"""

import collections
import sys


def load(path):
    """读一份 go cover 文本剖面,返回 {(文件, 行段): (语句数, 是否覆盖)}。"""
    out = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("mode:"):
                continue
            loc, nstmt, count = line.rsplit(" ", 2)
            fname, span = loc.split(":", 1)
            key = (fname, span)
            n, covered = int(nstmt), int(count) > 0
            if key in out:  # 同一剖面里重复出现(多次运行合并)取或
                n0, c0 = out[key]
                out[key] = (n0, c0 or covered)
            else:
                out[key] = (n, covered)
    return out


def pkg_of(fname):
    f = fname.replace("github.com/nanotun/server/", "")
    return "/".join(f.split("/")[:-1]) or "."


def main(unit_path, e2e_path, gaps_path="coverage-gaps.txt"):
    unit, e2e = load(unit_path), load(e2e_path)

    stat = collections.defaultdict(collections.Counter)
    gaps = collections.defaultdict(list)
    for key in set(unit) | set(e2e):
        fname, span = key
        n_u, cov_u = unit.get(key, (0, False))
        n_e, cov_e = e2e.get(key, (0, False))
        n = max(n_u, n_e)
        p = pkg_of(fname)
        stat[p]["total"] += n
        if cov_u and cov_e:
            stat[p]["both"] += n
        elif cov_u:
            stat[p]["unit"] += n
        elif cov_e:
            stat[p]["e2e"] += n
        else:
            stat[p]["none"] += n
            gaps[fname].append((span, n))

    hdr = f"{'包':<20}{'总计':>7}{'两边':>7}{'仅单测':>8}{'仅e2e':>7}{'都没有':>8}{'合并覆盖':>10}"
    print(hdr)
    print("-" * len(hdr))
    tot = collections.Counter()
    for p in sorted(stat, key=lambda p: stat[p]["none"], reverse=True):
        s = stat[p]
        tot.update(s)
        cov = s["both"] + s["unit"] + s["e2e"]
        print(f"{p:<20}{s['total']:>7}{s['both']:>7}{s['unit']:>8}{s['e2e']:>7}"
              f"{s['none']:>8}{100 * cov / s['total']:>9.1f}%")
    cov = tot["both"] + tot["unit"] + tot["e2e"]
    print("-" * len(hdr))
    print(f"{'合计':<20}{tot['total']:>7}{tot['both']:>7}{tot['unit']:>8}{tot['e2e']:>7}"
          f"{tot['none']:>8}{100 * cov / tot['total']:>9.1f}%")

    ranked = sorted(gaps.items(), key=lambda kv: sum(n for _, n in kv[1]), reverse=True)
    print("\n两边都没碰过的语句,按文件排序(前 20):")
    for fname, blocks in ranked[:20]:
        short = fname.replace("github.com/nanotun/server/", "")
        print(f"  {sum(n for _, n in blocks):>5} 条  {short}")

    with open(gaps_path, "w") as fh:
        for fname, blocks in ranked:
            short = fname.replace("github.com/nanotun/server/", "")
            for span, n in sorted(blocks, key=lambda b: int(b[0].split(".")[0])):
                fh.write(f"{short}:{span} {n}\n")
    print(f"\n完整空白清单(精确到语句块)已写到 {gaps_path}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    main(*sys.argv[1:4])
