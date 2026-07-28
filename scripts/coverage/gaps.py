#!/usr/bin/env python3
"""从 go coverprofile 里按文件/按块列出未覆盖语句。

用法:
  gaps.py PROFILE                 # 按文件汇总,降序
  gaps.py PROFILE 文件名片段       # 列出该文件里每个未覆盖块的行号区间
"""
import collections
import sys


def load(path):
    """→ {file: [(start_line, end_line, nstmt, count)]}"""
    blocks = collections.defaultdict(list)
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("mode:"):
                continue
            pos, nstmt, count = line.rsplit(" ", 2)
            fname, span = pos.rsplit(":", 1)
            start, end = span.split(",")
            blocks[fname].append(
                (int(start.split(".")[0]), int(end.split(".")[0]), int(nstmt), int(count))
            )
    return blocks


def main():
    blocks = load(sys.argv[1])
    if len(sys.argv) > 2:
        needle = sys.argv[2]
        for fname, bs in sorted(blocks.items()):
            if needle not in fname:
                continue
            miss = sorted(b for b in bs if b[3] == 0)
            print(f"{fname}  未覆盖 {sum(b[2] for b in miss)} 条 / 共 {sum(b[2] for b in bs)} 条")
            for start, end, nstmt, _ in miss:
                print(f"  L{start}-{end}  {nstmt} 条")
        return

    rows = []
    for fname, bs in blocks.items():
        miss = sum(b[2] for b in bs if b[3] == 0)
        if miss:
            rows.append((miss, sum(b[2] for b in bs), fname))
    rows.sort(reverse=True)
    total_miss = sum(r[0] for r in rows)
    total_all = sum(sum(b[2] for b in bs) for bs in blocks.values())
    for miss, all_, fname in rows:
        print(f"{miss:5d} / {all_:5d}  {fname}")
    print(f"\n合计未覆盖 {total_miss} / {total_all} 条,覆盖 {100.0 * (total_all - total_miss) / total_all:.1f}%")


if __name__ == "__main__":
    main()
