#!/usr/bin/env python3
"""变异验证:把生产代码定点改坏,确认测试真的会红。

变异清单写在一个 JSON 文件里,每项:
  {"desc": "...", "file": "store/web_admins.go", "old": "...", "new": "...",
   "nth": 0, "test": "./store/", "run": "TestFoo|TestBar"}

"run" 可选,把该条变异的验证收窄到相关用例(整包跑三十条变异要一小时)。填写时宁宽勿窄。

nth 是当 old 在文件里出现多次时选第几个(默认 0)。逃逸(测试照过)的项会被单独列出——
那说明这段逻辑虽然被执行过,但没有任何断言真正检查它的结果。

用法: mutate.py MUTATIONS.json [--test-timeout 300s]
"""
import json
import subprocess
import sys


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# 变异一律以「开跑那一刻的原始内容」为基准施加,还原也还原成它 —— 而不是各自读一遍磁盘。
#
# 否则一次没还原干净就会连环出错:后一条变异的锚点在被改过的文件里找不到,被报成「锚点失效」
# (于是看起来是清单写错了,其实是工具漏了),而它随手拍下的"原始内容"里已经带着上一条变异,
# 一路传下去,最后把某条变异留在工作树里 —— 那是会被当成真代码提交掉的。
def patch(path, pristine, old, new, nth):
    idx = -1
    for _ in range(nth + 1):
        idx = pristine.find(old, idx + 1)
        if idx < 0:
            return False
    write(path, pristine[:idx] + new + pristine[idx + len(old):])
    return True


def main():
    spec_path = sys.argv[1]
    timeout = "600s"
    if "--test-timeout" in sys.argv:
        timeout = sys.argv[sys.argv.index("--test-timeout") + 1]
    with open(spec_path, encoding="utf-8") as fh:
        muts = json.load(fh)

    pristine = {m["file"]: read(m["file"]) for m in muts}

    # 开跑前先确认原始代码是能编过的。否则每条变异都会因为「构建失败」被记成抓住,
    # 一份全绿的报告底下其实一条断言都没跑 —— 这种假绿比逃逸更危险。
    base = subprocess.run(["go", "build", "./..."], capture_output=True, text=True)
    if base.returncode != 0:
        print("原始代码就编不过,先修好再跑变异:\n" + base.stderr.strip())
        return 2

    caught, escaped, broken, nocompile = [], [], [], []
    for i, m in enumerate(muts, 1):
        desc, path = m["desc"], m["file"]
        if not patch(path, pristine[path], m["old"], m["new"], m.get("nth", 0)):
            broken.append(desc)
            print(f"[{i}/{len(muts)}] 找不到锚点,跳过: {desc}", flush=True)
            continue
        try:
            cmd = ["go", "test", m.get("test", "./..."), "-count=1", "-timeout", timeout]
            # 可选 "run":把这条变异的验证收窄到相关用例上。整包跑一轮动辄一两分钟,
            # 三十条变异就是一小时;收窄后是分钟级。填写时要**宁宽勿窄** —— 漏掉真正
            # 会抓住它的用例会得出"逃逸"的假结论。
            if m.get("run"):
                cmd += ["-run", m["run"]]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            out = proc.stdout + proc.stderr
            if proc.returncode == 0:
                escaped.append(desc)
                mark = "逃逸 ✗"
            elif "[build failed]" in out or "syntax error" in out:
                # 编不过不算「测试抓住了它」:这条变异什么断言都没验证到,得改写成语法合法的形状。
                nocompile.append(desc)
                mark = "编不过 —"
            else:
                caught.append(desc)
                mark = "抓住 ✓"
            print(f"[{i}/{len(muts)}] {mark}  {desc}", flush=True)
        finally:
            write(path, pristine[path])

    # 收尾复核:哪怕上面某一步出了意外,也不许把变异留在工作树里。
    dirty = [p for p, src in pristine.items() if read(p) != src]
    if dirty:
        for p in dirty:
            write(p, pristine[p])
        print("\n警告:以下文件在跑完时与开跑前不一致,已强制还原(请复核 git diff):")
        for p in dirty:
            print(f"  - {p}")

    print(f"\n抓住 {len(caught)} / 共 {len(caught) + len(escaped)}")
    if escaped:
        print("\n逃逸的变异(测试照过,说明没有断言真正检查这段逻辑):")
        for d in escaped:
            print(f"  - {d}")
    if nocompile:
        print("\n编不过(不算被抓住,需改写成语法合法的变异):")
        for d in nocompile:
            print(f"  - {d}")
    if broken:
        print("\n锚点失效:")
        for d in broken:
            print(f"  - {d}")
    return 1 if escaped else 0


if __name__ == "__main__":
    sys.exit(main())
