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
import signal
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
def patch(path, pristine, old, new, nth, also=()):
    text = pristine
    # "also" 是给「冗余防线」用的:两处各自都足以挡住同一个错误,单拆任何一层另一层就补上了,
    # 于是单条变异永远逃逸,看起来像没测,其实是测了。要证明这对防线真实存在(而不是两层都是空的),
    # 只能同时拆掉。edits 顺序施加,每一步都以上一步的结果为基准。
    edits = [(old, new, nth)] + [(o, n, 0) for o, n in also]
    for o, n, k in edits:
        idx = -1
        for _ in range(k + 1):
            idx = text.find(o, idx + 1)
            if idx < 0:
                return False
        text = text[:idx] + n + text[idx + len(o):]
    write(path, text)
    return True


# 源码注释里中英混排,全角逗号/括号跟半角混着用;手写锚点时抄成半角是最常见的失手。
# 这一步不放宽匹配(那会让变异改到意料之外的位置),只是在找不到时把文件里的真实文本打出来,
# 好直接照抄 —— 否则「锚点失效」只是一句「跳过」,而这条变异从此再没人验证过。
FULLWIDTH = str.maketrans({
    "，": ",", "（": "(", "）": ")", "：": ":", "；": ";",
    "！": "!", "？": "?", "、": ",", "　": " ",
})


def diagnose(pristine, old):
    norm = pristine.translate(FULLWIDTH)
    idx = norm.find(old.translate(FULLWIDTH))
    if idx < 0:
        return None
    # 逐字符替换,所以规范化后的下标可以直接落回原文。
    return pristine[idx:idx + len(old)]


def main():
    spec_path = sys.argv[1]
    timeout = "600s"
    if "--test-timeout" in sys.argv:
        timeout = sys.argv[sys.argv.index("--test-timeout") + 1]
    with open(spec_path, encoding="utf-8") as fh:
        muts = json.load(fh)

    pristine = {m["file"]: read(m["file"]) for m in muts}

    # 整批要跑一两个小时,中途被 Ctrl-C / kill 掉是常态。默认的 SIGTERM 会直接终止进程,
    # 当时正被改坏的那个文件就留在工作树里了 —— 下一次 git commit 会把变异当成真代码提交。
    # 转成异常,好让下面的 finally 把所有文件还原回去。
    def on_signal(signum, _frame):
        raise KeyboardInterrupt(f"收到信号 {signum}")

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    # 开跑前先确认原始代码是能编过的。否则每条变异都会因为「构建失败」被记成抓住,
    # 一份全绿的报告底下其实一条断言都没跑 —— 这种假绿比逃逸更危险。
    base = subprocess.run(["go", "build", "./..."], capture_output=True, text=True)
    if base.returncode != 0:
        print("原始代码就编不过,先修好再跑变异:\n" + base.stderr.strip())
        return 2

    caught, escaped, broken, nocompile = [], [], [], []
    try:
        run_all(muts, pristine, timeout, caught, escaped, broken, nocompile)
    except KeyboardInterrupt as stop:
        print(f"\n中断:{stop}(已跑 {len(caught) + len(escaped) + len(nocompile)} 条)", flush=True)
    finally:
        restore_all(pristine)

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


# restore_all 是最后一道保险:哪怕上面任何一步出了意外(信号、异常、写盘失败),
# 也不许把变异留在工作树里 —— 那是会被当成真代码提交掉的。
def restore_all(pristine):
    dirty = [p for p, src in pristine.items() if read(p) != src]
    for p in dirty:
        write(p, pristine[p])
    if dirty:
        print("\n以下文件与开跑前不一致,已强制还原(请复核 git diff):")
        for p in dirty:
            print(f"  - {p}")


def run_all(muts, pristine, timeout, caught, escaped, broken, nocompile):
    for i, m in enumerate(muts, 1):
        desc, path = m["desc"], m["file"]
        if not patch(path, pristine[path], m["old"], m["new"], m.get("nth", 0), m.get("also", ())):
            broken.append(desc)
            print(f"[{i}/{len(muts)}] 找不到锚点,跳过: {desc}", flush=True)
            actual = diagnose(pristine[path], m["old"])
            if actual is not None:
                print("      只差全/半角标点,文件里的真实文本是:", flush=True)
                print("      " + actual.replace("\n", "\n      "), flush=True)
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


if __name__ == "__main__":
    sys.exit(main())
