#!/usr/bin/env python3
"""变异验证:把生产代码定点改坏,确认测试真的会红。

变异清单写在一个 JSON 文件里,每项:
  {"desc": "...", "file": "store/web_admins.go", "old": "...", "new": "...",
   "nth": 0, "test": "./store/"}

nth 是当 old 在文件里出现多次时选第几个(默认 0)。逃逸(测试照过)的项会被单独列出——
那说明这段逻辑虽然被执行过,但没有任何断言真正检查它的结果。

用法: mutate.py MUTATIONS.json [--test-timeout 300s]
"""
import json
import subprocess
import sys


def patch(path, old, new, nth):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    idx = -1
    for _ in range(nth + 1):
        idx = src.find(old, idx + 1)
        if idx < 0:
            return None
    mutated = src[:idx] + new + src[idx + len(old):]
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(mutated)
    return src


def main():
    spec_path = sys.argv[1]
    timeout = "600s"
    if "--test-timeout" in sys.argv:
        timeout = sys.argv[sys.argv.index("--test-timeout") + 1]
    with open(spec_path, encoding="utf-8") as fh:
        muts = json.load(fh)

    caught, escaped, broken = [], [], []
    for i, m in enumerate(muts, 1):
        desc, path = m["desc"], m["file"]
        original = patch(path, m["old"], m["new"], m.get("nth", 0))
        if original is None:
            broken.append(desc)
            print(f"[{i}/{len(muts)}] 找不到锚点,跳过: {desc}", flush=True)
            continue
        try:
            proc = subprocess.run(
                ["go", "test", m.get("test", "./..."), "-count=1", "-timeout", timeout],
                capture_output=True, text=True)
            if proc.returncode == 0:
                escaped.append(desc)
                mark = "逃逸 ✗"
            else:
                caught.append(desc)
                mark = "抓住 ✓"
            print(f"[{i}/{len(muts)}] {mark}  {desc}", flush=True)
        finally:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(original)

    print(f"\n抓住 {len(caught)} / 共 {len(caught) + len(escaped)}")
    if escaped:
        print("\n逃逸的变异(测试照过,说明没有断言真正检查这段逻辑):")
        for d in escaped:
            print(f"  - {d}")
    if broken:
        print("\n锚点失效:")
        for d in broken:
            print(f"  - {d}")
    return 1 if escaped else 0


if __name__ == "__main__":
    sys.exit(main())
