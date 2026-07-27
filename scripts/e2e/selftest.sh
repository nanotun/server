#!/usr/bin/env bash
# 断言库自身的测试。不连任何机器,直接 ./selftest.sh 就能跑。
#
# 这套 e2e 里唯一不需要三台机器的部分。加它是因为脚手架出过两次错,
# 两次都伪装成了产品缺陷:一次是断言把登录名当 device_id 传,五条限速断言
# 从落地起就没验证过任何东西;一次是 $var 后跟全角标点让整套在 macOS 上跑不起来。
#
# env_error 这套机制有几个不显眼但一碰就坏的性质,正是这里要钉住的:
#   - 写 stdout 会污染取值结果(它常在 $(...) 里被调用);
#   - 子 shell 里改数组父 shell 看不见,所以必须落文件;
#   - 期望值本身是空串的断言不能被误判成「没测到」。

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/assert.sh
source "$HERE/lib/assert.sh"

fails=0
expect() { # expect <说明> <期望> <实际>
  if [[ "$2" == "$3" ]]; then
    printf '  ok   %s\n' "$1"
  else
    printf '  BAD  %s:期望 [%s] 实际 [%s]\n' "$1" "$2" "$3"
    fails=1
  fi
}
envcount() { grep -c '' "$E2E_ENVLOG"; }

phase_begin "断言库自测"

echo "── 正常的通过与失败不受影响 ──"
check "正常通过" "abc" "abc"
expect "计入 PASS" 1 "$E2E_PASS"
check "正常失败" "abc" "xyz"
expect "计入 FAIL" 1 "$E2E_FAIL"

echo "── 取值为空且期望非空:记 ENV,不计红绿 ──"
check "取值为空" "150000" ""
expect "不计入 FAIL" 1 "$E2E_FAIL"
expect "不计入 PASS" 1 "$E2E_PASS"
expect "记入 ENV" 1 "$(envcount)"

echo "── 期望本身是空串(NXDOMAIN 那条)仍是正常断言 ──"
check "期望空结果" "" ""
expect "计入 PASS" 2 "$E2E_PASS"
expect "未误报 ENV" 1 "$(envcount)"

echo "── 取值为 ?(取值函数声明没取到)同样记 ENV ──"
check "取值为问号" "150000" "?"
expect "记入 ENV" 2 "$(envcount)"

echo "── check_match / check_contains 一并适用 ──"
check_match "正则取值为空" '^[0-9]+$' ""
check_contains "子串取值为空" "needle" ""
expect "各记一条" 4 "$(envcount)"

echo "── 同一条只记一次(wait_until 每秒调一遍谓词)──"
env_error "重复的说明"; env_error "重复的说明"; env_error "重复的说明"
expect "去重" 5 "$(envcount)"

echo "── 子 shell 里报的环境问题,父 shell 要统计得到 ──"
_broken_getter() { env_error "子 shell 里的取值故障"; echo "?"; }
val="$(_broken_getter)"
expect "取值未被 ENV 输出污染" "?" "$val"
expect "父 shell 统计到" 6 "$(envcount)"

echo "── 退出码:ENV 存在时为 2,优先于 FAIL 的 1 ──"
e2e_report >/dev/null 2>&1; rc=$?
expect "退出码" 2 "$rc"

# 静态检查。bash 会把紧跟在 $var 后面的多字节标点首字节并进变量名,set -u 下
# 当场报 unbound variable(见 e389798)。这个坑踩过两次 —— 第二次就是在写崩溃
# 恢复阶段时又写了一个 —— 靠人记不住,挡在这里。
echo "── 静态检查:\$var 后面不能紧跟非 ASCII 字符 ──"
offenders="$(python3 - "$HERE" <<'PY'
import re, sys, pathlib
root = pathlib.Path(sys.argv[1])
pat = re.compile(rb'\$[A-Za-z_][A-Za-z0-9_]*[^\x00-\x7F]')
out = []
seen = set()
for pattern in ('*.sh', 'lib/*.sh', 'phases/*.sh'):
    for p in sorted(root.glob(pattern)):
        if p in seen:
            continue
        seen.add(p)
        for i, line in enumerate(p.read_bytes().split(b'\n'), 1):
            if pat.search(line):
                out.append('%s:%d: %s' % (p.relative_to(root), i,
                                          line.decode('utf-8', 'replace').strip()))
print('\n'.join(out))
PY
)"
if [[ -n "$offenders" ]]; then
  printf '  BAD  以下位置要改成 ${var}:\n'
  printf '       %s\n' "$offenders"
  fails=1
else
  echo '  ok   没有裸 $var 紧跟全角标点'
fi

rm -f "$E2E_ENVLOG"
echo
if (( fails )); then
  echo "断言库自测:有不符合预期的项"
  exit 1
fi
echo "断言库自测:全部符合预期"
