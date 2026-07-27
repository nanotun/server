#!/usr/bin/env python3
"""nanotun-web 的回归测试客户端:完成登录并复用会话发请求。

替掉原先 curl + grep + sed 那条链子。换掉的理由不是风格,是那条链子踩过三个
真实的坑,而且每个都表现为「服务器拒绝了」这种会把人引向错误方向的现象:

  1. 验证码 data URL 在 HTML 里是转义过的(+ → &#43;),而 base64.b64decode
     默认静默丢弃非字母表字符 —— 于是得到一个短几十字节、zlib 解不开的 PNG。
  2. PoW 的 salt/signature 同样被转义,不 unescape 解出来的 salt 是错的。
  3. curl -d 不做 URL 编码,base64 里的 + 被表单解析成空格,服务端报
     「bad salt / bad signature」。

用 urllib 统一走 urlencode,这三类问题在源头上就不存在了。

用法:
  webclient.py --base URL --jar PATH login --user U --password P [--totp-secret S]
  webclient.py --base URL --jar PATH get  <path>  [--out FILE]
  webclient.py --base URL --jar PATH post <path>  [k=v ...]

统一在 stdout 打印 HTTP 状态码,便于 shell 侧直接断言。
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.cookiejar
import re
import ssl
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import capsolve  # noqa: E402  与本文件同目录下发


def build_opener(jar_path):
    jar = http.cookiejar.MozillaCookieJar(jar_path)
    try:
        jar.load(ignore_discard=True)
    except (OSError, http.cookiejar.LoadError):
        pass
    # 自签证书:回归环境走 127.0.0.1,证书校验没有意义,关掉以免每次都要塞 CA。
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(jar),
        urllib.request.HTTPSHandler(context=ctx),
        NoRedirect(),
    )
    return opener, jar


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """不自动跟随跳转:登录成功与否正是靠 302/303 区分的,跟了就看不见。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(opener, url, data=None):
    req = urllib.request.Request(url, data=data, method="POST" if data else "GET")
    req.add_header("User-Agent", "nanotun-e2e/1.0")
    try:
        with opener.open(req, timeout=20) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def field(body, name):
    """取 hidden field 的值,顺带反转义。"""
    m = re.search(r'name="%s"\s*[^>]*?value="([^"]*)"' % re.escape(name), body)
    if not m:
        m = re.search(r'value="([^"]*)"\s*[^>]*?name="%s"' % re.escape(name), body)
    return html.unescape(m.group(1)) if m else ""


def solve_captcha(body, tmp_png=None):
    # 落在脚本自己所在的目录里:那个目录是 e2e 下发用的临时目录,收尾时整个删掉,
    # 写到 /tmp 根下会留残留(状态校验抓不到,但下次排查时是噪声)。
    if tmp_png is None:
        tmp_png = __file__.rsplit("/", 1)[0] + "/cap.png"
    m = re.search(r"data:image/png;base64,(.*?)['\"]", body, re.S)
    if not m:
        return ""
    b = "".join(html.unescape(m.group(1)).split())
    raw = base64.b64decode(b + "=" * (-len(b) % 4), validate=True)
    with open(tmp_png, "wb") as f:
        f.write(raw)
    return capsolve.solve(tmp_png)


def solve_pow(body):
    """返回要附加到表单的 PoW 字段;没有 PoW 挑战则返回空 dict。

    难度会随失败次数自适应上升,所以这里不设 nonce 上限,靠调用方的超时兜底。
    """
    cid = field(body, "pow_challenge_id")
    if not cid:
        return {}
    salt_b64 = field(body, "pow_salt")
    difficulty = int(field(body, "pow_difficulty") or "0")
    salt = base64.b64decode(salt_b64 + "=" * (-len(salt_b64) % 4))
    prefix = cid.encode() + b"\x00" + salt
    nonce = 0
    while True:
        digest = hashlib.sha256(prefix + struct.pack(">Q", nonce)).digest()
        if leading_zero_bits(digest) >= difficulty:
            return {
                "pow_challenge_id": cid,
                "pow_salt": salt_b64,
                "pow_difficulty": str(difficulty),
                "pow_expires_at": field(body, "pow_expires_at"),
                "pow_signature": field(body, "pow_signature"),
                "pow_nonce": str(nonce),
            }
        nonce += 1


def leading_zero_bits(digest):
    bits = 0
    for byte in digest:
        if byte == 0:
            bits += 8
            continue
        while byte & 0x80 == 0:
            bits += 1
            byte <<= 1
        break
    return bits


def totp_code(secret):
    secret = secret.strip().upper()
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int(time.time() // 30)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    return "%06d" % ((struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % 1000000)


def do_login(opener, base, args):
    status, body = request(opener, base + "/login")
    if status != 200:
        print("login page status=%d" % status)
        return 1

    form = {
        "username": args.user,
        "password": args.password,
        "csrf_token": field(body, "csrf_token"),
    }
    captcha = solve_captcha(body)
    if captcha:
        form["captcha"] = captcha
    form.update(solve_pow(body))

    status, body = request(opener, base + "/login",
                           urllib.parse.urlencode(form).encode())
    if status not in (302, 303):
        print("step1 status=%d" % status)
        for hint in re.findall(r"(错误|失败|锁定|invalid|incorrect|locked)[^<]{0,40}", body):
            print("  hint: %s" % "".join(hint) if isinstance(hint, tuple) else hint)
        return 1

    if not args.totp_secret:
        print("200")
        return 0

    status, body = request(opener, base + "/login/totp")
    if status != 200:
        # 没有二步页面 → 该账号未开 TOTP,第一步就已经登录完成。
        print("200")
        return 0
    form = {"csrf_token": field(body, "csrf_token"), "code": totp_code(args.totp_secret)}
    status, _ = request(opener, base + "/login/totp",
                        urllib.parse.urlencode(form).encode())
    print("200" if status in (302, 303) else str(status))
    return 0 if status in (302, 303) else 1


def csrf_from(opener, base, path="/port-forwards"):
    """从任意一个已登录页面取 CSRF token。

    token 是按会话签发的,任何一个带表单的页面上取到的都能用;这里默认取端口转发页,
    调用方也可以用 --csrf-from 指定,避免某些页面对 viewer 角色 403 导致取不到。
    """
    _, body = request(opener, base + path)
    return field(body, "csrf_token")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True)
    p.add_argument("--jar", required=True)
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("login")
    lp.add_argument("--user", required=True)
    lp.add_argument("--password", required=True)
    lp.add_argument("--totp-secret", default="")

    gp = sub.add_parser("get")
    gp.add_argument("path")
    gp.add_argument("--out", default="")

    pp = sub.add_parser("post")
    pp.add_argument("path")
    pp.add_argument("kv", nargs="*")
    pp.add_argument("--csrf-from", default="/port-forwards")
    pp.add_argument("--no-csrf", action="store_true")
    pp.add_argument("--bad-csrf", default="")
    pp.add_argument("--out", default="")

    args = p.parse_args()
    base = args.base.rstrip("/")
    opener, jar = build_opener(args.jar)

    try:
        if args.cmd == "login":
            return do_login(opener, base, args)

        if args.cmd == "get":
            status, body = request(opener, base + args.path)
            if args.out:
                with open(args.out, "w") as f:
                    f.write(body)
            print(status)
            return 0

        form = {}
        for item in args.kv:
            k, _, v = item.partition("=")
            form[k] = v
        if args.bad_csrf:
            form["csrf_token"] = args.bad_csrf
        elif not args.no_csrf:
            form["csrf_token"] = csrf_from(opener, base, args.csrf_from)
        status, body = request(opener, base + args.path,
                               urllib.parse.urlencode(form).encode())
        if args.out:
            with open(args.out, "w") as f:
                f.write(body)
        print(status)
        return 0
    finally:
        jar.save(ignore_discard=True)


if __name__ == "__main__":
    sys.exit(main())
