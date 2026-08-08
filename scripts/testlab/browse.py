#!/usr/bin/env python3
"""拿真浏览器把 nanotun-web 的自助流程走一遍:开服 → 登录 → 建用户拿码 → 服务器码 → 权限边界。

    scripts/testlab/lab.sh browse          # 常用入口,不必直接调这个文件
    ./browse.py --base https://1.2.3.4:7443    # 也能对着真机跑(会在上面建管理员和用户)

── 为什么要有它 ────────────────────────────────────────────────────────────
scripts/e2e/phases/60-web.sh 已经覆盖了 web 的 HTTP 面:未登录重定向、CSRF、405、
RBAC、端口转发的各种拒绝。但它走的是 webclient.py,直接打接口 —— 页面渲不渲得出来、
表单填不填得进去、按钮点了有没有反应,它一概不知道。而真正会坏的地方(模板改坏、
表单少个字段、按钮绑错 handler)恰恰在那一层。

所以这里补的不是断言数量,是**入口**:每一步都从 DOM 上找元素、填真表单、点真按钮,
和自助部署者第一天做的事一模一样。全程只用浏览器,不碰 docker exec、不碰 CLI ——
凡是这个脚本做得到的,用户在界面上就做得到。

── 验证码 ──────────────────────────────────────────────────────────────
开服和登录都要过图形验证码。复用 e2e 那份确定性解算器(scripts/e2e/remote/capsolve.py):
它按 nanotun-web 自己的字模和排布参数识别,不是打码平台,也不联网。

── 管不了什么 ──────────────────────────────────────────────────────────
数据面一概不管 —— 那是 scripts/e2e/ 三台真机的事。这里只回答「后台点得动吗」。
"""
import argparse
import base64
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CAPSOLVE = ROOT / "scripts" / "e2e" / "remote" / "capsolve.py"

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit(
        "缺 playwright。装:\n"
        "    pip3 install playwright\n"
        "浏览器用系统已装的 Chrome(channel=chrome),不额外下一份。"
    )


class Report:
    def __init__(self):
        self.rows = []

    def check(self, name, cond, detail=""):
        cond = bool(cond)
        self.rows.append((name, cond, detail))
        print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""),
              flush=True)
        return cond

    def summary(self):
        ok = sum(1 for _, c, _ in self.rows if c)
        print("\n" + "─" * 46)
        print(f"合计 {len(self.rows)} 项:通过 {ok},失败 {len(self.rows) - ok}")
        for name, c, detail in self.rows:
            if not c:
                print(f"  失败:{name}" + (f" — {detail}" if detail else ""))
        return 0 if ok == len(self.rows) else 1


def solve_captcha(page, workdir):
    """验证码是 data:image/png;base64 内联在页面里的,从 DOM 读回来交给 capsolve。

    别去 HTML 源码里正则抠:模板会把 base64 里的 `+` 转义成 `&#43;`,抠出来的串
    b64decode 直接报 incomplete stream。走 DOM 拿 el.src,浏览器已经把实体还原好了。
    """
    src = page.eval_on_selector("img[src^='data:image/png']", "el => el.src")
    png = workdir / "captcha.png"
    png.write_bytes(base64.b64decode(src.split(",", 1)[1]))
    out = subprocess.run([sys.executable, str(CAPSOLVE), str(png)],
                         capture_output=True, text=True)
    return out.stdout.strip()


def submit(page, *labels):
    """点表单里那个真正的提交键。

    登录之后每一页顶部都挂着「组网 ON」和「退出」两个 type=submit 的按钮,泛选
    `button[type=submit]` 会点到导航栏上去 —— 表单没提交,页面也没跳,排查半天都在
    看错的地方。按钮面上的字才是唯一可靠的锚点,中英各给一个免得跟着 ?lang= 漂。
    """
    page.click(", ".join(f"form button:has-text('{t}')" for t in labels))
    page.wait_for_load_state("domcontentloaded")


def login(page, base, workdir, user, password):
    page.goto(f"{base}/login", wait_until="domcontentloaded")
    page.fill("input[name=username]", user)
    page.fill("input[name=password]", password)
    if page.query_selector("input[name=captcha]"):
        page.fill("input[name=captcha]", solve_captcha(page, workdir))
    # 登录页没登录,导航栏还不在,这里泛选是安全的。
    page.click("button[type=submit], input[type=submit]")
    page.wait_for_load_state("domcontentloaded")
    time.sleep(0.6)
    return page.url


def big_qrs(page):
    """页面上「肉眼可见的那张二维码」。

    只数 img[src^=data:] 会把导航栏图标、验证码之类一并算进来,断言就假绿了。
    按渲染宽度筛一道 —— 二维码是页面主角,不会只有百来像素。
    """
    return [i for i in page.query_selector_all("img[src^='data:image/png']")
            if (i.bounding_box() or {}).get("width", 0) > 150]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Web 管理面地址,如 https://127.0.0.1:7443")
    ap.add_argument("--admin-user", default="labadmin")
    ap.add_argument("--admin-pass", default="Lab-Browser-2026!qX")
    ap.add_argument("--viewer-user", default="labviewer")
    ap.add_argument("--viewer-pass", default="Lab-V1ewer-2026!wZ")
    ap.add_argument("--dial-host", default="203.0.113.10",
                    help="RFC 5737 文档地址:语法合法,又不会有人误以为真能拨")
    ap.add_argument("--shots", default="", help="截图目录;不给就不截")
    ap.add_argument("--headed", action="store_true", help="开着窗口跑,便于肉眼看")
    a = ap.parse_args()

    if not CAPSOLVE.exists():
        sys.exit(f"找不到验证码解算器:{CAPSOLVE}")

    workdir = Path(a.shots) if a.shots else Path("/tmp/nanotun-browse")
    workdir.mkdir(parents=True, exist_ok=True)
    r = Report()
    n = [0]

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(channel="chrome", headless=not a.headed)
        except Exception as e:
            sys.exit(f"起不来 Chrome({e})。装了 Google Chrome 吗?"
                     f"或者 `playwright install chromium` 之后把 channel 去掉。")
        # 后台证书是自签的,这里等价于用户在浏览器上点「继续前往」。
        ctx = browser.new_context(ignore_https_errors=True,
                                  viewport={"width": 1440, "height": 900})
        page = ctx.new_page()

        def shot(tag):
            if a.shots:
                n[0] += 1
                page.screenshot(path=str(workdir / f"{n[0]:02d}-{tag}.png"), full_page=True)

        print("\n══ 1. 开服向导:抢下首位管理员 ══")
        page.goto(f"{a.base}/setup", wait_until="domcontentloaded")
        r.check("无管理员时 /setup 放行",
                page.query_selector("input[name=password_confirm]") is not None)
        page.fill("input[name=username]", a.admin_user)
        page.fill("input[name=password]", a.admin_pass)
        page.fill("input[name=password_confirm]", a.admin_pass)
        page.fill("input[name=captcha]", solve_captcha(page, workdir))
        shot("setup")
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(1)
        r.check("建成后离开 setup 页", "/setup" not in page.url, f"落到 {page.url}")
        shot("after-setup")

        print("\n══ 2. setup 自封口(不需要另设开关)══")
        page.goto(f"{a.base}/setup", wait_until="domcontentloaded")
        r.check("有管理员后 /setup 不再放行", "/setup" not in page.url, f"跳到 {page.url}")

        print("\n══ 3. 用真表单登录 ══")
        ctx.clear_cookies()
        r.check("管理员登录成功",
                "/login" not in login(page, a.base, workdir, a.admin_user, a.admin_pass),
                page.url)
        shot("dashboard")

        print("\n══ 4. 逐页巡检(模板渲染)══")
        for path in ["/", "/users", "/devices", "/leases", "/acl", "/routes",
                     "/port-forwards", "/sessions", "/audit", "/admins",
                     "/settings", "/sysmon", "/me"]:
            resp = page.goto(f"{a.base}{path}", wait_until="domcontentloaded")
            status = resp.status if resp else 0
            body = page.content().lower()
            broken = "panic" in body or "internal server error" in body
            r.check(f"{path} 渲染正常", status < 400 and not broken, f"HTTP {status}")

        print("\n══ 5. 在界面上建 VPN 用户 ══")
        page.goto(f"{a.base}/users", wait_until="domcontentloaded")
        entry = page.query_selector("a[href*='new']")
        r.check("用户页有建用户入口", entry is not None)
        if entry:
            entry.click()
            page.wait_for_load_state("domcontentloaded")
            uname = f"browse{int(time.time()) % 100000}"
            page.fill("input[name=username]", uname)
            shot("newuser-form")
            submit(page, "创建", "Create")
            time.sleep(1.2)
            body = page.inner_text("body")
            # 这一页按设计只出**凭证**码;服务器 profile 码在 /server-qr 另走一条路(要二次
            # 验密码)。别改成期望两张 —— 那是看走眼,不是缺功能。
            r.check("建成后当场出凭证二维码", len(big_qrs(page)) == 1,
                    f"大图 {len(big_qrs(page))} 张")
            r.check("PSK 当场给出且说明只此一次",
                    re.search(r"[A-Z0-9]{5}-[A-Z0-9]{5}-", body) is not None
                    and ("一次" in body or "once" in body.lower()))
            # 措辞是有来历的:早先 UI 把 profile 说成「可公开」,而 hy2 mTLS 开着时它内嵌
            # 客户端证书。改对之后得有人守着,不然哪天改回去没人知道。
            r.check("讲清了它和 profile 码不是一回事",
                    "profile" in body.lower() and ("凭证" in body or "credential" in body.lower()))
            shot("user-created")
            page.goto(f"{a.base}/users", wait_until="domcontentloaded")
            r.check("新用户进了列表", uname in page.content(), uname)

        print("\n══ 6. 服务器配置码:没配拨号地址时怎么说 ══")
        resp = page.goto(f"{a.base}/server-qr", wait_until="domcontentloaded")
        r.check("没配 dial host 也不 500", resp.status < 500, f"HTTP {resp.status}")
        r.check("直说缺的是 server_dial_host", "server_dial_host" in page.inner_text("body"))
        shot("serverqr-nohost")

        print("\n══ 7. 在设置页配拨号地址 ══")
        page.goto(f"{a.base}/settings", wait_until="domcontentloaded")
        page.fill("input[name=server_dial_host]", a.dial_host)
        # 文档保留地址当然 ping 不通。勾上跳过 ICMP —— AWS / Vultr 这些默认拦 ICMP 的
        # 机器上,真实用户走的也正是这条路。
        page.check("input[name=skip_probe]")
        submit(page, "保存", "Save")
        time.sleep(1)
        r.check("拨号地址存进去了", a.dial_host in page.content(), a.dial_host)
        shot("settings")

        print("\n══ 8. 服务器配置码:二次验密码才给看 ══")
        page.goto(f"{a.base}/server-qr", wait_until="domcontentloaded")
        gate = page.inner_text("body")
        r.check("出码前拦一道密码", page.query_selector("input[name=password]") is not None)
        # 这是这一页最要紧的一句:同时说清「不含 PSK」和「照样是敏感物」。
        r.check("说明了码里含 mTLS 客户端证书",
                "客户端证书" in gate or "client cert" in gate.lower())
        shot("serverqr-gate")

        page.fill("input[name=password]", "definitely-not-the-password")
        submit(page, "显示服务器 QR", "Show server QR")
        time.sleep(0.8)
        r.check("密码错就拿不到码", len(big_qrs(page)) == 0, f"大图 {len(big_qrs(page))} 张")

        page.goto(f"{a.base}/server-qr", wait_until="domcontentloaded")
        page.fill("input[name=password]", a.admin_pass)
        submit(page, "显示服务器 QR", "Show server QR")
        time.sleep(1.2)
        body, html = page.inner_text("body"), page.content()
        r.check("密码对了出 profile 码", len(big_qrs(page)) >= 1, f"大图 {len(big_qrs(page))} 张")
        # URL 文本折在 <details> 里,innerText 取不到收起来的内容,只能从 HTML 上看。
        r.check("码是 nanotun:// 而不是凭证串", "nanotun://" in html)
        r.check("提示这次查看已入审计", "审计" in body or "audit" in body.lower())
        shot("serverqr-shown")

        print("\n══ 9. 权限边界:只读管理员 ══")
        page.goto(f"{a.base}/admins/new", wait_until="domcontentloaded")
        page.fill("input[name=username]", a.viewer_user)
        page.select_option("select[name=role]", "viewer")
        page.fill("input[name=password]", a.viewer_pass)
        page.fill("input[name=password_confirm]", a.viewer_pass)
        submit(page, "创建", "Create")
        time.sleep(0.8)
        r.check("在界面上建出 viewer", a.viewer_user in page.content(), a.viewer_user)

        ctx.clear_cookies()
        r.check("viewer 能登录",
                "/login" not in login(page, a.base, workdir, a.viewer_user, a.viewer_pass),
                page.url)
        r.check("viewer 读得了会话页",
                page.goto(f"{a.base}/sessions", wait_until="domcontentloaded").status == 200)
        r.check("viewer 读不了审计页",
                page.goto(f"{a.base}/audit", wait_until="domcontentloaded").status == 403)
        r.check("viewer 拿不到服务器码",
                page.goto(f"{a.base}/server-qr", wait_until="domcontentloaded").status >= 400)
        page.goto(f"{a.base}/users", wait_until="domcontentloaded")
        # 后端拒绝是底线,但界面上根本不该给这个入口 —— 否则用户点进去才知道自己没权限。
        r.check("viewer 界面上没有建用户入口", page.query_selector("a[href*='new']") is None)
        shot("viewer")

        browser.close()

    rc = r.summary()
    if a.shots:
        print(f"截图:{workdir}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
