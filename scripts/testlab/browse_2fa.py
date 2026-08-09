#!/usr/bin/env python3
"""真浏览器把 Web 后台的 2FA(TOTP)全生命周期走一遍 —— browse.py 只到「登录/建用户/权限」,
这里补的是**第二因子**那一层:

    注册 → 启用拿恢复码 → 二次因子登录 → 错码被拒 → 恢复码登录 → 恢复码一次性(重用被拒)
    → 改密 step-up(当前密码 + 当前 TOTP)→ 旧密码作废 / 新密码仍需 TOTP。

    scripts/testlab/lab.sh browse-2fa           # 常用入口
    ./browse_2fa.py --base https://127.0.0.1:7443

── 为什么单独一支 ──────────────────────────────────────────────────────────
2FA 是后台最要命的一段:一旦「密码泄露 + cookie 劫持能一键关 2FA」或「enable 时输的码
能被重放到登录」这类洞回归,e2e 的 HTTP 断言看不出来 —— 它们不驱动浏览器、也不算 TOTP。
这支从 DOM 上填真表单、用**内置的 RFC6238 算码**(和服务端 totp.go 同一套:base32 无填充 /
HMAC-SHA1 / 30s / 6 位),把自助部署者开 2FA 的每一步原样走一遍。

── 时间步这道坎 ────────────────────────────────────────────────────────────
服务端 enable / 登录 / 改密 step-up **共享同一 totp_last_used_step**:同一枚码用过一次就作废
(防「step-up 里输的码被重放到登录」)。所以每次要「消费」一枚码之前,必须等到一个**严格更新**
的 30s 窗口 —— 见 wait_step()。否则会在正确的码上莫名其妙地被拒,查起来像 bug 实则是重放防护。

── 管不了什么 ──────────────────────────────────────────────────────────────
数据面一概不管(那是 scripts/e2e/ 三台真机的事)。这里只回答「后台的 2FA 点得动、拦得住吗」。
"""
import argparse
import base64
import hashlib
import hmac
import re
import struct
import sys
import time
from pathlib import Path

# 复用 browse.py 里已验证的助手:验证码解算 / 登录 / 报告表。同目录直接借。
sys.path.insert(0, str(Path(__file__).resolve().parent))
from browse import Report, login, solve_captcha  # noqa: E402

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sys.exit("缺 playwright。装:pip3 install playwright(浏览器用系统 Chrome,channel=chrome)")


# ── 内置 RFC6238 TOTP:与 cmd/nanotun-web/totp.go 逐字对齐 ──────────────────
def _b32key(secret):
    s = secret.strip().upper().replace(" ", "")
    s += "=" * ((8 - len(s) % 8) % 8)  # base32 解码要 8 的倍数;服务端发的是无填充串
    return base64.b32decode(s)


def totp_at(secret, step):
    dig = hmac.new(_b32key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    off = dig[-1] & 0x0F
    binc = ((dig[off] & 0x7F) << 24) | (dig[off + 1] << 16) | (dig[off + 2] << 8) | dig[off + 3]
    return f"{binc % 1000000:06d}"


def wait_step(state, min_gap=2):
    """返回一个「严格大于上次消费步 + min_gap」且不贴 30s 边界的时间步。

    min_gap=2 是为了跨过服务端可能因 ±1 skew 命中的相邻步:上次我按步 S 提交,服务端可能
    实际消费了 S+1,下一枚必须落在 ≥ S+2 才稳。首枚(state['used'] 为空)只要落在窗口安全带即可。
    """
    while True:
        now = time.time()
        step = int(now) // 30
        gap_ok = state["used"] is None or step >= state["used"] + min_gap
        if gap_ok and 2 <= (now % 30) < 25:
            return step
        time.sleep(1)


def wrong_code(secret):
    """一枚**保证错**的 6 位码:避开当前 ±1 三个窗口的真码。"""
    s = int(time.time()) // 30
    bad = {totp_at(secret, s + d) for d in (-1, 0, 1)}
    for cand in range(1000000):
        c = f"{cand:06d}"
        if c not in bad:
            return c
    return "000000"  # 不可能到这


def logout(ctx):
    # 清 cookie = 客户端登出(会话 cookie + pending + csrf 一并掉),下一次从密码步重来。
    ctx.clear_cookies()


def dashed_codes(text):
    """从页面文本里抠恢复码(XXXX-XXXX,base32 字母表 A-Z2-7),按出现顺序去重。"""
    seen, out = set(), []
    for m in re.findall(r"[A-Z2-7]{4}-[A-Z2-7]{4}", text):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Web 管理面地址,如 https://127.0.0.1:7443")
    ap.add_argument("--admin-user", default="tfa_admin")
    ap.add_argument("--admin-pass", default="Tfa-Admin-2026!qX7z")
    ap.add_argument("--new-pass", default="Tfa-Rotated-2026!wZ9k")
    ap.add_argument("--shots", default="", help="截图目录;不给就不截")
    ap.add_argument("--headed", action="store_true")
    a = ap.parse_args()

    workdir = Path(a.shots) if a.shots else Path("/tmp/nanotun-browse-2fa")
    workdir.mkdir(parents=True, exist_ok=True)
    r = Report()
    state = {"used": None}  # 上次被消费的 TOTP 时间步
    n = [0]

    with sync_playwright() as pw:
        try:
            browser = pw.chromium.launch(channel="chrome", headless=not a.headed)
        except Exception as e:
            sys.exit(f"起不来 Chrome({e})。装了 Google Chrome 吗?")
        ctx = browser.new_context(ignore_https_errors=True,
                                  viewport={"width": 1440, "height": 900})
        page = ctx.new_page()

        def shot(tag):
            if a.shots:
                n[0] += 1
                page.screenshot(path=str(workdir / f"{n[0]:02d}-{tag}.png"), full_page=True)

        # ── 0. 抢首位管理员(和 browse.py 一样,自己 setup)────────────────────
        print("\n══ 0. 开服向导:抢下首位管理员 ══")
        page.goto(f"{a.base}/setup", wait_until="domcontentloaded")
        if not r.check("无管理员时 /setup 放行",
                       page.query_selector("input[name=password_confirm]") is not None):
            # /setup 关着说明这台已有管理员;本测试要自己抢首位,提示怎么重置。
            print("  → 这台已有 Web 管理员。先 lab.sh reset && lab.sh install --local(别带 --web-admin)")
            browser.close()
            return r.summary()
        page.fill("input[name=username]", a.admin_user)
        page.fill("input[name=password]", a.admin_pass)
        page.fill("input[name=password_confirm]", a.admin_pass)
        page.fill("input[name=captcha]", solve_captcha(page, workdir))
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(1)
        r.check("建成后离开 setup 页", "/setup" not in page.url, page.url)

        # ── 1. 首次登录(此时还没开 TOTP,应直达后台)───────────────────────
        print("\n══ 1. 开 2FA 前:密码登录直达后台 ══")
        logout(ctx)
        url = login(page, a.base, workdir, a.admin_user, a.admin_pass)
        r.check("未开 2FA 时密码即登录", "/login" not in url, url)

        # ── 2. 在 /me 注册 TOTP(需当前密码 step-up)──────────────────────
        print("\n══ 2. 注册 TOTP:/me → 输当前密码 → 拿密钥 ══")
        page.goto(f"{a.base}/me", wait_until="domcontentloaded")
        r.check("未开 2FA 时 /me 显示「未启用」并给出启用入口",
                page.query_selector("form[action='/me/totp/setup'] input[name=password]") is not None)
        page.fill("form[action='/me/totp/setup'] input[name=password]", a.admin_pass)
        page.click("form[action='/me/totp/setup'] button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.4)
        html = page.content()
        m = re.search(r"secret=([A-Z2-7]+)", html) or re.search(
            r"user-select:all[^>]*>([A-Z2-7]{16,})<", html)
        secret = m.group(1) if m else ""
        r.check("扫码页给出 base32 密钥", bool(secret) and len(secret) >= 16, f"secret 长度 {len(secret)}")
        r.check("扫码页给出 TOTP 二维码",
                page.query_selector("img[src^='data:image/png']") is not None)
        r.check("确认表单指向 /me/totp/enable",
                page.query_selector("form[action='/me/totp/enable'] input[name=code]") is not None)
        shot("totp-setup")

        # ── 3. 启用:算当前码 → enable → 落到一次性恢复码页 ────────────────
        print("\n══ 3. 启用 TOTP:算码确认 → 拿 10 条一次性恢复码 ══")
        step = wait_step(state)                     # 首枚:当前安全窗口即可
        page.fill("form[action='/me/totp/enable'] input[name=code]", totp_at(secret, step))
        page.click("form[action='/me/totp/enable'] button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        state["used"] = step                        # enable 消费掉这一步
        r.check("启用后跳到一次性恢复码页(PRG)", "/me/totp/codes" in page.url, page.url)
        recovery = dashed_codes(page.inner_text("body"))
        r.check("当场发够 10 条恢复码", len(recovery) == 10, f"实得 {len(recovery)} 条")
        shot("recovery-codes")

        page.goto(f"{a.base}/me", wait_until="domcontentloaded")
        me = page.inner_text("body")
        r.check("/me 现在标记 2FA 已启用", "已启用" in me or "enabled" in me.lower())
        r.check("恢复码计数显示 10 / 10", re.search(r"10\s*/\s*10", me) is not None)

        # ── 4. 二次因子登录:先错码被拒,再正确码放行 ─────────────────────
        print("\n══ 4. 二次因子登录:错码拦、对码放 ══")
        logout(ctx)
        url = login(page, a.base, workdir, a.admin_user, a.admin_pass)
        r.check("开了 2FA:过密码后落到 /login/totp", "/login/totp" in url, url)

        page.fill("input#code", wrong_code(secret))
        page.click("form:has(input#code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.5)
        r.check("错误 TOTP 码进不去后台", "/login/totp" in page.url, page.url)

        step = wait_step(state)                      # 正确码:跨过 enable 消费的步
        page.fill("input#code", totp_at(secret, step))
        page.click("form:has(input#code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        ok_login = "/login" not in page.url
        state["used"] = step if ok_login else state["used"]
        r.check("正确 TOTP 码进入后台", ok_login, page.url)

        # ── 5. 恢复码登录 + 一次性(同一码重用被拒)───────────────────────
        print("\n══ 5. 恢复码:能登录,且一次性 ══")
        logout(ctx)
        login(page, a.base, workdir, a.admin_user, a.admin_pass)
        # 恢复码表单折在 <details> 里,先展开再填。
        page.eval_on_selector("details", "d => d.open = true")
        page.fill("input#recovery_code", recovery[0])
        page.click("form:has(input#recovery_code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        r.check("恢复码可完成二次因子登录", "/login" not in page.url, page.url)

        logout(ctx)
        login(page, a.base, workdir, a.admin_user, a.admin_pass)
        page.eval_on_selector("details", "d => d.open = true")
        page.fill("input#recovery_code", recovery[0])          # 重用同一条
        page.click("form:has(input#recovery_code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        r.check("同一恢复码第二次用被拒", "/login/totp" in page.url, page.url)

        # 换第二条把自己放回后台(证明是「这条已消费」而非「恢复码整体失效」)。
        page.eval_on_selector("details", "d => d.open = true")
        page.fill("input#recovery_code", recovery[1])
        page.click("form:has(input#recovery_code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        r.check("另一条未用恢复码仍可登录", "/login" not in page.url, page.url)

        # ── 6. 改密 step-up:要当前密码 + 当前 TOTP ───────────────────────
        print("\n══ 6. 改密 step-up:当前密码 + 当前 TOTP 一并验 ══")
        page.goto(f"{a.base}/admins", wait_until="domcontentloaded")
        link = page.query_selector("a[href*='reset-pwd']")
        r.check("管理员页有改密入口", link is not None)
        href = link.get_attribute("href") if link else ""
        page.goto(f"{a.base}{href}", wait_until="domcontentloaded")
        r.check("改自己的密码要求当前密码",
                page.query_selector("input[name=current_password]") is not None)
        r.check("已开 2FA:改密还要当前 TOTP 码",
                page.query_selector("input[name=totp_code]") is not None)
        step = wait_step(state)
        page.fill("input[name=current_password]", a.admin_pass)
        page.fill("input[name=totp_code]", totp_at(secret, step))
        page.fill("input[name=password]", a.new_pass)
        page.fill("input[name=password_confirm]", a.new_pass)
        page.click("form[action*='reset-pwd'] button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.8)
        state["used"] = step
        r.check("改密提交后离开改密表单", "reset-pwd" not in page.url, page.url)
        shot("after-reset")

        # ── 7. 旧密码作废 / 新密码仍要过 TOTP ────────────────────────────
        print("\n══ 7. 旧密码作废、新密码仍受 2FA 保护 ══")
        logout(ctx)
        url = login(page, a.base, workdir, a.admin_user, a.admin_pass)   # 旧密码
        r.check("旧密码再也登不进(连 TOTP 步都到不了)",
                "/login/totp" not in url and "/login" in url, url)

        logout(ctx)
        url = login(page, a.base, workdir, a.admin_user, a.new_pass)     # 新密码
        r.check("新密码过密码步后仍落 /login/totp", "/login/totp" in url, url)
        step = wait_step(state)
        page.fill("input#code", totp_at(secret, step))
        page.click("form:has(input#code) button[type=submit]")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(0.6)
        r.check("新密码 + TOTP 进入后台", "/login" not in page.url, page.url)

        browser.close()

    rc = r.summary()
    if a.shots:
        print(f"截图:{workdir}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
