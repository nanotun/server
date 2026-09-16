/*
 * app.js — 全站通用的非侵入式行为脚本(委托监听 + data-* 属性驱动)。
 *
 * 背景(第十一轮深扫 LOW 保留项:去掉 CSP script-src 的 'unsafe-inline')
 * -------------------------------------------------------------------
 * 原先模板里散落大量内联事件处理器:onclick="return confirm(...)"、
 * onclick="this.select()"、onclick="window.print()"、以及拨号 host 表单的
 * onsubmit 进度提示。内联 on*= 处理器无法用 nonce 授权,只能靠 'unsafe-inline'
 * 放行 —— 而那正是我们要移除的 XSS 兜底缺口。
 *
 * 本文件是**外链** /static/app.js(script-src 'self' 覆盖,无需 nonce),用事件
 * 委托 + data-* 属性复刻这些行为,从而让模板彻底摆脱内联 on*= 处理器。i18n 文案
 * 由模板渲染进 data-* 属性(html/template 按属性上下文自动转义),脚本只读取、不拼接
 * HTML,无注入面。
 *
 * 覆盖的约定
 * ----------
 *  - [data-confirm="msg"]         点击时 confirm(msg),取消则阻止默认动作(表单提交 / 链接跳转)。
 *  - [data-select-on-click]       点击时全选该元素文本(textarea/input .select())。
 *  - [data-print]                 点击时 window.print()。
 *  - form[data-progress-form]     提交时禁用按钮 + 改文案 + 可选进度/超时兜底(拨号 host 探测)。
 *  - body[data-msg-required]      原生表单校验气泡的文案(见下面「校验气泡」一节)。
 *    body[data-msg-pattern]
 *  - input[type=password]         自动补一个「眼睛」按钮切换明文/密文(见「密码可见性」一节)。
 *    body[data-msg-show-pw]       按钮的无障碍文案(aria-label / title),两种状态各一句。
 *    body[data-msg-hide-pw]
 *
 * 页面各自的复制到剪贴板逻辑仍留在**带 nonce 的内联 <script>** 里(涉及 i18n 文案 +
 * 元素特定取值 + alert/prompt 降级),不在此文件。
 */
(function () {
    "use strict";

    // ---- 原生校验气泡的文案 -------------------------------------------------
    //
    // required 字段留空时,浏览器弹的那个气泡(「请填写此字段。」)不是我们打的 —— 它是
    // 浏览器自带的,语言跟的是**浏览器界面语言**,而不是页面的 lang。于是英文界面上,
    // 中文版 Chrome 照样弹中文,整页只有这一个气泡不听话。
    //
    // 唯一能改它的办法是 setCustomValidity():在 invalid 事件里塞进我们自己的文案。
    // 文案由模板渲染进 body 的 data-* (与本文件其它约定同一套做法,html/template 按属性
    // 上下文转义,脚本只读不拼)。
    //
    // 两个容易踩的点:
    //   · invalid 事件**不冒泡**,必须用捕获(第三个参数 true),否则挂在 document 上收不到;
    //   · 自定义文案一旦设上就会让该字段**一直**被判为非法(哪怕后来填对了),所以要在
    //     input/change 时清空。少了这一步,填对了也提交不了,而且看不出为什么。
    var msgRequired = document.body && document.body.getAttribute("data-msg-required");
    var msgPattern = document.body && document.body.getAttribute("data-msg-pattern");

    document.addEventListener("invalid", function (e) {
        var el = e.target;
        if (!el || typeof el.setCustomValidity !== "function" || !el.validity) return;
        if (el.validity.valueMissing && msgRequired) {
            el.setCustomValidity(msgRequired);
        } else if (el.validity.patternMismatch && msgPattern) {
            // title 是字段自己的说明(比如「6 位数字」),有就优先用,比通用句子具体。
            el.setCustomValidity(el.getAttribute("title") || msgPattern);
        }
    }, true);

    // 清空:否则上面设过的文案会把一个已经填对的字段永久钉死成非法。
    document.addEventListener("input", clearValidity, true);
    document.addEventListener("change", clearValidity, true);
    function clearValidity(e) {
        var el = e.target;
        if (el && typeof el.setCustomValidity === "function") el.setCustomValidity("");
    }

    // ---- 点击委托:confirm / select / print ---------------------------------
    document.addEventListener("click", function (e) {
        var t = e.target;
        if (!t || !t.closest) return;

        // data-confirm:二次确认。取消 → 阻止默认(阻止 submit / 链接跳转)+ 阻断冒泡。
        var confirmEl = t.closest("[data-confirm]");
        if (confirmEl) {
            var msg = confirmEl.getAttribute("data-confirm");
            if (msg && !window.confirm(msg)) {
                e.preventDefault();
                e.stopPropagation();
                return;
            }
        }

        // data-select-on-click:点击只读文本框时全选,便于手动复制。
        var selEl = t.closest("[data-select-on-click]");
        if (selEl && typeof selEl.select === "function") {
            selEl.select();
        }

        // data-print:调起浏览器打印(恢复码等)。
        var printEl = t.closest("[data-print]");
        if (printEl) {
            e.preventDefault();
            window.print();
        }
    });

    // ---- 密码可见性:给每个密码框补一个「眼睛」 ---------------------------------
    //
    // 登录页 / 首次安装 / 改密 / 新建管理员 / QR 口令页的密码框都是 type=password,
    // 输错一个字符只能整段删掉重打。这里在脚本层统一给它们补一个切换按钮,模板不用
    // 逐个改;无 JS 时就是普通密码框(渐进增强)。
    //
    // 两个取舍:
    //   · 按钮是 type=button,不会被当成表单提交键;放在 <form> 里按回车仍提交表单。
    //   · SVG 是写死的常量,不拼任何页面数据;文案从 body 的 data-* 读(html/template
    //     已按属性上下文转义),与本文件其余约定一致 —— 不引入注入面。
    var msgShowPw = document.body && document.body.getAttribute("data-msg-show-pw");
    var msgHidePw = document.body && document.body.getAttribute("data-msg-hide-pw");
    var SVG_NS = "http://www.w3.org/2000/svg";

    function eyeIcon(open) {
        var svg = document.createElementNS(SVG_NS, "svg");
        svg.setAttribute("viewBox", "0 0 24 24");
        svg.setAttribute("width", "18");
        svg.setAttribute("height", "18");
        svg.setAttribute("fill", "none");
        svg.setAttribute("stroke", "currentColor");
        svg.setAttribute("stroke-width", "1.8");
        svg.setAttribute("stroke-linecap", "round");
        svg.setAttribute("stroke-linejoin", "round");
        svg.setAttribute("aria-hidden", "true");
        var eye = document.createElementNS(SVG_NS, "path");
        eye.setAttribute("d", "M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z");
        svg.appendChild(eye);
        var pupil = document.createElementNS(SVG_NS, "circle");
        pupil.setAttribute("cx", "12");
        pupil.setAttribute("cy", "12");
        pupil.setAttribute("r", "3");
        svg.appendChild(pupil);
        if (!open) {
            // 斜杠 = 「当前是明文,点一下藏起来」。
            var slash = document.createElementNS(SVG_NS, "path");
            slash.setAttribute("d", "M4 4l16 16");
            svg.appendChild(slash);
        }
        return svg;
    }

    function setToggleState(btn, visible) {
        var label = visible ? (msgHidePw || "Hide password") : (msgShowPw || "Show password");
        btn.setAttribute("aria-label", label);
        btn.setAttribute("title", label);
        btn.setAttribute("aria-pressed", visible ? "true" : "false");
        while (btn.firstChild) btn.removeChild(btn.firstChild);
        btn.appendChild(eyeIcon(!visible));
    }

    function enhancePasswordInputs() {
        var inputs = document.querySelectorAll('input[type="password"]');
        for (var i = 0; i < inputs.length; i++) {
            var input = inputs[i];
            if (!input.parentNode || input.parentNode.classList.contains("pw-wrap")) continue;
            var wrap = document.createElement("span");
            wrap.className = "pw-wrap";
            input.parentNode.insertBefore(wrap, input);
            wrap.appendChild(input);
            var btn = document.createElement("button");
            btn.type = "button";
            btn.className = "pw-toggle";
            btn.tabIndex = -1; // 不抢 Tab 顺序:密码框 → 下一个字段;鼠标/触屏点它即可。
            setToggleState(btn, false);
            wrap.appendChild(btn);
        }
    }

    document.addEventListener("click", function (e) {
        var t = e.target;
        if (!t || !t.closest) return;
        var btn = t.closest(".pw-toggle");
        if (!btn) return;
        e.preventDefault();
        var input = btn.parentNode && btn.parentNode.querySelector("input");
        if (!input) return;
        var show = input.type === "password";
        input.type = show ? "text" : "password";
        setToggleState(btn, show);
        // 切换后把焦点还给输入框,光标留在末尾,继续打字不打断。
        try {
            input.focus({ preventScroll: true });
            var n = input.value.length;
            input.setSelectionRange(n, n);
        } catch (_) { /* 某些浏览器对 type=password 不支持 setSelectionRange,忽略 */ }
    });

    // footer 里以 defer 引入,执行时 DOM 已就绪;保险起见两种情形都接住。
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", enhancePasswordInputs);
    } else {
        enhancePasswordInputs();
    }

    // ---- 提交委托:拨号 host 探测的进度提示 / 超时兜底 ------------------------
    // 复刻 dashboard 横幅 + settings 页原 onsubmit 行为:提交后禁用按钮防重复提交、
    // 改文案为「检测中…」;可选:显示进度元素;可选:N 毫秒后仍未离开本页(server hang)
    // 则改文案为「无响应」并显示逃生链接。JS 未加载时表单照常提交,仅无进度反馈(渐进增强)。
    document.addEventListener("submit", function (e) {
        var form = e.target;
        if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-progress-form")) {
            return;
        }
        var btnSel = form.getAttribute("data-progress-btn");
        var btn = btnSel
            ? document.querySelector(btnSel)
            : form.querySelector('button[type="submit"], button');
        var probing = form.getAttribute("data-progress-text");
        if (btn) {
            btn.disabled = true;
            if (probing) btn.textContent = probing;
        }
        var showSel = form.getAttribute("data-progress-show");
        if (showSel) {
            var showEl = document.querySelector(showSel);
            if (showEl) showEl.style.display = "inline";
        }
        var toText = form.getAttribute("data-progress-timeout-text");
        var toShow = form.getAttribute("data-progress-timeout-show");
        var toMs = parseInt(form.getAttribute("data-progress-timeout-ms") || "0", 10);
        if (toMs > 0 && (toText || toShow)) {
            setTimeout(function () {
                // 仍 disabled = 仍在本页(未跳转)= server 无响应,才提示逃生。
                if (btn && btn.disabled) {
                    if (toText) btn.textContent = toText;
                    if (toShow) {
                        var l = document.querySelector(toShow);
                        if (l) l.style.display = "inline";
                    }
                }
            }, toMs);
        }
    });
})();
