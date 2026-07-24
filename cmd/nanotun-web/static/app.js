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
 *
 * 页面各自的复制到剪贴板逻辑仍留在**带 nonce 的内联 <script>** 里(涉及 i18n 文案 +
 * 元素特定取值 + alert/prompt 降级),不在此文件。
 */
(function () {
    "use strict";

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
