/*
 * pow_solver.js — 浏览器端登录页前置 PoW(自适应难度)解题器。
 *
 * 约束 / 设计
 * -----------
 * 1) **纯 JS 同步 SHA-256** + setTimeout 切片。
 *    试过 crypto.subtle.digest(异步) — 每次 await 一个 microtask ~50μs,
 *    14-bit 平均 16K 次 → 800ms+;反而比同步纯 JS(~3μs/hash,V8 jit 后)
 *    慢。同步 + setTimeout 让事件循环每 50ms 喘一次,UI 不卡死。
 *
 * 2) 算法与服务端 nanotun-web/pow.go 完全一致:
 *      preimage = UTF8(challenge_id) || 0x00 || salt(16B) || BE_uint64(nonce)
 *      合法当且仅当 SHA256(preimage) 前导零比特数 >= difficulty
 *    challenge_id 是字符串,**不**做 base64 decode 直接 UTF8 编码;salt 是
 *    base64 std,要 atob 还原 16 字节。
 *
 * 3) **按钮策略**:页面加载即 disable 提交按钮,解出 nonce 后写入
 *    #pow-nonce 并 enable 按钮。模板里没有 PoW 时本脚本根本不会被
 *    include,按钮天然可点 — 所以脚本里 disable 是安全的(只在需要 PoW
 *    时执行)。
 *
 * 4) 进度提示:每 500ms 更新一次 #pow-status,显示已尝试次数 + H/s。
 *    用户看得到进度,不会以为页面卡死。
 *
 * 5) 整段 IIFE,没有全局污染。
 */

(function () {
    'use strict';

    // ===== 通用工具 =====

    function $(id) { return document.getElementById(id); }

    // base64 std → Uint8Array(16)。salt 长度必然 16,出错就报警(服务端保证)。
    function b64ToBytes(b64) {
        var bin = atob(b64);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    // UTF-8 编码,模板里 challenge_id 是 base64url 字符串(ASCII),
    // 但用统一编码器更安全(以后改格式不破坏)。
    var utf8Enc = (typeof TextEncoder !== 'undefined') ? new TextEncoder() : null;
    function utf8Bytes(s) {
        if (utf8Enc) return utf8Enc.encode(s);
        // 老浏览器回退:只支持 ASCII(challenge_id 实际上都是 ASCII,够用)。
        var out = new Uint8Array(s.length);
        for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
        return out;
    }

    // 数 digest 前导零比特数(从最高字节最高位开始)。
    function leadingZeroBits(digest) {
        var n = 0;
        for (var i = 0; i < digest.length; i++) {
            var b = digest[i];
            if (b === 0) { n += 8; continue; }
            for (var bit = 7; bit >= 0; bit--) {
                if ((b & (1 << bit)) === 0) n++;
                else return n;
            }
            return n;
        }
        return n;
    }

    // ===== SHA-256(基于 RFC 6234 / FIPS 180-4) =====
    //
    // 实现选择:单输入接口 sha256(bytesUint8Array) → Uint8Array(32)。
    // 不做 streaming 接口,每次完整 hash —— PoW 每次 nonce 都重算 64 字节
    // preimage(challenge_id 几十字节 + 0x00 + 16 + 8),固定走一次。
    //
    // 性能基准(M2 / Chrome 122):~3μs/hash(60B 输入,1 个 SHA256 block);
    //   14-bit 平均 ~50ms,18-bit ~1s,22-bit ~16s。
    //
    // 实现尽量避免 alloc / 函数调用开销:
    //   - K[] / H0[] 顶层 const
    //   - W[] 复用 typed array(每次 hash 新建一个 — 实测 V8 escape analysis
    //     能把它当 stack alloc,反复 new 不慢)
    //   - 内层用 |0 强制 int32 让 V8 走 SMI 快路径

    var K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);

    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

    // 把输入 bytes 按 SHA-256 padding 规则补齐到 64B 的倍数,返回 Uint8Array。
    // 长度上限按 PoW preimage 通常 60-80 字节考虑,这里也支持任意长度。
    function padInput(bytes) {
        var l = bytes.length;
        // 至少补 1 字节 0x80 + 8 字节长度;块长 64。
        var padLen = 64 - ((l + 9) % 64);
        if (padLen === 64) padLen = 0;
        var totalLen = l + 1 + padLen + 8;
        var out = new Uint8Array(totalLen);
        out.set(bytes, 0);
        out[l] = 0x80;
        // 8 字节大端长度(单位:bit);PoW preimage 长度远小于 2^32,
        // 高 4 字节恒为 0 — 但还是按规范完整写 8B。
        var bitLen = l * 8;
        // 高位 4 字节(JS 数值精度上 l < 2^29 才安全;PoW 用例下绝对安全)
        var view = new DataView(out.buffer);
        view.setUint32(totalLen - 8, Math.floor(bitLen / 0x100000000));
        view.setUint32(totalLen - 4, bitLen >>> 0);
        return out;
    }

    function sha256(bytes) {
        var padded = padInput(bytes);
        var H = new Uint32Array([
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        ]);
        var W = new Uint32Array(64);
        var view = new DataView(padded.buffer);

        for (var block = 0; block < padded.length; block += 64) {
            for (var i = 0; i < 16; i++) {
                W[i] = view.getUint32(block + i * 4);
            }
            for (var i = 16; i < 64; i++) {
                var s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
                var s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
                W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
            }
            var a = H[0], b = H[1], c = H[2], d = H[3];
            var e = H[4], f = H[5], g = H[6], h = H[7];
            for (var i = 0; i < 64; i++) {
                var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
                var ch = (e & f) ^ (~e & g);
                var t1 = (h + S1 + ch + K[i] + W[i]) | 0;
                var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
                var mj = (a & b) ^ (a & c) ^ (b & c);
                var t2 = (S0 + mj) | 0;
                h = g; g = f; f = e; e = (d + t1) | 0;
                d = c; c = b; b = a; a = (t1 + t2) | 0;
            }
            H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0;
            H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
            H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0;
            H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
        }

        var out = new Uint8Array(32);
        var oView = new DataView(out.buffer);
        for (var i = 0; i < 8; i++) oView.setUint32(i * 4, H[i]);
        return out;
    }

    // ===== solver 主循环 =====

    function solve(challengeID, saltB64, difficulty, onProgress, onDone) {
        var cidBytes = utf8Bytes(challengeID);
        var salt = b64ToBytes(saltB64);
        if (salt.length !== 16) {
            onDone(new Error('salt length != 16'), null);
            return;
        }
        // 预拼 preimage 的固定前缀:cid || 0x00 || salt;nonce 8B 在结尾。
        var preimage = new Uint8Array(cidBytes.length + 1 + 16 + 8);
        preimage.set(cidBytes, 0);
        preimage[cidBytes.length] = 0;
        preimage.set(salt, cidBytes.length + 1);
        var nonceOffset = cidBytes.length + 1 + 16;
        var nonceView = new DataView(preimage.buffer, nonceOffset, 8);

        // JS 数值精度限制:nonce 用 [hi, lo] 两个 uint32 模拟 BE uint64;
        // 自增时 lo 溢出再加 hi。PoW 用例下平均 2^difficulty 次,22-bit
        // 也才 4M 次,lo 永远不会溢出 — 但保留 hi 兼容理论极端难度。
        var nonceHi = 0, nonceLo = 0;
        var startTime = performance.now();
        var lastTick = startTime;
        var triedThisTick = 0;

        function chunk() {
            var deadline = performance.now() + 30; // 30ms 一片,留 UI 余量
            while (performance.now() < deadline) {
                // 批量 1000 次再查时间,减少 performance.now() 调用频率。
                for (var k = 0; k < 1000; k++) {
                    nonceView.setUint32(0, nonceHi);
                    nonceView.setUint32(4, nonceLo);
                    var h = sha256(preimage);
                    if (leadingZeroBits(h) >= difficulty) {
                        var nonceStr = nonceHi === 0
                            ? '' + nonceLo
                            : (BigInt(nonceHi) * 4294967296n + BigInt(nonceLo)).toString();
                        onDone(null, {
                            nonce: nonceStr,
                            tried: (nonceHi * 4294967296) + nonceLo + 1,
                            elapsedMs: performance.now() - startTime,
                        });
                        return;
                    }
                    triedThisTick++;
                    nonceLo = (nonceLo + 1) >>> 0;
                    if (nonceLo === 0) nonceHi = (nonceHi + 1) >>> 0;
                }
            }
            var now = performance.now();
            if (now - lastTick > 500) {
                var total = (nonceHi * 4294967296) + nonceLo;
                var hps = triedThisTick / ((now - lastTick) / 1000);
                onProgress({ tried: total, hps: hps, elapsedMs: now - startTime });
                lastTick = now;
                triedThisTick = 0;
            }
            // 让事件循环喘 5ms — setTimeout(0) 的最小延迟在多数浏览器是 ~1-4ms,
            // 给出 5ms 让 UI 渲染 / input 事件优先,后台跑也不会被掐 throttle。
            setTimeout(chunk, 5);
        }
        // 启动:用 requestAnimationFrame 让首屏渲染先完成。
        if (typeof requestAnimationFrame !== 'undefined') {
            requestAnimationFrame(chunk);
        } else {
            setTimeout(chunk, 0);
        }
    }

    // ===== 入口:DOMContentLoaded 后接管 #pow-status =====

    function start() {
        var status = $('pow-status');
        var nonceField = $('pow-nonce');
        var submitBtn = $('submit-btn');
        if (!status || !nonceField || !submitBtn) return;

        var diff = parseInt(status.getAttribute('data-difficulty'), 10) || 0;
        var cid = document.querySelector('input[name="pow_challenge_id"]').value;
        var salt = document.querySelector('input[name="pow_salt"]').value;
        if (!cid || !salt || diff <= 0) return;

        // i18n:文案由模板按当前语言写进 data-i18n-* 属性(模板才知道语言);
        // 缺失时回落中文默认,保证本静态脚本单独也能工作。
        function msg(name, fallback) {
            var v = status.getAttribute('data-i18n-' + name);
            return (v !== null && v !== '') ? v : fallback;
        }
        var T = {
            verifying: msg('verifying', '安全验证中…'),
            progress: msg('progress', '安全验证中…(已尝试 {tried} 次,约 {hps} kH/s,难度 {diff}-bit)'),
            failPre: msg('fail-pre', '安全验证失败:'),
            failMid: msg('fail-mid', ',请'),
            failRefresh: msg('fail-refresh', '刷新页面'),
            failPost: msg('fail-post', '重试'),
            done: msg('done', '验证完成({tried} 次,耗时 {elapsed}s)'),
            login: msg('login', '登录'),
        };
        function fill(tpl, vars) {
            return tpl.replace(/\{(\w+)\}/g, function (m, k) {
                return Object.prototype.hasOwnProperty.call(vars, k) ? vars[k] : m;
            });
        }

        submitBtn.disabled = true;
        submitBtn.textContent = T.verifying;

        solve(cid, salt, diff,
            function (p) {
                var hps = (p.hps / 1000).toFixed(1);
                status.textContent = fill(T.progress, {
                    tried: p.tried.toLocaleString(),
                    hps: hps,
                    diff: diff,
                });
            },
            function (err, res) {
                if (err) {
                    status.innerHTML =
                        '<span style="color:#c0392b">' + T.failPre + err.message +
                        T.failMid + '<a href="/login">' + T.failRefresh + '</a>' + T.failPost + '</span>';
                    return;
                }
                nonceField.value = res.nonce;
                submitBtn.disabled = false;
                submitBtn.textContent = T.login;
                status.textContent = fill(T.done, {
                    tried: res.tried.toLocaleString(),
                    elapsed: (res.elapsedMs / 1000).toFixed(2),
                });
            }
        );
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
