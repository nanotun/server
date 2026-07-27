#!/usr/bin/env python3
"""按 nanotun-web 的字模与排布参数确定性识别验证码(仅用于回归测试自动登录)。

数字色 #202028、噪点 #A0A0A8、干扰线 #707078 —— 按亮度阈值就能把数字笔画单独取出来,
再在 jitter 范围内暴力对齐 5x7 字模。
"""
import struct
import sys
import zlib

GLYPH = [
    [0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110],
    [0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110],
    [0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111],
    [0b11110, 0b00001, 0b00001, 0b01110, 0b00001, 0b00001, 0b11110],
    [0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010],
    [0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110],
    [0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110],
    [0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000],
    [0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110],
    [0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100],
]
W, H, SCALE, MARGIN, N = 130, 44, 3, 12, 4


def load(path):
    data = open(path, "rb").read()
    pos, idat, w, h, bpp = 8, b"", 0, 0, 3
    while pos < len(data):
        ln = struct.unpack(">I", data[pos:pos + 4])[0]
        typ, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + ln]
        if typ == b"IHDR":
            w, h, _, ctype = struct.unpack(">IIBB", body[:10])
            bpp = {0: 1, 2: 3, 4: 2, 6: 4}[ctype]
        elif typ == b"IDAT":
            idat += body
        pos += 12 + ln
    raw, stride, rows, prev, p = zlib.decompress(idat), w * bpp, [], bytearray(w * 3 if bpp == 3 else w * bpp), 0
    prev = bytearray(stride)
    for _ in range(h):
        ft, line = raw[p], bytearray(raw[p + 1:p + 1 + stride])
        p += 1 + stride
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b = prev[i]
            c = prev[i - bpp] if i >= bpp else 0
            if ft == 1:
                line[i] = (line[i] + a) & 0xFF
            elif ft == 2:
                line[i] = (line[i] + b) & 0xFF
            elif ft == 3:
                line[i] = (line[i] + (a + b) // 2) & 0xFF
            elif ft == 4:
                pp = a + b - c
                pa, pb, pc = abs(pp - a), abs(pp - b), abs(pp - c)
                line[i] = (line[i] + (a if (pa <= pb and pa <= pc) else (b if pb <= pc else c))) & 0xFF
        rows.append(line)
        prev = line
    return w, h, bpp, rows


def solve(path):
    w, h, bpp, rows = load(path)
    dark = [[rows[y][x * bpp] < 0x50 and rows[y][x * bpp + 1] < 0x50 for x in range(w)] for y in range(h)]
    cellW = (W - MARGIN * 2) // N
    out = ""
    for i in range(N):
        best, bestscore = "?", -1
        for jx in (-1, 0, 1):
            for jy in (-2, -1, 0, 1, 2):
                left = MARGIN + i * cellW + (cellW - 5 * SCALE) // 2 + jx
                top = (H - 7 * SCALE) // 2 + jy
                for d, g in enumerate(GLYPH):
                    score = 0
                    for row in range(7):
                        for col in range(5):
                            want = bool(g[row] & (1 << (4 - col)))
                            x, y = left + col * SCALE + 1, top + row * SCALE + 1
                            got = dark[y][x] if 0 <= y < h and 0 <= x < w else False
                            score += 1 if want == got else -1
                    if score > bestscore:
                        best, bestscore = str(d), score
        out += best
    return out


if __name__ == "__main__":
    print(solve(sys.argv[1]))
