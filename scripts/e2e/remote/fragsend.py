#!/usr/bin/env python3
# 从客户端 A 用原始套接字(IP_HDRINCL)手工造 IPv4 分片,经隧道打到另一台客户端的 vIP,
# 供 frag-acl-drill.sh 验证「端口 deny 不能被分片绕过」这条数据面性质。
#
# 为什么不用 scapy / hping3:发版门禁跑在三台**只装了生产依赖**的真机上,不能为一条
# 断言在上面拉一堆包。Python 标准库的 socket 就够造原始 IP 头了 —— 唯一要求是 root
# (SOCK_RAW),而 e2e 的执行用户本就是 root。
#
# 用法: fragsend.py <src_vip> <dst_vip> <dport> <mode> <ipid> [reps]
#   whole      不分片的 TCP SYN(dport 落在 L4 头里,ACL 能读到 → 正常按端口规则判)
#   frag       一个数据报拆两片:
#                首片 offset0 / MF=1,带前 8 字节 TCP(源口+目的口都在这 8 字节里);
#                非首片 offset8 / MF=0,只有 TCP 尾部 —— **读不到任何端口**。
#              这是有效的绕过判据:非首片若被放行,就等于端口 deny 形同虚设。
#   frag2only  只发那枚非首片。注意:孤立非首片(没有首片相伴)会被**本机内核的
#              defrag 队列**扣住、根本发不出网卡,所以它到不了服务端 —— 对服务端而言
#              这个向量无意义,留着只是为了在文档/复算时说明这一点。用 frag 成对发。
#
# L4 校验和一律填 0:服务端的 ACL 判定只看 IP/端口五元组,不校验 TCP 校验和;而这些包
# 本就不为完成握手,只为「能不能被 ACL 拦住」。落到对端也会被其协议栈丢,不影响判定。
import socket
import struct
import sys


def _ipchk(h):
    if len(h) % 2:
        h += b"\0"
    s = sum(struct.unpack("!%dH" % (len(h) // 2), h))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def _ip_hdr(src, dst, ipid, flags_off, payload_len, proto=6):
    ver_ihl, tos, total, ttl, chk = 0x45, 0, 20 + payload_len, 64, 0
    sb, db = socket.inet_aton(src), socket.inet_aton(dst)
    base = struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ipid, flags_off, ttl, proto, chk, sb, db)
    chk = _ipchk(base)
    return struct.pack("!BBHHHBBH4s4s", ver_ihl, tos, total, ipid, flags_off, ttl, proto, chk, sb, db)


def _tcp20(sport, dport):
    seq, ack = 0x11223344, 0
    off_flags = (5 << 12) | 0x02  # data offset 5 words + SYN
    win, chk, urg = 1024, 0, 0
    return struct.pack("!HHIIHHHH", sport, dport, seq, ack, off_flags, win, chk, urg)


def main():
    if len(sys.argv) < 6:
        sys.exit(__doc__)
    src, dst, dport, mode, ipid = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5])
    reps = int(sys.argv[6]) if len(sys.argv) > 6 else 3
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    tcp = _tcp20(40000, dport)
    for _ in range(reps):
        if mode == "whole":
            s.sendto(_ip_hdr(src, dst, ipid, 0x0000, len(tcp)) + tcp, (dst, 0))
        elif mode == "frag":
            f1, f2 = tcp[:8], tcp[8:]
            s.sendto(_ip_hdr(src, dst, ipid, 0x2000, len(f1)) + f1, (dst, 0))  # MF, offset 0
            s.sendto(_ip_hdr(src, dst, ipid, 0x0001, len(f2)) + f2, (dst, 0))  # offset 8, no MF
        elif mode == "frag2only":
            f2 = tcp[8:]
            s.sendto(_ip_hdr(src, dst, ipid, 0x0001, len(f2)) + f2, (dst, 0))
        else:
            sys.exit("unknown mode: " + mode)
    print("sent mode=%s ipid=%d reps=%d dport=%d %s->%s" % (mode, ipid, reps, dport, src, dst))


if __name__ == "__main__":
    main()
