✨ 功能特性
协议组合（3 入站）

VLESS + Reality（主用）

TCP + Reality

抗封锁能力强

自动生成 Reality keypair

VLESS + TLS（备用）

TCP + TLS

兼容性好

使用自签证书（客户端 insecure=1）

Hysteria2

UDP

高速传输

与 VLESS-TLS 共用证书

关键特性

✅ 强制公网出口检测

自动检测 IPv4 / IPv6

至少存在一个公网出口才会继续部署

✅ sing-box 稳健安装

当前仓库 → edge/community → GitHub Release（musl/static）

✅ Reality keypair 落盘 + 一致性校验

防止 private_key / pbk 不匹配导致 invalid connection

✅ 端口可输入 / 回车随机

随机范围：1000–65535

✅ PUBLIC_HOST 自动选择

IPv4 优先

IPv6 自动加 []

✅ 自动生成 v2rayN 可导入链接

一次生成 3 条（Reality / TLS / HY2）
'''
bash <(curl -Ls https://raw.githubusercontent.com/hooghub/Alpine/main/masb.sh)
