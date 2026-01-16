masb.sh

Alpine Linux 下的 sing-box 一键服务端部署脚本（musl）

masb.sh 是一个面向 Alpine Linux（musl） 的 sing-box 服务端自动化安装与配置脚本，目标是 一次部署即可直接可用，并尽量避免 Reality / TLS 常见的配置错误。

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

🖥️ 支持环境

系统：Alpine Linux（推荐最新稳定版）

架构：

x86_64

aarch64

armv7

386

riscv64

初始化系统：OpenRC

🚀 使用方法
一键运行
bash <(curl -Ls https://raw.githubusercontent.com/hooghub/Alpine/main/masb.sh)


必须使用 root 用户 运行。

🔧 部署流程说明
1️⃣ 公网 IP 检测（强制）

自动检测：

IPv4（优先）

IPv6（备用）

若两者均不可用，脚本直接退出

2️⃣ 端口设置

依次设置以下端口（可直接回车随机）：

VLESS Reality

VLESS TLS

Hysteria2

3️⃣ Reality 伪装站点

可手动输入域名

或从内置池中随机选择，例如：

www.cloudflare.com

www.apple.com

www.google.com

Reality 的 sni 与 handshake.server 强制一致

4️⃣ Reality Keypair

每次部署 重新生成

落盘保存：

/etc/sing-box/reality_private_key.txt
/etc/sing-box/reality_public_key.txt


启动前进行一致性校验，防止输出错误链接

5️⃣ TLS 证书

自动生成 自签证书

用于：

VLESS + TLS

Hysteria2

客户端需设置：

insecure = 1

📂 文件与目录
/etc/sing-box/
├── config.json
├── reality_private_key.txt
├── reality_public_key.txt
├── v2rayn_links.txt
└── tls/
    ├── cert.pem
    ├── key.pem
    └── fullchain.pem

/var/log/sing-box/
├── sing-box.log
└── sing-box.err

🔗 v2rayN 导入链接

部署完成后，脚本会输出 3 条完整可用的导入链接：

VLESS + Reality

VLESS + TLS

Hysteria2

同时写入：

/etc/sing-box/v2rayn_links.txt

▶️ 服务管理（OpenRC）
rc-service sing-box start
rc-service sing-box stop
rc-service sing-box restart


设置为开机启动：

rc-update add sing-box default

📜 日志查看
tail -f /var/log/sing-box/sing-box.log

⚠️ 注意事项

Reality 客户端强烈建议使用 Xray-core

在 v2rayN 中选择 Xray-core

自签证书场景下：

insecure=1 是必须的

Reality 的：

pbk

short_id

sni

三者必须匹配，脚本已自动保证一致性

📌 设计理念

宁可部署失败，也不输出一个“看似能用但一定连不上”的配置。

这个脚本的核心目标不是“省事”，而是：

可复现

可验证

可直接导入使用
