#!/bin/sh
# ============================================================
# masb.sh (Alpine) - sing-box server installer (musl)
# ------------------------------------------------------------
# 目标：
#   1) VLESS + Reality (主用，抗封锁)
#   2) VLESS + TLS     (备用，兼容性强)
#   3) Hysteria2       (UDP，高速)
#
# 特性：
#   - 强制检测公网 IPv4/IPv6：至少一个可用，否则退出
#   - sing-box 稳健安装：当前仓库 -> edge/community -> GitHub release(musl/static)
#   - Reality keypair 落盘并做一致性校验，避免 pbk/private 不匹配导致 invalid connection
#   - 端口：可输入 / 回车随机（10000-64536）
#   - PUBLIC_HOST 不询问：自动选择 IPv4 > IPv6（IPv6 自动加 []）
#   - 输出 v2rayN 可导入链接（3条）
#
# 说明：
#   - 本脚本默认给 VLESS-TLS/HY2 使用自签证书（insecure=1），便于直接可用
#   - Reality 的 sni 必须等于 handshake.server（脚本已强制一致）
#
# 使用：
#   bash <(curl -Ls https://raw.githubusercontent.com/hooghub/Alpine/main/masb.sh)
# ============================================================

set -eu

#################################
# ===== 基础工具函数 =====
#################################
need_cmd() { command -v "$1" >/dev/null 2>&1; }
die() { echo "[x] $*" >&2; exit 1; }

rand_hex() { hexdump -vn "$1" -e '1/1 "%02x"' /dev/urandom; }
urlencode() { printf "%s" "$1" | jq -sRr @uri; }

gen_uuid() {
  # 简单生成一个 v4 风格 UUID（足够用于 VLESS）
  a=$(rand_hex 4); b=$(rand_hex 2); c=$(rand_hex 2)
  d=$(rand_hex 2); e=$(rand_hex 6)
  printf "%s-%s-4%s-8%s-%s\n" "$a" "$b" "${c#?}" "${d#?}" "$e"
}

prompt() {
  # 用法：prompt VAR "提示" "默认值"
  var="$1"; text="$2"; def="${3:-}"
  if [ -n "$def" ]; then printf "%s [%s]: " "$text" "$def"; else printf "%s: " "$text"; fi
  read -r val || true
  [ -z "$val" ] && val="$def"
  eval "$var=\$val"
}

#################################
# ===== 端口选择：可输入/可随机 =====
#################################
rand_port() {
  # 10000-64536，避免常用端口
  if [ -n "${RANDOM:-}" ]; then
    echo $((10000 + RANDOM % 64536))
  else
    n="$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')"
    echo $((10000 + n % 64536))
  fi
}

pick_port() {
  # 用法：pick_port VAR "名称"
  var="$1"; label="$2"
  prompt "$var" "$label 端口（回车=随机）" ""
  eval "p=\${$var:-}"
  if [ -z "$p" ]; then
    p="$(rand_port)"
    echo "[i] $label 随机端口：$p"
  fi
  case "$p" in
    ''|*[!0-9]*) die "$label 端口非法：$p" ;;
  esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || die "$label 端口超出范围：$p"
  eval "$var=\$p"
}

#################################
# ===== 公网 IPv4/IPv6 检测（强制）=====
#################################
is_private_ip4() {
  ip="$1"
  case "$ip" in
    10.*|127.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|169.254.*|0.*) return 0 ;;
  esac
  return 1
}

get_public_ip4() {
  for u in \
    "https://api.ipify.org" \
    "https://ipv4.icanhazip.com" \
    "https://ifconfig.co/ip"
  do
    ip="$(curl -4 -fsSL --max-time 4 "$u" 2>/dev/null | tr -d '\r\n ' || true)"
    printf "%s" "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || continue
    is_private_ip4 "$ip" && continue
    echo "$ip"; return 0
  done
  return 1
}

get_public_ip6() {
  for u in \
    "https://api64.ipify.org" \
    "https://ipv6.icanhazip.com" \
    "https://ifconfig.co/ip"
  do
    ip="$(curl -6 -fsSL --max-time 4 "$u" 2>/dev/null | tr -d '\r\n ' || true)"
    printf "%s" "$ip" | grep -q ':' || continue
    echo "$ip"; return 0
  done
  return 1
}

detect_public_ips_strict() {
  PUB4="$(get_public_ip4 2>/dev/null || true)"
  PUB6="$(get_public_ip6 2>/dev/null || true)"

  echo
  echo "---- 公网出口检测（强制）----"
  [ -n "$PUB4" ] && echo "[+] IPv4：$PUB4" || echo "[-] IPv4：不可用"
  [ -n "$PUB6" ] && echo "[+] IPv6：$PUB6" || echo "[-] IPv6：不可用"
  echo "----------------------------"

  [ -n "$PUB4" ] || [ -n "$PUB6" ] || die "未检测到 IPv4 或 IPv6 公网出口，终止部署"
}

#################################
# ===== sing-box 安装（稳健）=====
#################################
install_singbox() {
  # 基础依赖：curl/jq/openssl
  apk add --no-cache ca-certificates curl jq openssl >/dev/null

  # 1) 当前仓库
  if need_cmd sing-box; then return 0; fi
  echo "[i] Try: apk add sing-box (current repos)"
  if apk add --no-cache sing-box >/dev/null 2>&1; then return 0; fi

  # 2) edge/community（临时仓库，不污染 /etc/apk/repositories）
  EDGE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/edge/community"
  echo "[i] Try: apk add sing-box (edge/community)"
  if apk add --no-cache --repository="$EDGE_COMMUNITY" sing-box >/dev/null 2>&1; then return 0; fi

  # 3) GitHub release fallback（musl/static 优先）
  echo "[!] apk install failed; fallback to GitHub release (musl/static preferred)"

  APK_ARCH="$(apk --print-arch 2>/dev/null || true)"
  case "$APK_ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    armv7)   GOARCH="armv7" ;;
    x86|i686) GOARCH="386" ;;
    riscv64) GOARCH="riscv64" ;;
    *)       GOARCH="$APK_ARCH" ;;
  esac

  API="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  JSON="$(curl -fsSL "$API")"

  URL_MUSL="$(printf "%s" "$JSON" | jq -r --arg a "$GOARCH" '
    .assets[].browser_download_url
    | select(test("linux";"i"))
    | select(test($a;"i"))
    | select(test("musl|alpine|static";"i"))
    | select(endswith(".tar.gz"))
  ' | head -n1)"

  URL_ANY="$(printf "%s" "$JSON" | jq -r --arg a "$GOARCH" '
    .assets[].browser_download_url
    | select(test("linux";"i"))
    | select(test($a;"i"))
    | select(endswith(".tar.gz"))
  ' | head -n1)"

  DL_URL="$URL_MUSL"
  if [ -z "${DL_URL:-}" ] || [ "$DL_URL" = "null" ]; then
    DL_URL="$URL_ANY"
  fi
  [ -n "${DL_URL:-}" ] && [ "$DL_URL" != "null" ] || die "Cannot find sing-box asset for GOARCH=$GOARCH"

  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  curl -fL "$DL_URL" -o "$tmp/sing-box.tgz"
  tar -xzf "$tmp/sing-box.tgz" -C "$tmp"

  BIN="$(find "$tmp" -type f -name sing-box -perm -111 | head -n1 || true)"
  [ -n "$BIN" ] || die "sing-box binary not found in archive"

  install -m 0755 "$BIN" /usr/local/bin/sing-box
  ln -sf /usr/local/bin/sing-box /usr/bin/sing-box 2>/dev/null || true
}

#################################
# ===== Reality：伪装站随机池 + keypair 落盘 =====
#################################
pick_random() {
  awk 'BEGIN{srand()} {a[NR]=$0} END{ if(NR>0) print a[int(rand()*NR)+1] }'
}

choose_reality_handshake() {
  # 你以后想扩充池子，就在这里加域名
  POOL="$(cat <<'EOF'
www.cloudflare.com
www.apple.com
www.google.com
www.gstatic.com
www.bing.com
www.wikipedia.org
www.netflix.com
www.microsoft.com
www.yahoo.com
EOF
)"
  echo
  echo "Reality 伪装站：回车=随机从池里选；也可以手动输入域名"
  echo "$POOL" | sed 's/^/  - /'
  prompt REALITY_HANDSHAKE_SERVER "伪装目标域名" ""
  if [ -z "${REALITY_HANDSHAKE_SERVER:-}" ]; then
    REALITY_HANDSHAKE_SERVER="$(printf "%s\n" "$POOL" | pick_random)"
    echo "[+] 已随机选择：$REALITY_HANDSHAKE_SERVER"
  fi
  REALITY_HANDSHAKE_PORT="443"

  # 关键：客户端 sni 必须等于服务端 handshake.server（脚本强制一致）
  REALITY_CLIENT_SNI="$REALITY_HANDSHAKE_SERVER"
}

generate_reality_keypair_persist() {
  # 每次部署都生成新对，避免历史残留导致 pbk/private 不一致
  mkdir -p /etc/sing-box
  KEY_PRIV_FILE="/etc/sing-box/reality_private_key.txt"
  KEY_PUB_FILE="/etc/sing-box/reality_public_key.txt"

  KP="$(sing-box generate reality-keypair 2>/dev/null || true)"
  REALITY_PRIV="$(printf "%s\n" "$KP" | sed -n 's/^PrivateKey: *//p' | head -n1)"
  REALITY_PUB="$(printf "%s\n" "$KP" | sed -n 's/^PublicKey: *//p' | head -n1)"

  [ -n "${REALITY_PRIV:-}" ] && [ -n "${REALITY_PUB:-}" ] || {
    echo "[x] Reality keypair 解析失败，sing-box 输出如下："
    echo "$KP"
    exit 1
  }

  echo "$REALITY_PRIV" > "$KEY_PRIV_FILE"
  echo "$REALITY_PUB"  > "$KEY_PUB_FILE"
  chmod 600 "$KEY_PRIV_FILE" "$KEY_PUB_FILE"

  echo "[i] Reality keypair 已保存："
  echo "    $KEY_PRIV_FILE"
  echo "    $KEY_PUB_FILE"
}

#################################
# ===== TLS 证书（自签，供 VLESS-TLS / HY2 共用）=====
#################################
make_self_signed_cert() {
  # 用法：make_self_signed_cert SNI CERT KEY FULLCHAIN
  SNI="$1"
  CERT_PATH="$2"
  KEY_PATH="$3"
  FULLCHAIN_PATH="$4"

  mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")" "$(dirname "$FULLCHAIN_PATH")"

  # 含 SAN，降低客户端兼容性问题
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY_PATH" -out "$CERT_PATH" \
    -subj "/CN=${SNI}" \
    -addext "subjectAltName=DNS:${SNI}" >/dev/null 2>&1

  cp -f "$CERT_PATH" "$FULLCHAIN_PATH"
}

#################################
# ===== OpenRC 服务 =====
#################################
ensure_openrc_service() {
  RC_FILE="/etc/init.d/sing-box"
  if [ ! -f "$RC_FILE" ]; then
    cat > "$RC_FILE" <<'RC_EOF'
#!/sbin/openrc-run
name="sing-box"
description="sing-box service"
command="/usr/bin/sing-box"
command_args="run -c /etc/sing-box/config.json"
command_background="yes"
pidfile="/run/sing-box.pid"
output_log="/var/log/sing-box/sing-box.log"
error_log="/var/log/sing-box/sing-box.err"
depend() { need net; }
RC_EOF
    chmod +x "$RC_FILE"
  fi
  rc-update add sing-box default >/dev/null 2>&1 || true
}

#################################
# ===== 一致性校验：拒绝输出“错链接” =====
#################################
sanity_check_reality_consistency() {
  # config private_key 必须等于落盘 priv，否则说明中途被改了
  CONF_PRIV="$(grep -oE '"private_key":[[:space:]]*"[^"]+"' /etc/sing-box/config.json | head -n1 | cut -d'"' -f4)"
  [ -n "$CONF_PRIV" ] || die "sanity: config private_key not found"

  DISK_PRIV="$(cat /etc/sing-box/reality_private_key.txt 2>/dev/null || true)"
  DISK_PUB="$(cat /etc/sing-box/reality_public_key.txt 2>/dev/null || true)"
  [ -n "$DISK_PRIV" ] && [ -n "$DISK_PUB" ] || die "sanity: reality key files missing"

  if [ "$CONF_PRIV" != "$DISK_PRIV" ]; then
    echo "[x] 配置文件 private_key 与落盘 priv 不一致，拒绝输出错误链接"
    echo "    config: $CONF_PRIV"
    echo "    disk:   $DISK_PRIV"
    exit 1
  fi
}

#################################
# ===============================
# ============ main ============
# ===============================
#################################
[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

install_singbox
apk add --no-cache jq openssl >/dev/null

detect_public_ips_strict

# 目录准备
mkdir -p /etc/sing-box /etc/sing-box/tls /var/log/sing-box

#################################
# ===== 端口输入/随机 =====
# 你以后想固定端口，把下面三个变量直接写死即可
#################################
echo
pick_port VLESS_REALITY_PORT "VLESS Reality"
pick_port VLESS_TLS_PORT     "VLESS TLS"
pick_port HY2_PORT           "Hysteria2"

#################################
# ===== Reality 参数 =====
#################################
choose_reality_handshake
generate_reality_keypair_persist

# 读取落盘 keypair（单一事实来源）
REALITY_PRIV="$(cat /etc/sing-box/reality_private_key.txt)"
REALITY_PUB="$(cat /etc/sing-box/reality_public_key.txt)"

#################################
# ===== 账号/密码 =====
#################################
UUID="$(gen_uuid)"
SHORT_ID="$(rand_hex 4)"          # Reality sid（8 hex）
HY2_PASSWORD="$(rand_hex 16)"     # HY2 密码（一个即可）

#################################
# ===== TLS（自签，供 VLESS-TLS/HY2）=====
#################################
TLS_SNI="example.com"   # 以后要换成域名就改这里（或接入 LE）
TLS_CERT="/etc/sing-box/tls/cert.pem"
TLS_KEY="/etc/sing-box/tls/key.pem"
TLS_FULLCHAIN="/etc/sing-box/tls/fullchain.pem"
make_self_signed_cert "$TLS_SNI" "$TLS_CERT" "$TLS_KEY" "$TLS_FULLCHAIN"
TLS_INSECURE="1"        # 自签必须 insecure=1

#################################
# ===== sing-box 配置写入 =====
# 重点：VLESS-REALITY / VLESS-TLS / HY2 三个入站
#################################
CONFIG_PATH="/etc/sing-box/config.json"
cat > "$CONFIG_PATH" <<EOF

{
  "log": {
    "level": "info",
    "timestamp": true,
    "output": "/var/log/sing-box/sing-box.log"
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-reality",
      "listen": "0.0.0.0",
      "listen_port": ${VLESS_REALITY_PORT},
      "users": [
        { "uuid": "${UUID}",
        "flow": ""
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${REALITY_HANDSHAKE_SERVER}",
        "reality": {
          "enabled": true,
          "handshake": { 
          "server": "${REALITY_HANDSHAKE_SERVER}",
          "server_port": 443 
          },
          "private_key": "${REALITY_PRIV}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },
    {
      "type": "vless",
      "tag": "in-vless-tls",
      "listen": "0.0.0.0",
      "listen_port": ${VLESS_TLS_PORT},
      "users": [
        { "uuid": "${UUID}" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SNI}",
        "certificate_path": "${TLS_FULLCHAIN}",
        "key_path": "${TLS_KEY}"
      }
    },
    {
      "type": "hysteria2",
      "tag": "in-hy2",
      "listen": "0.0.0.0",
      "listen_port": ${HY2_PORT},
      "users": [
        { "password": "${HY2_PASSWORD}" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SNI}",
        "certificate_path": "${TLS_FULLCHAIN}",
        "key_path": "${TLS_KEY}"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF

echo "[+] 写入配置：$CONFIG_PATH"
sing-box check -c "$CONFIG_PATH" >/dev/null

# OpenRC
ensure_openrc_service
rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || true

# 一致性校验：拒绝输出错链接
sanity_check_reality_consistency

#################################
# ===== PUBLIC_HOST 自动选择（不询问）=====
# IPv4 > IPv6（IPv6 自动加 []）
#################################
if [ -n "${PUB4:-}" ]; then
  PUBLIC_HOST="$PUB4"
else
  PUBLIC_HOST="[$PUB6]"
fi
echo "[i] 分享链接使用的地址：$PUBLIC_HOST"

#################################
# ===== v2rayN 导入链接（3条）=====
# Reality：强制完整参数，避免 v2rayN 解析差异
#################################
ENC_R_SNI="$(urlencode "$REALITY_CLIENT_SNI")"
ENC_TLS_SNI="$(urlencode "$TLS_SNI")"

VLESS_REALITY_LINK="vless://${UUID}@${PUBLIC_HOST}:${VLESS_REALITY_PORT}?type=tcp&encryption=none&security=reality&sni=${ENC_R_SNI}&insecure=${TLS_INSECURE}&fp=chrome&pbk=${REALITY_PUB}&sid=${SHORT_ID}#VLESS-Reality-${PUBLIC_HOST}"
VLESS_TLS_LINK="vless://${UUID}@${PUBLIC_HOST}:${VLESS_TLS_PORT}?type=tcp&encryption=none&security=tls&sni=${ENC_TLS_SNI}&insecure=${TLS_INSECURE}#VLESS-TLS-${PUBLIC_HOST}"
HY2_LINK="hysteria2://${HY2_PASSWORD}@${PUBLIC_HOST}:${HY2_PORT}?sni=${ENC_TLS_SNI}&insecure=${TLS_INSECURE}#HY2-${PUBLIC_HOST}"

LINKS_PATH="/etc/sing-box/v2rayn_links.txt"
printf "%s\n%s\n%s\n" "$VLESS_REALITY_LINK" "$VLESS_TLS_LINK" "$HY2_LINK" > "$LINKS_PATH"
chmod 600 "$LINKS_PATH" || true

#################################
# ===== 输出摘要 =====
#################################
echo
echo "================== 部署完成 =================="
echo "公网检测 IPv4：       ${PUB4:-无}"
echo "公网检测 IPv6：       ${PUB6:-无}"
echo
echo "---- VLESS Reality ----"
echo "端口：               ${VLESS_REALITY_PORT}"
echo "伪装目标：           ${REALITY_HANDSHAKE_SERVER}:${REALITY_HANDSHAKE_PORT}"
echo "SNI：                ${REALITY_CLIENT_SNI}"
echo "short_id(sid)：      ${SHORT_ID}"
echo "PublicKey(pbk)：     ${REALITY_PUB}"
echo
echo "---- VLESS TLS ----"
echo "端口：               ${VLESS_TLS_PORT}"
echo "SNI：                ${TLS_SNI}"
echo
echo "---- HY2 ----"
echo "端口：               ${HY2_PORT}"
echo "SNI：                ${TLS_SNI}"
echo
echo "UUID：               ${UUID}"
echo "HY2 password：       ${HY2_PASSWORD}"
echo
echo "---- v2rayN 可导入链接（3条）----"
echo "$VLESS_REALITY_LINK"
echo "$VLESS_TLS_LINK"
echo "$HY2_LINK"
echo
echo "已写入：$LINKS_PATH"
echo "服务管理：rc-service sing-box restart | stop | start"
echo "日志查看：tail -f /var/log/sing-box/sing-box.log"
echo "配置信息：singbox配置 /etc/sing-box/config.json"
echo "PrivateKey：cat /etc/sing-box/reality_private_key.txt"
echo "PublicKey ：cat /etc/sing-box/reality_public_key.txt"
echo
echo "提示：Reality 客户端建议使用 Xray-core（v2rayN 里选择 Xray-core）。"
