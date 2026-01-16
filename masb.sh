#!/bin/sh
set -eu

#################################
# utils
#################################
need_cmd() { command -v "$1" >/dev/null 2>&1; }
rand_hex() { hexdump -vn "$1" -e '1/1 "%02x"' /dev/urandom; }
die() { echo "[x] $*" >&2; exit 1; }

gen_uuid() {
  a=$(rand_hex 4); b=$(rand_hex 2); c=$(rand_hex 2)
  d=$(rand_hex 2); e=$(rand_hex 6)
  printf "%s-%s-4%s-8%s-%s\n" "$a" "$b" "${c#?}" "${d#?}" "$e"
}

prompt() {
  var="$1"; text="$2"; def="${3:-}"
  printf "%s [%s]: " "$text" "$def"
  read -r v || true
  [ -z "$v" ] && v="$def"
  eval "$var=\$v"
}

yesno() {
  v="$(printf "%s" "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [ "$v" = "y" ] || [ "$v" = "yes" ]
}

urlencode() { printf "%s" "$1" | jq -sRr @uri; }

#################################
# 公网 IP 检测（强制）
#################################
is_private_ip4() {
  case "$1" in
    10.*|127.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*|169.254.*|0.*) return 0 ;;
  esac
  return 1
}

get_public_ip4() {
  for u in https://api.ipify.org https://ipv4.icanhazip.com https://ifconfig.co/ip; do
    ip="$(curl -4 -fsSL --max-time 4 "$u" 2>/dev/null | tr -d '\r\n ' || true)"
    printf "%s" "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || continue
    is_private_ip4 "$ip" && continue
    echo "$ip"; return 0
  done
  return 1
}

get_public_ip6() {
  for u in https://api64.ipify.org https://ipv6.icanhazip.com https://ifconfig.co/ip; do
    ip="$(curl -6 -fsSL --max-time 4 "$u" 2>/dev/null | tr -d '\r\n ' || true)"
    printf "%s" "$ip" | grep -q ':' || continue
    echo "$ip"; return 0
  done
  return 1
}

detect_public_ips_strict() {
  PUB4="$(get_public_ip4 || true)"
  PUB6="$(get_public_ip6 || true)"

  echo "---- 公网出口检测 ----"
  [ -n "$PUB4" ] && echo "[+] IPv4：$PUB4" || echo "[-] IPv4：不可用"
  [ -n "$PUB6" ] && echo "[+] IPv6：$PUB6" || echo "[-] IPv6：不可用"
  echo "----------------------"

  [ -n "$PUB4" ] || [ -n "$PUB6" ] || die "未检测到 IPv4 或 IPv6 公网出口，终止部署"
}

#################################
# sing-box 安装（稳健）
#################################
install_singbox() {
  apk add --no-cache ca-certificates curl jq openssl >/dev/null

  need_cmd sing-box && return

  apk add --no-cache sing-box >/dev/null 2>&1 && return

  apk add --no-cache \
    --repository=https://dl-cdn.alpinelinux.org/alpine/edge/community \
    sing-box >/dev/null 2>&1 && return

  ARCH="$(apk --print-arch)"
  case "$ARCH" in
    x86_64) GOARCH=amd64 ;;
    aarch64) GOARCH=arm64 ;;
    armv7) GOARCH=armv7 ;;
    *) die "不支持架构: $ARCH" ;;
  esac

  JSON="$(curl -fsSL https://api.github.com/repos/SagerNet/sing-box/releases/latest)"
  URL="$(echo "$JSON" | jq -r --arg a "$GOARCH" '
    .assets[].browser_download_url
    | select(test("linux";"i"))
    | select(test($a;"i"))
    | select(test("musl|static|alpine";"i"))
    | select(endswith(".tar.gz"))
  ' | head -n1)"

  [ -n "$URL" ] || die "无法找到 sing-box release"

  tmp="$(mktemp -d)"
  curl -fL "$URL" -o "$tmp/sb.tgz"
  tar -xzf "$tmp/sb.tgz" -C "$tmp"
  install -m 0755 "$(find "$tmp" -name sing-box -type f | head -n1)" /usr/bin/sing-box
}

#################################
# main
#################################
[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

install_singbox
detect_public_ips_strict

mkdir -p /etc/sing-box /var/log/sing-box

# Reality
POOL="www.cloudflare.com www.apple.com www.microsoft.com www.google.com www.youtube.com"
REALITY_SERVER="$(printf "%s\n" $POOL | shuf | head -n1)"

# TLS（自签，示例简化）
TLS_SNI="example.com"
CERT="/etc/sing-box/cert.pem"
KEY="/etc/sing-box/key.pem"
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$KEY" -out "$CERT" -subj "/CN=${TLS_SNI}" >/dev/null 2>&1

UUID="$(gen_uuid)"
SHORT_ID="$(rand_hex 4)"
HY2_P1="$(rand_hex 16)"
HY2_P2="$(rand_hex 16)"

KP="$(sing-box generate reality-keypair)"
R_PRIV="$(echo "$KP" | sed -n 's/.*Private.*: *//p')"
R_PUB="$(echo "$KP" | sed -n 's/.*Public.*: *//p')"

cat > /etc/sing-box/config.json <<EOF
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "vless",
      "listen_port": 443,
      "users": [{ "uuid": "$UUID", "flow": "xtls-rprx-vision" }],
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "private_key": "$R_PRIV",
          "short_id": ["$SHORT_ID"],
          "handshake": { "server": "$REALITY_SERVER", "server_port": 443 }
        }
      }
    },
    {
      "type": "hysteria2",
      "listen_port": 8443,
      "users": [{ "password": "$HY2_P1" }],
      "tls": { "enabled": true, "certificate_path": "$CERT", "key_path": "$KEY" }
    },
    {
      "type": "hysteria2",
      "listen_port": 9443,
      "users": [{ "password": "$HY2_P2" }],
      "tls": { "enabled": true, "certificate_path": "$CERT", "key_path": "$KEY" }
    }
  ],
  "outbounds": [{ "type": "direct" }]
}
EOF

# PUBLIC_HOST 自动选择
if [ -n "$PUB4" ]; then
  PUBLIC_HOST="$PUB4"
else
  PUBLIC_HOST="[$PUB6]"
fi

echo "---- v2rayN ----"
echo "vless://${UUID}@${PUBLIC_HOST}:443?security=reality&sni=${REALITY_SERVER}&pbk=${R_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision"
echo "hysteria2://${HY2_P1}@${PUBLIC_HOST}:8443?insecure=1"
echo "hysteria2://${HY2_P2}@${PUBLIC_HOST}:9443?insecure=1"
