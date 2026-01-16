#!/bin/sh
set -eu

need_cmd() { command -v "$1" >/dev/null 2>&1; }

# random hex
rand_hex() { hexdump -vn "$1" -e '1/1 "%02x"' /dev/urandom; }

# UUID v4-like (works for VLESS)
gen_uuid() {
  a=$(rand_hex 4)
  b=$(rand_hex 2)
  c=$(rand_hex 2)
  d=$(rand_hex 2)
  e=$(rand_hex 6)

  # set version-ish and variant-ish
  c="$(printf "%s" "$c" | sed 's/^\(.\)./\14/')$(printf "%s" "$c" | cut -c2-)"
  d_first="$(printf "%s" "$d" | cut -c1)"
  case "$d_first" in
    0|1|2|3) d_first=8 ;;
    4|5|6|7) d_first=9 ;;
    8|9|a|b|A|B) d_first=a ;;
    *) d_first=b ;;
  esac
  d="${d_first}$(printf "%s" "$d" | cut -c2-)"

  printf "%s-%s-%s-%s-%s\n" "$a" "$b" "$c" "$d" "$e"
}

prompt() {
  var="$1"; text="$2"; def="${3:-}"
  if [ -n "$def" ]; then
    printf "%s [%s]: " "$text" "$def"
  else
    printf "%s: " "$text"
  fi
  read -r val || true
  if [ -z "$val" ] && [ -n "$def" ]; then
    val="$def"
  fi
  eval "$var=\$val"
}

# URL-encode via jq (Alpine friendly)
urlencode() { printf "%s" "$1" | jq -sRr @uri; }

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh $0"
  exit 1
fi

apk add --no-cache ca-certificates curl jq openssl >/dev/null

# sing-box (Alpine package, runs on musl)
if ! apk info -e sing-box >/dev/null 2>&1; then
  apk add --no-cache sing-box >/dev/null
fi

if ! need_cmd sing-box; then
  echo "[!] 找不到 sing-box，请检查 apk 源"
  exit 1
fi

mkdir -p /etc/sing-box /var/log/sing-box

echo "=== 服务端参数（VLESS+Reality + 2×HY2）==="

# Ports
prompt VLESS_PORT "VLESS+Reality 监听端口" "443"
prompt HY2_1_PORT "HY2#1 监听端口" "8443"
prompt HY2_2_PORT "HY2#2 监听端口" "9443"

# Reality disguise target (handshake)
echo
echo "Reality 需要一个伪装目标（建议：大站域名 + 443）"
prompt REALITY_HANDSHAKE_SERVER "Reality handshake 目标域名" "www.cloudflare.com"
prompt REALITY_HANDSHAKE_PORT   "Reality handshake 目标端口" "443"
prompt REALITY_CLIENT_SNI       "客户端使用的 SNI（一般=目标域名）" "$REALITY_HANDSHAKE_SERVER"

# HY2 TLS
echo
echo "HY2 需要 TLS 证书：你可以填现成证书路径；不填则生成自签证书（客户端需 insecure=1）"
prompt TLS_CERT_PATH "证书 cert.pem 路径（留空=自动生成自签）" ""
prompt TLS_KEY_PATH  "私钥 key.pem 路径（留空=自动生成自签）" ""
prompt TLS_SNI       "HY2 客户端 SNI（有正规证书请填证书域名；自签随意）" "example.com"

SELF_SIGNED="0"
if [ -z "${TLS_CERT_PATH}" ] || [ -z "${TLS_KEY_PATH}" ]; then
  SELF_SIGNED="1"
  TLS_CERT_PATH="/etc/sing-box/selfsigned_cert.pem"
  TLS_KEY_PATH="/etc/sing-box/selfsigned_key.pem"
  echo "[+] 生成自签证书：$TLS_CERT_PATH / $TLS_KEY_PATH"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_KEY_PATH" -out "$TLS_CERT_PATH" -days 3650 \
    -subj "/CN=${TLS_SNI}" >/dev/null 2>&1
fi

# ===== Auto-generate secrets =====
UUID="$(gen_uuid)"
SHORT_ID="$(rand_hex 4)"     # 8 hex chars common
HY2_PASS_1="$(rand_hex 16)"
HY2_PASS_2="$(rand_hex 16)"

# ===== Reality X25519 keypair =====
REALITY_PRIV=""
REALITY_PUB=""

# Try built-in generator (depends on build)
if sing-box generate help >/dev/null 2>&1; then
  KP="$(sing-box generate reality-keypair 2>/dev/null || true)"
  REALITY_PRIV="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -n1)"
  REALITY_PUB="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]ublic.*: *//p' | head -n1)"
fi

if [ -z "${REALITY_PRIV}" ] || [ -z "${REALITY_PUB}" ]; then
  echo
  echo "[!] 未能自动生成 Reality keypair（你的 sing-box 包可能不带 'generate reality-keypair'）。"
  echo "    你可以：升级 sing-box 或手动输入已有的 Reality private/public key。"
  echo
  prompt REALITY_PRIV "请手动输入 Reality private_key（X25519）"
  prompt REALITY_PUB  "请手动输入 Reality public_key（X25519）"
fi

# ===== Build server config =====
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
      "tag": "in-vless-reality",
      "list
