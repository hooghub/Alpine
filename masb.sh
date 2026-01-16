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
  if [ -n "$def" ]; then printf "%s [%s]: " "$text" "$def"; else printf "%s: " "$text"; fi
  read -r val || true
  if [ -z "$val" ] && [ -n "$def" ]; then val="$def"; fi
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
prompt HY2_1_PORT  "HY2#1 监听端口" "8443"
prompt HY2_2_PORT  "HY2#2 监听端口" "9443"

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
  # 3650 days
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$TLS_KEY_PATH" -out "$TLS_CERT_PATH" -days 3650 \
    -subj "/CN=${TLS_SNI}" >/dev/null 2>&1
fi

# ===== Auto-generate secrets =====
UUID="$(gen_uuid)"
SHORT_ID="$(rand_hex 4)"          # 8 hex chars is common
HY2_PASS_1="$(rand_hex 16)"
HY2_PASS_2="$(rand_hex 16)"

# Reality X25519 keypair
# Prefer sing-box built-in generator if available; fallback to openssl (raw) is not reliable for Reality format.
REALITY_PRIV=""
REALITY_PUB=""

if sing-box help 2>/dev/null | grep -qi "generate" && sing-box generate help 2>/dev/null | grep -qi "reality"; then
  # Most sing-box builds: sing-box generate reality-keypair
  KP="$(sing-box generate reality-keypair 2>/dev/null || true)"
  # Try parse lines like: PrivateKey: xxx  PublicKey: yyy
  REALITY_PRIV="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -n1)"
  REALITY_PUB="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]ublic.*: *//p' | head -n1)"
fi

if [ -z "${REALITY_PRIV}" ] || [ -z "${REALITY_PUB}" ]; then
  echo
  echo "[!] 你的 sing-box 似乎没有 reality-keypair 生成子命令（或输出格式不同）。"
  echo "    解决方案：升级/更换 sing-box 包，确保支持 'sing-box generate reality-keypair'。"
  echo "    你也可以手动填入已有的 reality private_key / public_key。"
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
      "listen": "0.0.0.0",
      "listen_port": ${VLESS_PORT},
      "users": [
        { "uuid": "${UUID}", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "${REALITY_HANDSHAKE_SERVER}",
            "server_port": ${REALITY_HANDSHAKE_PORT}
          },
          "private_key": "${REALITY_PRIV}",
          "short_id": ["${SHORT_ID}"]
        }
      }
    },

    {
      "type": "hysteria2",
      "tag": "in-hy2-1",
      "listen": "0.0.0.0",
      "listen_port": ${HY2_1_PORT},
      "users": [
        { "password": "${HY2_PASS_1}" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SNI}",
        "certificate_path": "${TLS_CERT_PATH}",
        "key_path": "${TLS_KEY_PATH}"
      }
    },
    {
      "type": "hysteria2",
      "tag": "in-hy2-2",
      "listen": "0.0.0.0",
      "listen_port": ${HY2_2_PORT},
      "users": [
        { "password": "${HY2_PASS_2}" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SNI}",
        "certificate_path": "${TLS_CERT_PATH}",
        "key_path": "${TLS_KEY_PATH}"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ]
}
EOF

echo "[+] 写入配置：$CONFIG_PATH"
if ! sing-box check -c "$CONFIG_PATH" >/dev/null 2>&1; then
  echo "[!] 配置校验失败："
  sing-box check -c "$CONFIG_PATH" || true
  exit 1
fi

# ===== OpenRC service =====
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
rc-service sing-box restart >/dev/null 2>&1 || rc-service sing-box start >/dev/null 2>&1 || true

# ===== v2rayN links =====
# IMPORTANT: For v2rayN on Windows:
# - VLESS Reality link uses pbk + sid + sni + fp + flow
# - HY2 link uses hysteria2://pass@host:port?sni=...&insecure=...
prompt PUBLIC_HOST "对外可访问的服务器域名/IP（写到分享链接里）" ""

if [ -z "$PUBLIC_HOST" ]; then
  # best-effort: try hostname -i or public ip (no web). fallback to "YOUR_SERVER_IP"
  PUBLIC_HOST="$(hostname -i 2>/dev/null | awk '{print $1}' || true)"
  if [ -z "$PUBLIC_HOST" ]; then PUBLIC_HOST="YOUR_SERVER_IP"; fi
fi

NAME_VLESS="VLESS-Reality"
NAME_HY2_1="HY2-1"
NAME_HY2_2="HY2-2"

ENC_NAME_VLESS="$(urlencode "$NAME_VLESS")"
ENC_NAME_HY2_1="$(urlencode "$NAME_HY2_1")"
ENC_NAME_HY2_2="$(urlencode "$NAME_HY2_2")"

ENC_SNI_REALITY="$(urlencode "$REALITY_CLIENT_SNI")"
ENC_SNI_HY2="$(urlencode "$TLS_SNI")"

# VLESS Reality (common import format)
VLESS_LINK="vless://${UUID}@${PUBLIC_HOST}:${VLESS_PORT}?type=tcp&encryption=none&security=reality&sni=${ENC_SNI_REALITY}&fp=chrome&pbk=${REALITY_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${ENC_NAME_VLESS}"

# HY2 insecure handling
INSECURE="0"
if [ "$SELF_SIGNED" = "1" ]; then
  INSECURE="1"
fi

HY2_LINK_1="hysteria2://${HY2_PASS_1}@${PUBLIC_HOST}:${HY2_1_PORT}?sni=${ENC_SNI_HY2}&insecure=${INSECURE}#${ENC_NAME_HY2_1}"
HY2_LINK_2="hysteria2://${HY2_PASS_2}@${PUBLIC_HOST}:${HY2_2_PORT}?sni=${ENC_SNI_HY2}&insecure=${INSECURE}#${ENC_NAME_HY2_2}"

SUB_PATH="/etc/sing-box/v2rayn_links.txt"
printf "%s\n%s\n%s\n" "$VLESS_LINK" "$HY2_LINK_1" "$HY2_LINK_2" > "$SUB_PATH"

echo
echo "================== 部署完成 =================="
echo "服务端配置：$CONFIG_PATH"
echo
echo "---- 自动生成参数（请保存）----"
echo "UUID:             $UUID"
echo "Reality publicKey: $REALITY_PUB"
echo "Reality short_id:  $SHORT_ID"
echo "HY2#1 password:    $HY2_PASS_1"
echo "HY2#2 password:    $HY2_PASS_2"
echo
echo "---- v2rayN 可导入链接（3条）----"
echo "$VLESS_LINK"
echo "$HY2_LINK_1"
echo "$HY2_LINK_2"
echo
echo "已写入：$SUB_PATH （v2rayN 可从文件导入 / 从剪贴板导入）"
echo
echo "服务管理：rc-service sing-box restart | stop | start"
echo "日志查看：tail -f /var/log/sing-box/sing-box.log"
echo
if [ "$SELF_SIGNED" = "1" ]; then
  echo "[提示] 你使用了自签证书：HY2 链接已自动带 insecure=1（客户端允许不验证证书）"
else
  echo "[提示] 你使用了自带证书：HY2 链接为 insecure=0（客户端会验证证书）"
fi
