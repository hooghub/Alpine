#!/bin/sh
set -eu

#################################
# utils
#################################
need_cmd() { command -v "$1" >/dev/null 2>&1; }
rand_hex() { hexdump -vn "$1" -e '1/1 "%02x"' /dev/urandom; }

gen_uuid() {
  # uuid v4-like
  a=$(rand_hex 4)
  b=$(rand_hex 2)
  c=$(rand_hex 2)
  d=$(rand_hex 2)
  e=$(rand_hex 6)
  printf "%s-%s-4%s-8%s-%s\n" "$a" "$b" "${c#?}" "${d#?}" "$e"
}

prompt() {
  var="$1"; text="$2"; def="${3:-}"
  if [ -n "$def" ]; then printf "%s [%s]: " "$text" "$def"; else printf "%s: " "$text"; fi
  read -r val || true
  [ -z "$val" ] && val="$def"
  eval "$var=\$val"
}

yesno() {
  v="$(printf "%s" "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [ "$v" = "y" ] || [ "$v" = "yes" ] || [ "$v" = "1" ] || [ "$v" = "true" ]
}

urlencode() { printf "%s" "$1" | jq -sRr @uri; }

pick_random() {
  awk 'BEGIN{srand()} {a[NR]=$0} END{ if(NR>0) print a[int(rand()*NR)+1] }'
}

die() { echo "[x] $*" >&2; exit 1; }

#################################
# robust install sing-box
#################################
install_singbox() {
  apk add --no-cache ca-certificates curl jq openssl >/dev/null

  if need_cmd sing-box; then
    return 0
  fi

  echo "[i] Try: apk add sing-box (current repos)"
  if apk add --no-cache sing-box >/dev/null 2>&1; then
    return 0
  fi

  EDGE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/edge/community"
  echo "[i] Try: apk add sing-box (edge/community)"
  if apk add --no-cache --repository="$EDGE_COMMUNITY" sing-box >/dev/null 2>&1; then
    return 0
  fi

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
# install acme.sh
#################################
install_acmesh() {
  if need_cmd acme.sh; then
    return 0
  fi

  EDGE_COMMUNITY="https://dl-cdn.alpinelinux.org/alpine/edge/community"
  echo "[i] Installing acme.sh from edge/community (no repo change)"
  apk add --no-cache --repository="$EDGE_COMMUNITY" acme.sh >/dev/null 2>&1 || true

  if ! need_cmd acme.sh; then
    echo "[!] apk acme.sh failed, fallback to official installer"
    curl -fsSL https://get.acme.sh | sh
    if [ -x "$HOME/.acme.sh/acme.sh" ]; then
      ln -sf "$HOME/.acme.sh/acme.sh" /usr/local/bin/acme.sh 2>/dev/null || true
    fi
  fi

  need_cmd acme.sh || die "acme.sh install failed"
}

#################################
# 80 port check & help
#################################
ensure_tools_for_portcheck() {
  # ss is in iproute2
  if ! need_cmd ss; then
    apk add --no-cache iproute2 >/dev/null 2>&1 || true
  fi
  # netstat as fallback (busybox-extras)
  if ! need_cmd netstat; then
    apk add --no-cache busybox-extras >/dev/null 2>&1 || true
  fi
}

is_port80_listening() {
  if need_cmd ss; then
    ss -ltn 2>/dev/null | awk '$4 ~ /:80$/ {found=1} END{exit (found?0:1)}'
    return $?
  fi
  if need_cmd netstat; then
    netstat -ltn 2>/dev/null | awk '$4 ~ /:80$/ {found=1} END{exit (found?0:1)}'
    return $?
  fi
  # unknown -> assume not listening
  return 1
}

show_port80_occupy() {
  echo "---- 80 端口占用信息（如果有）----"
  if need_cmd ss; then
    # -p may be unavailable in some builds; try with -p first
    ss -ltnp 2>/dev/null | awk 'NR==1 || $4 ~ /:80$/ {print}' || true
    ss -ltn 2>/dev/null | awk 'NR==1 || $4 ~ /:80$/ {print}' || true
  elif need_cmd netstat; then
    netstat -ltnp 2>/dev/null | awk 'NR==1 || $4 ~ /:80$/ {print}' || true
    netstat -ltn 2>/dev/null | awk 'NR==1 || $4 ~ /:80$/ {print}' || true
  else
    echo "(缺少 ss/netstat，无法展示占用详情)"
  fi
  echo "----------------------------------"
}

stop_common_web_services() {
  # best-effort stop
  for svc in nginx caddy apache2 httpd lighttpd; do
    if rc-service "$svc" status >/dev/null 2>&1; then
      echo "[i] stopping: $svc"
      rc-service "$svc" stop >/dev/null 2>&1 || true
    fi
  done
}

ensure_port80_for_acme() {
  ensure_tools_for_portcheck
  if is_port80_listening; then
    echo
    echo "[!] 检测到 80 端口正在监听，acme.sh standalone 可能会失败。"
    show_port80_occupy

    prompt STOP_WEB "是否尝试自动停止常见 Web 服务(nginx/caddy/apache2/lighttpd)？(y/N)" "N"
    if yesno "$STOP_WEB"; then
      stop_common_web_services
      sleep 1
      if is_port80_listening; then
        echo "[!] 80 端口仍被占用。你需要手动释放 80，或改用 DNS 验证方式。"
        show_port80_occupy
        die "80 端口不可用，终止。"
      fi
      echo "[+] 80 端口已释放（或不再监听）。"
    else
      die "80 端口被占用，未释放，终止。"
    fi
  fi
}

#################################
# reality disguise pool
#################################
choose_reality_handshake() {
  POOL="$(cat <<'EOF'
www.cloudflare.com
www.apple.com
www.microsoft.com
www.amazon.com
www.google.com
www.youtube.com
www.gstatic.com
www.bing.com
www.wikipedia.org
www.netflix.com
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
  REALITY_CLIENT_SNI="$REALITY_HANDSHAKE_SERVER"
}

#################################
# certificate issuance
#################################
issue_cert_lets_encrypt() {
  DOMAIN="$1"
  CERT_PATH="$2"
  KEY_PATH="$3"
  FULLCHAIN_PATH="$4"

  install_acmesh
  ensure_port80_for_acme

  echo
  echo "[i] 正在申请 Let's Encrypt 证书（standalone）: $DOMAIN"
  echo "[i] 要求：域名 A/AAAA 指向本机，且外网可访问 80 端口"

  acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  acme.sh --issue -d "$DOMAIN" --standalone --force

  mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")" "$(dirname "$FULLCHAIN_PATH")"

  acme.sh --install-cert -d "$DOMAIN" \
    --key-file "$KEY_PATH" \
    --cert-file "$CERT_PATH" \
    --fullchain-file "$FULLCHAIN_PATH" \
    --reloadcmd "rc-service sing-box restart >/dev/null 2>&1 || true"
}

make_self_signed_cert() {
  SNI="$1"
  CERT_PATH="$2"
  KEY_PATH="$3"
  FULLCHAIN_PATH="$4"

  echo "[i] 生成自签证书（含 SAN）"
  mkdir -p "$(dirname "$CERT_PATH")" "$(dirname "$KEY_PATH")" "$(dirname "$FULLCHAIN_PATH")"

  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$KEY_PATH" -out "$CERT_PATH" \
    -subj "/CN=${SNI}" \
    -addext "subjectAltName=DNS:${SNI}" >/dev/null 2>&1

  cp -f "$CERT_PATH" "$FULLCHAIN_PATH"
}

#################################
# main
#################################
[ "$(id -u)" -eq 0 ] || die "请用 root 运行"

install_singbox
apk add --no-cache jq openssl >/dev/null

mkdir -p /etc/sing-box /var/log/sing-box

echo
prompt VLESS_PORT "VLESS+Reality 监听端口" "443"
prompt HY2_1_PORT  "HY2#1 监听端口" "8443"
prompt HY2_2_PORT  "HY2#2 监听端口" "9443"

choose_reality_handshake

echo
prompt HAS_DOMAIN "是否有域名并自动申请 Let's Encrypt？(y/N)" "N"

TLS_CERT="/etc/sing-box/tls/cert.pem"
TLS_KEY="/etc/sing-box/tls/key.pem"
TLS_FULLCHAIN="/etc/sing-box/tls/fullchain.pem"
TLS_SNI=""
HY2_INSECURE="0"

if yesno "$HAS_DOMAIN"; then
  prompt DOMAIN "请输入域名（已解析到本机）" ""
  [ -n "${DOMAIN:-}" ] || die "域名不能为空"
  TLS_SNI="$DOMAIN"
  HY2_INSECURE="0"
  issue_cert_lets_encrypt "$DOMAIN" "$TLS_CERT" "$TLS_KEY" "$TLS_FULLCHAIN"
else
  prompt TLS_SNI "无域名：自签证书 SNI（随意填一个域名样式）" "example.com"
  HY2_INSECURE="1"
  make_self_signed_cert "$TLS_SNI" "$TLS_CERT" "$TLS_KEY" "$TLS_FULLCHAIN"
fi

UUID="$(gen_uuid)"
SHORT_ID="$(rand_hex 4)"
HY2_PASS_1="$(rand_hex 16)"
HY2_PASS_2="$(rand_hex 16)"

# Reality keypair (must exist)
if ! sing-box generate help >/dev/null 2>&1; then
  die "当前 sing-box 不支持 generate 子命令，无法自动生成 Reality keypair。请升级 sing-box。"
fi

KP="$(sing-box generate reality-keypair 2>/dev/null || true)"
REALITY_PRIV="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]rivate.*: *//p' | head -n1)"
REALITY_PUB="$(printf "%s\n" "$KP" | sed -n 's/.*[Pp]ublic.*: *//p' | head -n1)"
[ -n "${REALITY_PRIV:-}" ] && [ -n "${REALITY_PUB:-}" ] || die "生成 Reality keypair 失败"

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
          "handshake": { "server": "${REALITY_HANDSHAKE_SERVER}", "server_port": ${REALITY_HANDSHAKE_PORT} },
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
      "users": [ { "password": "${HY2_PASS_1}" } ],
      "tls": {
        "enabled": true,
        "server_name": "${TLS_SNI}",
        "certificate_path": "${TLS_FULLCHAIN}",
        "key_path": "${TLS_KEY}"
      }
    },
    {
      "type": "hysteria2",
      "tag": "in-hy2-2",
      "listen": "0.0.0.0",
      "listen_port": ${HY2_2_PORT},
      "users": [ { "password": "${HY2_PASS_2}" } ],
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

# OpenRC service
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

# v2rayN links
echo
prompt PUBLIC_HOST "对外可访问的域名/IP（写到分享链接里；有域名建议填域名）" ""
if [ -z "$PUBLIC_HOST" ]; then
  PUBLIC_HOST="$(hostname -i 2>/dev/null | awk '{print $1}' || true)"
  [ -n "$PUBLIC_HOST" ] || PUBLIC_HOST="YOUR_SERVER_IP"
fi

ENC_R_SNI="$(urlencode "$REALITY_CLIENT_SNI")"
ENC_TLS_SNI="$(urlencode "$TLS_SNI")"
ENC_NAME_VLESS="$(urlencode "VLESS-Reality")"
ENC_NAME_HY2_1="$(urlencode "HY2-1")"
ENC_NAME_HY2_2="$(urlencode "HY2-2")"

VLESS_LINK="vless://${UUID}@${PUBLIC_HOST}:${VLESS_PORT}?type=tcp&encryption=none&security=reality&sni=${ENC_R_SNI}&fp=chrome&pbk=${REALITY_PUB}&sid=${SHORT_ID}&flow=xtls-rprx-vision#${ENC_NAME_VLESS}"
HY2_LINK_1="hysteria2://${HY2_PASS_1}@${PUBLIC_HOST}:${HY2_1_PORT}?sni=${ENC_TLS_SNI}&insecure=${HY2_INSECURE}#${ENC_NAME_HY2_1}"
HY2_LINK_2="hysteria2://${HY2_PASS_2}@${PUBLIC_HOST}:${HY2_2_PORT}?sni=${ENC_TLS_SNI}&insecure=${HY2_INSECURE}#${ENC_NAME_HY2_2}"

SUB_PATH="/etc/sing-box/v2rayn_links.txt"
printf "%s\n%s\n%s\n" "$VLESS_LINK" "$HY2_LINK_1" "$HY2_LINK_2" > "$SUB_PATH"

echo
echo "================== 部署完成 =================="
echo "Reality 伪装目标:    ${REALITY_HANDSHAKE_SERVER}:${REALITY_HANDSHAKE_PORT}"
echo "Reality SNI:         ${REALITY_CLIENT_SNI}"
echo "Reality 公钥(pbk):   ${REALITY_PUB}"
echo "Reality short_id:    ${SHORT_ID}"
echo "UUID:                ${UUID}"
echo "HY2#1 password:      ${HY2_PASS_1}"
echo "HY2#2 password:      ${HY2_PASS_2}"
echo
echo "---- v2rayN 可导入链接（3条）----"
echo "$VLESS_LINK"
echo "$HY2_LINK_1"
echo "$HY2_LINK_2"
echo
echo "已写入：$SUB_PATH（v2rayN 可从文件导入 / 从剪贴板导入）"
echo "服务管理：rc-service sing-box restart | stop | start"
echo "日志查看：tail -f /var/log/sing-box/sing-box.log"
