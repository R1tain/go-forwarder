#!/usr/bin/env bash
# ===========================================================
#  Go-Forwarder 端口转发管理脚本
#  功能: 安装/CRUD转发规则/systemd持久化/双栈互转/高性能转发
#  架构: 纯 Layer 4 TCP/UDP 高性能转发 (支持 Linux splice 零拷贝)
# ===========================================================
set -uo pipefail

# ----------------------- 基础路径 -----------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/go-forwarder"
BIN="/usr/local/bin/go-forwarder"
RULES_FILE="$CONFIG_DIR/rules.json"
SERVICE_FILE="/etc/systemd/system/go-forwarder.service"

# 兼容/继承 realm 规则文件
REALM_RULES="/etc/realm/rules.json"

# ----------------------- 颜色输出 -----------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'
info(){ echo -e "${BLUE}[信息]${NC} $1"; }
ok(){ echo -e "${GREEN}[成功]${NC} $1"; }
warn(){ echo -e "${YELLOW}[警告]${NC} $1" >&2; }
err(){ echo -e "${RED}[错误]${NC} $1" >&2; }
press_enter(){ read -rp "按回车键继续..." _; }

require_root(){
  if [ "$(id -u)" -ne 0 ]; then
    err "请使用 root 权限运行此脚本 (例如: sudo bash $0)"
    exit 1
  fi
}

# ----------------------- 依赖安装 -----------------------
install_deps(){
  local need=()
  command -v curl >/dev/null 2>&1 || need+=(curl)
  command -v jq   >/dev/null 2>&1 || need+=(jq)
  command -v tar  >/dev/null 2>&1 || need+=(tar)
  command -v ss   >/dev/null 2>&1 || need+=(iproute2)
  [ ${#need[@]} -eq 0 ] && return 0
  info "正在安装依赖: ${need[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq "${need[@]}" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${need[@]/iproute2/iproute}" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${need[@]/iproute2/iproute}" >/dev/null 2>&1
  else
    err "未能识别系统包管理器，请手动安装: ${need[*]}"
    exit 1
  fi
  ok "依赖安装完成"
}

# ----------------------- 架构检测 -----------------------
detect_arch(){
  local m
  m=$(uname -m)
  case $m in
    x86_64|amd64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *) echo "$m" ;;
  esac
}

# ----------------------- 工具函数 -----------------------
valid_port(){ [[ $1 =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

is_port_used(){
  local port=$1 exclude_id=${2:-}
  if [ -f "$RULES_FILE" ] && jq -e --argjson port "$port" --argjson excl "${exclude_id:-null}" \
      '[.[] | select(.listen_port==$port and .id != $excl)] | length > 0' \
      "$RULES_FILE" >/dev/null 2>&1; then
    return 0
  fi
  if command -v ss >/dev/null 2>&1 && ss -tuln 2>/dev/null | grep -qE "[:.]${port}[[:space:]]"; then
    return 0
  fi
  return 1
}

random_port(){
  local p i
  for i in $(seq 1 50); do
    p=$(( (RANDOM % 55001) + 10000 ))
    if ! is_port_used "$p"; then echo "$p"; return 0; fi
  done
  err "未能找到可用随机端口，请手动指定"
  return 1
}

detect_family(){
  local addr=$1
  if [[ $addr =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    echo ipv4
  elif [[ $addr == *:* ]]; then
    echo ipv6
  else
    echo domain
  fi
}

display_listen_string(){
  local fam=$1 ipc=$2 port=$3 cfam
  case $fam in
    ipv4) echo "0.0.0.0:$port" ;;
    ipv6) echo "[::]:$port" ;;
    dual) echo "[::]:$port (双栈)" ;;
    custom)
      cfam=$(detect_family "$ipc")
      if [ "$cfam" = "ipv6" ]; then echo "[$ipc]:$port"; else echo "$ipc:$port"; fi
      ;;
    *) echo ":$port" ;;
  esac
}

format_target(){
  local addr=$1 port=$2 fam
  fam=$(detect_family "$addr")
  if [ "$fam" = "ipv6" ]; then echo "[$addr]:$port"; else echo "$addr:$port"; fi
}

proto_display(){
  case $1 in
    tcp) echo "TCP" ;;
    udp) echo "UDP" ;;
    both|all|tcp+udp) echo "TCP+UDP" ;;
    *) echo "$1" ;;
  esac
}

ipv6_enabled(){
  if [ -f /proc/sys/net/ipv6/conf/all/disable_ipv6 ]; then
    [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" = "0" ]
  else
    return 0
  fi
}

# ----------------------- 初始化环境 -----------------------
init_files(){
  mkdir -p "$CONFIG_DIR"
  if [ ! -f "$RULES_FILE" ]; then
    if [ -f "$REALM_RULES" ]; then
      info "检测到已有 realm 转发规则，正在继承迁移..."
      cp "$REALM_RULES" "$RULES_FILE"
      ok "成功迁移 realm 规则至 $RULES_FILE"
    else
      echo '[]' > "$RULES_FILE"
    fi
  fi
}

# ----------------------- 规则重载/生效 -----------------------
apply_changes(){
  local msg=${1:-"规则已更新"}
  if systemctl is-active --quiet go-forwarder 2>/dev/null; then
    systemctl restart go-forwarder
    ok "$msg (服务已重启生效)"
  else
    ok "$msg (服务未运行，启动后将自动生效)"
  fi
}

# ----------------------- 交互输入收集 -----------------------
collect_listen_family(){
  local def=${1:-3}
  echo ""
  echo "请选择监听地址族:"
  echo "  1) IPv4  (0.0.0.0)"
  echo "  2) IPv6  ([::])"
  echo "  3) 双栈  (同时监听IPv4和IPv6，默认推荐)"
  echo "  4) 自定义IP"
  local c
  while true; do
    read -rp "请输入选项 [1-4, 默认$def]: " c
    c=${c:-$def}
    case $c in
      1) LISTEN_FAMILY=ipv4; LISTEN_IP_CUSTOM=""; break ;;
      2) ipv6_enabled || warn "检测到系统可能未开启IPv6"
         LISTEN_FAMILY=ipv6; LISTEN_IP_CUSTOM=""; break ;;
      3) ipv6_enabled || warn "检测到系统可能未开启IPv6"
         LISTEN_FAMILY=dual; LISTEN_IP_CUSTOM=""; break ;;
      4) read -rp "请输入自定义监听IP: " LISTEN_IP_CUSTOM
         [ -z "$LISTEN_IP_CUSTOM" ] && { warn "IP不能为空"; continue; }
         LISTEN_FAMILY=custom; break ;;
      *) warn "无效输入" ;;
    esac
  done
}

collect_port(){
  local exclude_id=${1:-}
  echo ""
  echo "请选择监听端口方式:"
  echo "  1) 手动指定"
  echo "  2) 随机分配"
  local c
  while true; do
    read -rp "请输入选项 [1-2, 默认1]: " c
    c=${c:-1}
    case $c in
      1)
        while true; do
          read -rp "请输入监听端口(1-65535): " LISTEN_PORT
          if ! valid_port "$LISTEN_PORT"; then warn "端口格式不正确"; continue; fi
          if is_port_used "$LISTEN_PORT" "$exclude_id"; then warn "该端口已被占用或已存在规则使用"; continue; fi
          break
        done
        break ;;
      2)
        LISTEN_PORT=$(random_port) || continue
        info "已分配随机端口: $LISTEN_PORT"
        break ;;
      *) warn "无效输入" ;;
    esac
  done
}

collect_protocol(){
  local def=${1:-1}
  echo ""
  echo "请选择转发协议:"
  echo "  1) TCP+UDP (默认推荐, 适用于大部分代理/网页/游戏/DNS)"
  echo "  2) 仅TCP"
  echo "  3) 仅UDP"
  local c
  while true; do
    read -rp "请输入选项 [1-3, 默认$def]: " c
    c=${c:-$def}
    case $c in
      1) PROTO=both; break ;;
      2) PROTO=tcp; break ;;
      3) PROTO=udp; break ;;
      *) warn "无效输入" ;;
    esac
  done
}

collect_target(){
  while true; do
    read -rp "请输入目标地址(IP或DDNS动态域名): " TARGET_ADDR
    [ -n "$TARGET_ADDR" ] && break
    warn "目标地址不能为空"
  done
  while true; do
    read -rp "请输入目标端口: " TARGET_PORT
    valid_port "$TARGET_PORT" && break
    warn "端口格式不正确"
  done
}

collect_remark(){
  read -rp "请输入备注(可留空): " REMARK
}

# ----------------------- 规则 CRUD -----------------------
add_rule(){
  echo ""
  echo "===== 新增转发规则 ====="
  collect_listen_family 3
  collect_port ""
  collect_protocol 1
  collect_target
  collect_remark

  local max_id next_id now
  max_id=$(jq '[.[].id] | max // 0' "$RULES_FILE" 2>/dev/null) || max_id=0
  next_id=$(( max_id + 1 ))
  now=$(date '+%Y-%m-%d %H:%M:%S')

  local new_rule
  new_rule=$(jq -n \
    --argjson id "$next_id" \
    --arg remark "$REMARK" \
    --arg lf "$LISTEN_FAMILY" \
    --arg lip "$LISTEN_IP_CUSTOM" \
    --argjson lp "$LISTEN_PORT" \
    --arg proto "$PROTO" \
    --arg target "$TARGET_ADDR" \
    --argjson tp "$TARGET_PORT" \
    --arg created "$now" \
    '{id:$id, remark:$remark, listen_family:$lf, listen_ip:$lip, listen_port:$lp, protocol:$proto, target:$target, target_port:$tp, enabled:true, created:$created}')

  jq --argjson rule "$new_rule" '. += [$rule]' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"
  apply_changes "规则 #$next_id 添加成功"
  press_enter
}

list_rules(){
  echo ""
  echo "================================================ 转发规则列表 ================================================"
  local count
  count=$(jq '. | length' "$RULES_FILE" 2>/dev/null) || count=0
  if [ "$count" -eq 0 ]; then
    echo "  (暂无转发规则)"
    echo "=============================================================================================================="
    return 0
  fi

  printf "%-4s | %-12s | %-24s | %-8s | %-30s | %-6s\n" "ID" "备注" "本地监听" "协议" "目标地址" "状态"
  echo "--------------------------------------------------------------------------------------------------------------"

  while read -r row; do
    [ -z "$row" ] && continue
    local id remark fam ip port proto target tport en status_str listen_str target_str
    id=$(echo "$row" | jq -r '.id')
    remark=$(echo "$row" | jq -r '.remark // "-"')
    fam=$(echo "$row" | jq -r '.listen_family // "dual"')
    ip=$(echo "$row" | jq -r '.listen_ip // ""')
    port=$(echo "$row" | jq -r '.listen_port')
    proto=$(echo "$row" | jq -r '.protocol // "both"')
    target=$(echo "$row" | jq -r '.target')
    tport=$(echo "$row" | jq -r '.target_port')
    en=$(echo "$row" | jq -r '.enabled')

    listen_str=$(display_listen_string "$fam" "$ip" "$port")
    target_str=$(format_target "$target" "$tport")
    [ "$en" = "true" ] && status_str="${GREEN}启用${NC}" || status_str="${RED}禁用${NC}"

    printf "%-4s | %-12s | %-24s | %-8s | %-30s | %b\n" \
      "$id" "${remark:0:10}" "$listen_str" "$(proto_display "$proto")" "${target_str:0:28}" "$status_str"
  done < <(jq -c '.[]' "$RULES_FILE")
  echo "=============================================================================================================="
}

edit_rule(){
  list_rules
  echo ""
  read -rp "请输入要修改的规则 ID: " rid
  if ! jq -e --argjson id "$rid" '.[] | select(.id==$id)' "$RULES_FILE" >/dev/null 2>&1; then
    err "未找到 ID 为 $rid 的规则"; press_enter; return
  fi

  local cur_row cur_remark cur_fam cur_ip cur_lp cur_proto cur_target cur_tp
  cur_row=$(jq -c --argjson id "$rid" '.[] | select(.id==$id)' "$RULES_FILE")
  cur_remark=$(echo "$cur_row" | jq -r '.remark // ""')
  cur_fam=$(echo "$cur_row" | jq -r '.listen_family // "dual"')
  cur_ip=$(echo "$cur_row" | jq -r '.listen_ip // ""')
  cur_lp=$(echo "$cur_row" | jq -r '.listen_port')
  cur_proto=$(echo "$cur_row" | jq -r '.protocol // "both"')
  cur_target=$(echo "$cur_row" | jq -r '.target')
  cur_tp=$(echo "$cur_row" | jq -r '.target_port')

  echo "当前规则: ID=$rid | 备注=$cur_remark | 监听=$cur_lp($cur_fam) | 协议=$cur_proto | 目标=$cur_target:$cur_tp"
  echo "提示: 如不修改某项，直接回车保持当前值"

  # 1. 监听端口
  read -rp "监听端口 [$cur_lp]: " val
  if [ -n "$val" ]; then
    if ! valid_port "$val"; then err "端口格式不正确"; press_enter; return; fi
    if is_port_used "$val" "$rid"; then err "端口已被占用"; press_enter; return; fi
    LISTEN_PORT=$val
  else
    LISTEN_PORT=$cur_lp
  fi

  # 2. 目标地址
  read -rp "目标地址 [$cur_target]: " val
  TARGET_ADDR=${val:-$cur_target}

  # 3. 目标端口
  read -rp "目标端口 [$cur_tp]: " val
  if [ -n "$val" ]; then
    if ! valid_port "$val"; then err "端口格式不正确"; press_enter; return; fi
    TARGET_PORT=$val
  else
    TARGET_PORT=$cur_tp
  fi

  # 4. 协议
  echo "转发协议 1) TCP+UDP 2) 仅TCP 3) 仅UDP [当前: $(proto_display "$cur_proto")]"
  read -rp "请选择 [留空保持不变]: " val
  case $val in
    1) PROTO=both ;;
    2) PROTO=tcp ;;
    3) PROTO=udp ;;
    *) PROTO=$cur_proto ;;
  esac

  # 5. 备注
  read -rp "备注 [$cur_remark]: " val
  REMARK=${val:-$cur_remark}

  jq --argjson id "$rid" \
     --arg remark "$REMARK" \
     --argjson lp "$LISTEN_PORT" \
     --arg proto "$PROTO" \
     --arg target "$TARGET_ADDR" \
     --argjson tp "$TARGET_PORT" \
     'map(if .id == $id then .remark=$remark | .listen_port=$lp | .protocol=$proto | .target=$target | .target_port=$tp else . end)' \
     "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"

  apply_changes "规则 #$rid 修改成功"
  press_enter
}

delete_rule(){
  list_rules
  echo ""
  read -rp "请输入要删除的规则 ID: " rid
  if ! jq -e --argjson id "$rid" '.[] | select(.id==$id)' "$RULES_FILE" >/dev/null 2>&1; then
    err "未找到 ID 为 $rid 的规则"; press_enter; return
  fi
  read -rp "确认删除规则 #$rid? [y/N]: " yn
  if [[ ! $yn =~ ^[Yy]$ ]]; then warn "已取消删除"; press_enter; return; fi

  jq --argjson id "$rid" 'map(select(.id != $id))' "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"
  apply_changes "规则 #$rid 已删除"
  press_enter
}

toggle_rule(){
  list_rules
  echo ""
  read -rp "请输入要切换状态(启用/禁用)的规则 ID: " rid
  if ! jq -e --argjson id "$rid" '.[] | select(.id==$id)' "$RULES_FILE" >/dev/null 2>&1; then
    err "未找到 ID 为 $rid 的规则"; press_enter; return
  fi

  local cur_st new_st
  cur_st=$(jq --argjson id "$rid" '.[] | select(.id==$id) | .enabled' "$RULES_FILE")
  [ "$cur_st" = "true" ] && new_st=false || new_st=true

  jq --argjson id "$rid" --argjson st "$new_st" \
     'map(if .id == $id then .enabled=$st else . end)' \
     "$RULES_FILE" > "$RULES_FILE.tmp" && mv "$RULES_FILE.tmp" "$RULES_FILE"

  local status_text
  [ "$new_st" = "true" ] && status_text="已启用" || status_text="已禁用"
  apply_changes "规则 #$rid $status_text"
  press_enter
}

# ----------------------- 安装 / 更新 -----------------------
install_forwarder(){
  echo ""
  echo "===== 安装 / 更新 go-forwarder ====="
  local arch
  arch=$(detect_arch)
  info "当前系统架构: $arch"

  local src_bin=""
  if [ -f "$SCRIPT_DIR/go_forwarder_linux_$arch" ]; then
    src_bin="$SCRIPT_DIR/go_forwarder_linux_$arch"
    info "检测到同目录预编译二进制: $src_bin"
  elif [ -f "$SCRIPT_DIR/go-forwarder" ]; then
    src_bin="$SCRIPT_DIR/go-forwarder"
    info "检测到同目录二进制: $src_bin"
  fi

  if [ -n "$src_bin" ]; then
    systemctl stop go-forwarder 2>/dev/null || true
    cp "$src_bin" "$BIN"
    chmod +x "$BIN"
    ok "已成功从本地部署二进制到 $BIN"
  else
    info "尝试从 GitHub 公开 Release 下载二进制..."
    local download_url="https://github.com/R1tain/go-forwarder/releases/latest/download/go_forwarder_linux_$arch"
    local tmp_bin="/tmp/go_forwarder_$arch"
    if curl -sSL -f "$download_url" -o "$tmp_bin" && [ -s "$tmp_bin" ]; then
      systemctl stop go-forwarder 2>/dev/null || true
      mv "$tmp_bin" "$BIN"
      chmod +x "$BIN"
      ok "已成功从 GitHub Release 下载并部署到 $BIN"
    elif command -v go >/dev/null 2>&1; then
      info "GitHub 下载不可用，检测到本机已安装 Go 环境，正在源码编译..."
      local gocode=""
      if [ -f "$SCRIPT_DIR/../go-forwarder-project/main.go" ]; then
        gocode="$SCRIPT_DIR/../go-forwarder-project/main.go"
      elif [ -f "$SCRIPT_DIR/main.go" ]; then
        gocode="$SCRIPT_DIR/main.go"
      fi
      if [ -n "$gocode" ]; then
        CGO_ENABLED=0 go build -ldflags="-s -w" -o "$BIN" "$gocode"
        chmod +x "$BIN"
        ok "编译安装成功: $BIN"
      else
        err "未找到 Go 源代码文件"
        press_enter; return 1
      fi
    else
      err "未找到适用于当前架构 ($arch) 的 go-forwarder 二进制，且无法从 GitHub 下载"
      press_enter; return 1
    fi
  fi

  # 写入 systemd 服务文件
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Go Port Forwarding Service
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN $RULES_FILE
Restart=always
RestartSec=3s
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable go-forwarder >/dev/null 2>&1
  systemctl restart go-forwarder
  ok "go-forwarder 服务已配置并启动成功！"
  press_enter
}

# ----------------------- 服务管理 -----------------------
service_menu(){
  while true; do
    clear
    echo "========================================"
    echo "          服务状态与日志管理"
    echo "========================================"
    if systemctl is-active --quiet go-forwarder 2>/dev/null; then
      echo -e "  服务状态: ${GREEN}运行中${NC}"
    else
      echo -e "  服务状态: ${RED}未运行${NC}"
    fi
    echo "----------------------------------------"
    echo "  1) 启动服务"
    echo "  2) 停止服务"
    echo "  3) 重启服务"
    echo "  4) 查看服务详细状态"
    echo "  5) 实时查看转发日志 (Ctrl+C 退出)"
    echo "  0) 返回主菜单"
    echo "========================================"
    read -rp "请输入选项: " opt
    case $opt in
      1) systemctl start go-forwarder && ok "服务已启动" ;;
      2) systemctl stop go-forwarder && ok "服务已停止" ;;
      3) systemctl restart go-forwarder && ok "服务已重启" ;;
      4) systemctl status go-forwarder --no-pager ;;
      5) journalctl -u go-forwarder -f -n 50 ;;
      0) break ;;
      *) warn "无效输入" ;;
    esac
    press_enter
  done
}

# ----------------------- 备份 / 恢复 -----------------------
backup_rules(){
  local out
  out="/root/go-forwarder-backup-$(date +%Y%m%d%H%M%S).tar.gz"
  tar czf "$out" -C "$CONFIG_DIR" rules.json 2>/dev/null
  ok "规则已成功备份到: $out"
  press_enter
}

restore_rules(){
  read -rp "请输入备份文件完整路径: " path
  if [ ! -f "$path" ]; then err "文件不存在"; press_enter; return; fi
  local tmpdir
  tmpdir=$(mktemp -d)
  tar xzf "$path" -C "$tmpdir" 2>/dev/null
  if [ ! -f "$tmpdir/rules.json" ]; then
    err "备份文件格式不正确，缺少 rules.json"; rm -rf "$tmpdir"; press_enter; return
  fi
  cp "$tmpdir/rules.json" "$RULES_FILE"
  rm -rf "$tmpdir"
  apply_changes "规则恢复成功"
  press_enter
}

# ----------------------- 卸载 -----------------------
uninstall_forwarder(){
  read -rp "确认卸载 go-forwarder? 这将停止服务并删除二进制 [y/N]: " yn
  if [[ ! $yn =~ ^[Yy]$ ]]; then warn "已取消"; press_enter; return; fi
  systemctl stop go-forwarder 2>/dev/null || true
  systemctl disable go-forwarder 2>/dev/null || true
  rm -f "$SERVICE_FILE" "$BIN"
  systemctl daemon-reload 2>/dev/null || true
  read -rp "是否保留规则配置文件 ($RULES_FILE) 便于下次使用? [Y/n]: " keep
  if [[ $keep =~ ^[Nn]$ ]]; then
    rm -rf "$CONFIG_DIR"
    ok "已完全卸载并删除规则配置"
  else
    ok "已卸载程序，规则文件保留在 $RULES_FILE"
  fi
  press_enter
}

# ----------------------- 主菜单 -----------------------
main_menu(){
  while true; do
    clear
    echo "========================================"
    echo "      Go-Forwarder 转发管理脚本"
    echo "========================================"
    if [ -x "$BIN" ]; then
      if systemctl is-active --quiet go-forwarder 2>/dev/null; then
        echo -e "  程序状态: ${GREEN}已安装${NC} | 服务状态: ${GREEN}运行中${NC}"
      else
        echo -e "  程序状态: ${GREEN}已安装${NC} | 服务状态: ${RED}已停止${NC}"
      fi
    else
      echo -e "  程序状态: ${RED}未安装${NC}"
    fi
    echo "----------------------------------------"
    echo "  1) 新增转发规则"
    echo "  2) 查看所有规则"
    echo "  3) 修改规则"
    echo "  4) 删除规则"
    echo "  5) 启用/禁用规则"
    echo "  6) 服务状态与实时日志"
    echo "  7) 安装 / 更新 go-forwarder"
    echo "  8) 备份规则"
    echo "  9) 恢复规则"
    echo " 10) 重载服务并立即生效"
    echo " 11) 卸载"
    echo "  0) 退出"
    echo "========================================"
    read -rp "请输入选项: " choice
    case $choice in
      1) if [ ! -x "$BIN" ]; then warn "请先安装 go-forwarder (选项7)"; press_enter; else add_rule; fi ;;
      2) list_rules; press_enter ;;
      3) if [ ! -x "$BIN" ]; then warn "请先安装 go-forwarder (选项7)"; press_enter; else edit_rule; fi ;;
      4) delete_rule ;;
      5) toggle_rule ;;
      6) service_menu ;;
      7) install_forwarder ;;
      8) backup_rules ;;
      9) restore_rules ;;
      10) apply_changes "配置已重新加载"; press_enter ;;
      11) uninstall_forwarder ;;
      0) exit 0 ;;
      *) warn "无效输入"; press_enter ;;
    esac
  done
}

# ----------------------- 入口 -----------------------
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  require_root
  install_deps
  init_files
  main_menu "$@"
fi
