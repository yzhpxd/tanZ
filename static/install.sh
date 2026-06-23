#!/bin/bash
# Tanzheng 探针自动化部署工具
# 基于 GitHub Releases 发布

exec 0</dev/tty
VERSION="v.1.0.1"
BASE_URL="https://github.com/yzhpxd/tanZ/releases/download/$VERSION"
RED='\033[0;31m'; GREEN='\033[0;32m'; PLAIN='\033[0m'

if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 root 权限运行！${PLAIN}"; exit 1; fi

echo -e "${GREEN}======================================${PLAIN}"
echo -e "  Tanzheng 探针自动化部署工具"
echo -e "${GREEN}======================================${PLAIN}"
echo "1. 安装主控服务端 (Server)"
echo "2. 安装被控客户端 (Agent)"
read -p "请选择安装类型 [1/2]: " choice

ARCH=$(uname -m)
[ "$ARCH" == "x86_64" ] && BIN_ARCH="amd64" || BIN_ARCH="arm64"

# --- 1. 安装服务端 ---
if [ "$choice" == "1" ]; then
    INSTALL_DIR="/home/mynetzheng"
    mkdir -p $INSTALL_DIR
    echo -e "${GREEN}[-] 正在从 GitHub 下载服务端...${PLAIN}"
    wget -qO $INSTALL_DIR/tz-server $BASE_URL/tz-server-$BIN_ARCH
    chmod +x $INSTALL_DIR/tz-server
    
    cat > /etc/systemd/system/tz-server.service <<EOF
[Unit]
Description=Tanzheng Server
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/tz-server
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now tz-server
    echo -e "${GREEN}[+] 服务端安装成功！${PLAIN}"

# --- 2. 安装客户端 ---
elif [ "$choice" == "2" ]; then
    read -p "请输入主控地址 (如 https://vps.666200.xyz): " SERVER_URL
    
    # 【修复重点】强制清理旧环境，避免旧 ID 文件导致新节点无法识别
    systemctl stop tz-agent 2>/dev/null
    rm -rf /home/agent
    
    INSTALL_DIR="/home/agent"
    id -u monitor &>/dev/null || useradd -m -s /sbin/nologin monitor
    mkdir -p $INSTALL_DIR
    
    echo -e "${GREEN}[-] 正在从 GitHub 下载客户端...${PLAIN}"
    wget -qO $INSTALL_DIR/tz-agent $BASE_URL/tz-agent-linux-$BIN_ARCH
    chmod +x $INSTALL_DIR/tz-agent
    chown -R monitor:monitor $INSTALL_DIR
    
    cat > /etc/systemd/system/tz-agent.service <<EOF
[Unit]
Description=Tanzheng Agent
After=network.target
[Service]
Type=simple
User=monitor
Group=monitor
WorkingDirectory=$INSTALL_DIR
# 【修复重点】移除了 /report，改为直接传入地址，与你能跑通的 VPS 脚本逻辑一致
ExecStart=$INSTALL_DIR/tz-agent -server $SERVER_URL
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now tz-agent
    echo -e "${GREEN}[+] 客户端安装成功！${PLAIN}"
else
    echo "[-] 无效输入。"
fi
