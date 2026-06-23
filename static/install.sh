#!/bin/bash
# Tanzheng 探针一键安装脚本
# 适配: Ubuntu/Debian/CentOS
# 使用方法: curl -sL https://tanz.666200.xyz/static/install.sh | bash

DOWNLOAD_URL="https://tanz.666200.xyz/static"
RED='\033[0;31m'; GREEN='\033[0;32m'; PLAIN='\033[0m'

if [ "$EUID" -ne 0 ]; then echo -e "${RED}请使用 root 权限运行！${PLAIN}"; exit 1; fi

echo -e "${GREEN}======================================${PLAIN}"
echo -e "  欢迎使用 Tanzheng 探针一键部署"
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
    echo "[-] 正在下载服务端..."
    wget -qO $INSTALL_DIR/tz-server $DOWNLOAD_URL/tz-server-linux-$BIN_ARCH
    chmod +x $INSTALL_DIR/tz-server
    
    cat > /etc/systemd/system/tz-server.service <<EOF
[Unit]
Description=Tanzheng Server Dashboard
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
    echo -e "${GREEN}[+] 服务端安装成功！面板默认端口 5001。${PLAIN}"

# --- 2. 安装客户端 ---
elif [ "$choice" == "2" ]; then
    read -p "请输入主控上报地址 (例如 https://status.666200.xyz): " SERVER_URL
    INSTALL_DIR="/home/agent"
    
    # 创建低权限运行用户
    id -u monitor &>/dev/null || useradd -m -s /sbin/nologin monitor
    mkdir -p $INSTALL_DIR
    
    echo "[-] 正在下载客户端..."
    wget -qO $INSTALL_DIR/tz-agent $DOWNLOAD_URL/tz-agent-linux-$BIN_ARCH
    chmod +x $INSTALL_DIR/tz-agent
    chown -R monitor:monitor $INSTALL_DIR
    
    cat > /etc/systemd/system/tz-agent.service <<EOF
[Unit]
Description=Tanzheng Agent
After=network.target
[Service]
Type=simple
User=monitor
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/tz-agent -server $SERVER_URL/report
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now tz-agent
    echo -e "${GREEN}[+] 客户端安装成功！已以后台静默方式运行。${PLAIN}"
else
    echo "[-] 无效选择。"
fi
