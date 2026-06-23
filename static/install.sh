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
    INSTALL_DIR="/home/agent"
    
    # 【核心升级 1】引入最严格的旧环境清理逻辑，彻底杜绝 ID 冲突和隐身问题
    echo -e "${GREEN}[-] 正在清理旧版本与残留配置...${PLAIN}"
    systemctl stop tz-agent 2>/dev/null
    systemctl disable tz-agent 2>/dev/null
    rm -f /etc/systemd/system/tz-agent.service
    systemctl daemon-reload
    rm -rf $INSTALL_DIR
    
    # 【核心升级 2】标准化的安全用户创建
    if ! id -u monitor &>/dev/null; then
        echo -e "${GREEN}[-] 正在创建低权限专用用户 monitor...${PLAIN}"
        useradd -m -s /sbin/nologin monitor
    fi
    
    mkdir -p $INSTALL_DIR
    echo -e "${GREEN}[-] 正在从 GitHub 下载客户端...${PLAIN}"
    wget -qO $INSTALL_DIR/tz-agent $BASE_URL/tz-agent-linux-$BIN_ARCH
    chmod +x $INSTALL_DIR/tz-agent
    
    # 将目录所有权移交给 monitor
    chown -R monitor:monitor $INSTALL_DIR
    
    echo -e "${GREEN}[-] 正在配置 Systemd 开机自启服务...${PLAIN}"
    cat > /etc/systemd/system/tz-agent.service <<EOF
[Unit]
Description=Tanzheng Agent
After=network.target

[Service]
Type=simple
User=monitor
Group=monitor
WorkingDirectory=$INSTALL_DIR
# 【核心升级 3】给变量加上双引号，防止输入地址时带有空格导致命令截断报错
ExecStart=$INSTALL_DIR/tz-agent -server "$SERVER_URL"
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload && systemctl enable --now tz-agent
    
    if systemctl is-active --quiet tz-agent; then
        echo -e "${GREEN}[+] ==========================================${PLAIN}"
        echo -e "${GREEN}[+] 探针客户端安装成功！${PLAIN}"
        echo -e "${GREEN}[+] 运行模式: monitor (安全低权限模式)${PLAIN}"
        echo -e "${GREEN}[+] ==========================================${PLAIN}"
    else
        echo -e "${RED}[-] 启动失败，请运行 'journalctl -u tz-agent -n 20' 检查报错。${PLAIN}"
    fi
else
    echo -e "${RED}[-] 无效输入。${PLAIN}"
fi
