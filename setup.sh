#!/bin/bash

# Shadowsocks-libev Installation Script with Options
# This script provides options to install shadowsocks-libev with or without shadow-tls

set -e

echo -e "\033[1;34m=== Shadowsocks 安装脚本 ===\033[0m"
echo ""

# Function to print colored text
print_info() { echo -e "\033[1;34m$1\033[0m"; }
print_success() { echo -e "\033[1;32m$1\033[0m"; }
print_warning() { echo -e "\033[1;33m$1\033[0m"; }
print_error() { echo -e "\033[1;31m$1\033[0m"; }

# Function to ask yes/no question
ask_yes_no() {
    while true; do
        read -p "$1 (y/n): " yn
        case $yn in
            [Yy]* ) return 0;;
            [Nn]* ) return 1;;
            * ) echo "请输入 y 或 n";;
        esac
    done
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "请使用 root 权限运行此脚本"
    exit 1
fi

# Main menu selection
echo -e "\033[1;36m请选择操作:\033[0m"
echo "1) 仅安装 shadowsocks-libev"
echo "2) 安装 shadowsocks-libev + shadow-tls"
echo "3) 卸载 shadowsocks-libev"
echo "4) 卸载 shadowsocks-libev + shadow-tls"
echo "5) 完全卸载所有组件"
echo "0) 退出"
echo ""
while true; do
    read -p "请输入选择 (0-5): " choice
    case $choice in
        0)
            print_info "退出脚本"
            exit 0
            ;;
        1)
            OPERATION_MODE="install-ss-only"
            print_info "选择操作: 仅安装 shadowsocks-libev"
            break
            ;;
        2)
            OPERATION_MODE="install-ss-with-tls"
            print_info "选择操作: 安装 shadowsocks-libev + shadow-tls"
            break
            ;;
        3)
            OPERATION_MODE="uninstall-ss-only"
            print_info "选择操作: 卸载 shadowsocks-libev"
            break
            ;;
        4)
            OPERATION_MODE="uninstall-ss-with-tls"
            print_info "选择操作: 卸载 shadowsocks-libev + shadow-tls"
            break
            ;;
        5)
            OPERATION_MODE="uninstall-all"
            print_info "选择操作: 完全卸载所有组件"
            break
            ;;
        *)
            echo "请输入 0-5 中的数字"
            ;;
    esac
done

echo ""

# Function to uninstall shadowsocks-libev
uninstall_shadowsocks() {
    print_info "开始卸载 shadowsocks-libev..."

    # Stop and disable service
    if systemctl is-active --quiet shadowsocks-libev 2>/dev/null; then
        print_warning "停止 shadowsocks-libev 服务..."
        systemctl stop shadowsocks-libev
    fi

    if systemctl is-enabled --quiet shadowsocks-libev 2>/dev/null; then
        print_warning "禁用 shadowsocks-libev 服务..."
        systemctl disable shadowsocks-libev
    fi

    # Remove package
    if dpkg -l | grep -q shadowsocks-libev; then
        print_warning "卸载 shadowsocks-libev 软件包..."
        apt remove -y shadowsocks-libev > /dev/null 2>&1
    fi

    # Remove configuration files
    if [ -f /etc/shadowsocks-libev/config.json ]; then
        if ask_yes_no "是否删除 shadowsocks-libev 配置文件？"; then
            print_warning "删除配置文件..."
            rm -rf /etc/shadowsocks-libev/
        fi
    fi

    print_success "Shadowsocks-libev 卸载完成"
}

# Function to uninstall shadow-tls
uninstall_shadow_tls() {
    print_info "开始卸载 shadow-tls..."

    # Stop and disable service
    if systemctl is-active --quiet shadow-tls 2>/dev/null; then
        print_warning "停止 shadow-tls 服务..."
        systemctl stop shadow-tls
    fi

    if systemctl is-enabled --quiet shadow-tls 2>/dev/null; then
        print_warning "禁用 shadow-tls 服务..."
        systemctl disable shadow-tls
    fi

    # Remove service file
    if [ -f /etc/systemd/system/shadow-tls.service ]; then
        print_warning "删除 shadow-tls 服务文件..."
        rm -f /etc/systemd/system/shadow-tls.service
        systemctl daemon-reload
    fi

    # Remove binary
    if [ -f /usr/local/bin/shadow-tls ]; then
        print_warning "删除 shadow-tls 二进制文件..."
        rm -f /usr/local/bin/shadow-tls
    fi

    print_success "Shadow-tls 卸载完成"
}

# Handle uninstall operations
if [ "$OPERATION_MODE" = "uninstall-ss-only" ]; then
    if ! command -v ss-server >/dev/null 2>&1; then
        print_warning "未检测到 shadowsocks-libev 安装"
        exit 0
    fi
    if ask_yes_no "确认要卸载 shadowsocks-libev 吗？"; then
        uninstall_shadowsocks
        print_success "=== 卸载完成 ==="
    else
        print_info "取消卸载操作"
    fi
    exit 0
fi

if [ "$OPERATION_MODE" = "uninstall-ss-with-tls" ]; then
    FOUND_SS=false
    FOUND_TLS=false

    if command -v ss-server >/dev/null 2>&1; then
        FOUND_SS=true
    fi

    if [ -f /usr/local/bin/shadow-tls ]; then
        FOUND_TLS=true
    fi

    if [ "$FOUND_SS" = false ] && [ "$FOUND_TLS" = false ]; then
        print_warning "未检测到 shadowsocks-libev 或 shadow-tls 安装"
        exit 0
    fi

    if ask_yes_no "确认要卸载 shadowsocks-libev 和 shadow-tls 吗？"; then
        if [ "$FOUND_TLS" = true ]; then
            uninstall_shadow_tls
        fi
        if [ "$FOUND_SS" = true ]; then
            uninstall_shadowsocks
        fi
        print_success "=== 卸载完成 ==="
    else
        print_info "取消卸载操作"
    fi
    exit 0
fi

if [ "$OPERATION_MODE" = "uninstall-all" ]; then
    FOUND_SS=false
    FOUND_TLS=false

    if command -v ss-server >/dev/null 2>&1; then
        FOUND_SS=true
    fi

    if [ -f /usr/local/bin/shadow-tls ]; then
        FOUND_TLS=true
    fi

    if [ "$FOUND_SS" = false ] && [ "$FOUND_TLS" = false ]; then
        print_warning "未检测到任何已安装的组件"
        exit 0
    fi

    echo -e "\033[1;31m警告: 这将完全卸载所有 shadowsocks 和 shadow-tls 组件！\033[0m"
    if ask_yes_no "确认要完全卸载所有组件吗？"; then
        if [ "$FOUND_TLS" = true ]; then
            uninstall_shadow_tls
        fi
        if [ "$FOUND_SS" = true ]; then
            uninstall_shadowsocks
        fi

        # Clean up any remaining files
        print_info "清理残留文件..."
        [ -d /etc/shadowsocks-libev ] && rm -rf /etc/shadowsocks-libev/
        [ -f /usr/local/bin/shadow-tls ] && rm -f /usr/local/bin/shadow-tls
        [ -f /etc/systemd/system/shadow-tls.service ] && rm -f /etc/systemd/system/shadow-tls.service
        systemctl daemon-reload

        print_success "=== 完全卸载完成 ==="
    else
        print_info "取消卸载操作"
    fi
    exit 0
fi

# Check existing installations for install operations
SS_INSTALLED=false
SHADOW_TLS_INSTALLED=false

if command -v ss-server >/dev/null 2>&1; then
    SS_INSTALLED=true
    print_warning "检测到已安装 shadowsocks-libev"
fi

if [ -f /usr/local/bin/shadow-tls ]; then
    SHADOW_TLS_INSTALLED=true
    print_warning "检测到已安装 shadow-tls"
fi

# Handle existing shadowsocks-libev installation
REINSTALL_SS=false
if [ "$SS_INSTALLED" = true ]; then
    echo ""
    if ask_yes_no "是否重新安装 shadowsocks-libev？"; then
        REINSTALL_SS=true
        print_info "将重新安装 shadowsocks-libev"
    else
        print_info "将保留现有 shadowsocks-libev 安装"
    fi
fi

# Handle existing shadow-tls installation (if needed)
REINSTALL_SHADOW_TLS=false
if [ "$OPERATION_MODE" = "install-ss-with-tls" ] && [ "$SHADOW_TLS_INSTALLED" = true ]; then
    echo ""
    if ask_yes_no "是否重新安装 shadow-tls？"; then
        REINSTALL_SHADOW_TLS=true
        print_info "将重新安装 shadow-tls"
    else
        print_info "将保留现有 shadow-tls 安装"
    fi
fi

echo ""
print_info "开始安装..."

# Update system
print_success "更新系统包列表..."
apt update > /dev/null 2>&1

# Install or configure shadowsocks-libev
if [ "$SS_INSTALLED" = false ] || [ "$REINSTALL_SS" = true ]; then
    print_success "安装 shadowsocks-libev..."
    apt install -y shadowsocks-libev openssl curl > /dev/null 2>&1

    # Generate random password if new installation
    if [ ! -f /etc/shadowsocks-libev/config.json ] || [ "$REINSTALL_SS" = true ]; then
        SS_PASSWORD=$(openssl rand -base64 16)
        print_warning "生成新的 shadowsocks 密码: $SS_PASSWORD"

        # Create shadowsocks configuration
        cat > /etc/shadowsocks-libev/config.json << EOF
{
    "server":["::1", "127.0.0.1"],
    "server_port":8388,
    "method":"aes-128-gcm",
    "password":"$SS_PASSWORD",
    "timeout":300,
    "fast_open":true
}
EOF
    fi
else
    print_info "使用现有 shadowsocks-libev 安装"
fi

# Read shadowsocks password
if [ -f /etc/shadowsocks-libev/config.json ]; then
    SS_PASSWORD=$(grep -o '"password":"[^"]*' /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    # Ensure method is aes-128-gcm
    sed -i 's/"method":"[^"]*"/"method":"aes-128-gcm"/' /etc/shadowsocks-libev/config.json
    print_success "已确保加密方法为 aes-128-gcm"
else
    print_error "错误: shadowsocks-libev 配置文件不存在"
    exit 1
fi

# Install shadow-tls if selected
if [ "$OPERATION_MODE" = "install-ss-with-tls" ]; then
    if [ "$SHADOW_TLS_INSTALLED" = false ] || [ "$REINSTALL_SHADOW_TLS" = true ]; then
        # Detect system architecture
        print_info "检测系统架构..."
        ARCH=$(uname -m)
        case $ARCH in
            x86_64)
                SHADOW_TLS_BINARY="shadow-tls-x86_64-unknown-linux-musl"
                print_success "检测到架构: x86_64"
                ;;
            aarch64|arm64)
                SHADOW_TLS_BINARY="shadow-tls-aarch64-unknown-linux-musl"
                print_success "检测到架构: ARM64"
                ;;
            *)
                print_error "不支持的架构: $ARCH"
                print_error "支持的架构: x86_64, aarch64/arm64"
                exit 1
                ;;
        esac

        # Stop existing shadow-tls service if running
        if systemctl is-active --quiet shadow-tls 2>/dev/null; then
            print_warning "停止现有 shadow-tls 服务..."
            systemctl stop shadow-tls
            sleep 2
        fi

        # Download shadow-tls binary
        print_success "下载 shadow-tls ($ARCH)..."
        if [ -f /usr/local/bin/shadow-tls ]; then
            rm -f /usr/local/bin/shadow-tls
        fi

        if ! wget "https://github.com/ihciah/shadow-tls/releases/latest/download/$SHADOW_TLS_BINARY" -O /usr/local/bin/shadow-tls -q; then
            print_error "下载 shadow-tls 失败"
            exit 1
        fi

        chmod +x /usr/local/bin/shadow-tls
        print_success "Shadow-TLS 安装成功"

        # Generate or reuse shadow-tls password
        if [ "$REINSTALL_SHADOW_TLS" = true ] || [ ! -f /etc/systemd/system/shadow-tls.service ]; then
            SHADOW_TLS_PASSWORD=$(openssl rand -base64 16)
            print_warning "生成新的 shadow-tls 密码: $SHADOW_TLS_PASSWORD"
        else
            # Try to extract existing password
            if [ -f /etc/systemd/system/shadow-tls.service ]; then
                SHADOW_TLS_PASSWORD=$(grep -o 'password [^[:space:]]*' /etc/systemd/system/shadow-tls.service | cut -d' ' -f2 2>/dev/null || openssl rand -base64 16)
            else
                SHADOW_TLS_PASSWORD=$(openssl rand -base64 16)
            fi
        fi

        # Create shadow-tls systemd service
        print_info "创建 shadow-tls 系统服务..."
        cat > /etc/systemd/system/shadow-tls.service << EOF
[Unit]
Description=Shadow-TLS Server Service
Documentation=man:sstls-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=shadow-tls --fastopen --v3 server --listen ::0:443 --server 127.0.0.1:8388 --tls gateway.icloud.com --password $SHADOW_TLS_PASSWORD
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=shadow-tls
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

        # Enable shadow-tls service
        systemctl enable shadow-tls.service
        systemctl daemon-reload
    else
        print_info "使用现有 shadow-tls 安装"
        # Extract existing password
        SHADOW_TLS_PASSWORD=$(grep -o 'password [^[:space:]]*' /etc/systemd/system/shadow-tls.service | cut -d' ' -f2 2>/dev/null || echo "未找到密码")
    fi
fi

# Start/restart services
print_info "启动服务..."

# Start shadowsocks-libev
systemctl enable shadowsocks-libev
systemctl restart shadowsocks-libev

if [ "$OPERATION_MODE" = "install-ss-with-tls" ]; then
    # Start shadow-tls
    systemctl restart shadow-tls.service
fi

# Wait a moment for services to start
sleep 3

# Get public IP addresses
print_info "获取公网 IP 地址..."
PUBLIC_IPV4=$(curl -4 -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "Not available")
PUBLIC_IPV6=$(curl -6 -s --connect-timeout 10 ifconfig.me 2>/dev/null || echo "Not available")

# Display results
echo ""
print_success "=== 安装完成 ==="

if [ "$OPERATION_MODE" = "install-ss-only" ]; then
    print_warning "Shadowsocks 服务运行在端口 8388"
    echo ""
    print_info "=== 配置信息 ==="

    if [ "$PUBLIC_IPV4" != "Not available" ]; then
        echo -e "\033[1;36mSS-IPv4 = ss, $PUBLIC_IPV4, 8388, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, udp-relay=true\033[0m"
    fi

    if [ "$PUBLIC_IPV6" != "Not available" ]; then
        echo -e "\033[1;36mSS-IPv6 = ss, $PUBLIC_IPV6, 8388, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, udp-relay=true\033[0m"
    fi

elif [ "$OPERATION_MODE" = "install-ss-with-tls" ]; then
    print_warning "Shadowsocks 服务运行在端口 8388"
    print_warning "Shadow-TLS 服务运行在端口 443"
    echo ""
    print_info "=== 配置信息 ==="

    if [ "$PUBLIC_IPV4" != "Not available" ]; then
        echo -e "\033[1;36mSS-IPv4 = ss, $PUBLIC_IPV4, 443, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, udp-relay=true, shadow-tls-password=\"$SHADOW_TLS_PASSWORD\", shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3\033[0m"
    fi

    if [ "$PUBLIC_IPV6" != "Not available" ]; then
        echo -e "\033[1;36mSS-IPv6 = ss, $PUBLIC_IPV6, 443, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, udp-relay=true, shadow-tls-password=\"$SHADOW_TLS_PASSWORD\", shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3\033[0m"
    fi
fi

echo ""
print_info "服务状态:"
echo "Shadowsocks-libev:"
systemctl status shadowsocks-libev --no-pager -l | head -3

if [ "$OPERATION_MODE" = "install-ss-with-tls" ]; then
    echo "Shadow-TLS:"
    systemctl status shadow-tls --no-pager -l | head -3
fi

echo ""
print_success "安装脚本执行完毕！"
