#!/bin/bash

# Shadowsocks-libev + Shadow-TLS Setup Script
# This script installs and configures shadowsocks-libev with shadow-tls

set -e

echo -e "\033[1;34m=== Shadowsocks-libev + Shadow-TLS Setup Script ===\033[0m"

# Update system and install shadowsocks-libev
echo -e "\033[1;32mUpdating system and installing shadowsocks-libev...\033[0m"
apt update > /dev/null 2>&1
apt install -y shadowsocks-libev openssl curl > /dev/null 2>&1

# Modify shadowsocks configuration to use aes-128-gcm
echo -e "\033[1;33mModifying shadowsocks configuration...\033[0m"
if [ -f /etc/shadowsocks-libev/config.json ]; then
    # Read the current password from config
    SS_PASSWORD=$(grep -o '"password":"[^"]*' /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
    
    # Update method to aes-128-gcm
    sed -i 's/"method":"[^"]*"/"method":"aes-128-gcm"/' /etc/shadowsocks-libev/config.json
    echo -e "\033[1;32mUpdated encryption method to aes-128-gcm\033[0m"
else
    echo -e "\033[1;31mError: /etc/shadowsocks-libev/config.json not found\033[0m"
    exit 1
fi

# Detect system architecture
echo -e "\033[1;36mDetecting system architecture...\033[0m"
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        SHADOW_TLS_BINARY="shadow-tls-x86_64-unknown-linux-musl"
        echo -e "\033[1;32mDetected architecture: x86_64\033[0m"
        ;;
    aarch64|arm64)
        SHADOW_TLS_BINARY="shadow-tls-aarch64-unknown-linux-musl"
        echo -e "\033[1;32mDetected architecture: ARM64\033[0m"
        ;;
    *)
        echo -e "\033[1;31mUnsupported architecture: $ARCH\033[0m"
        echo -e "\033[1;31mSupported architectures: x86_64, aarch64/arm64\033[0m"
        exit 1
        ;;
esac

# Stop existing shadow-tls service if running
if systemctl is-active --quiet shadow-tls; then
    echo -e "\033[1;33mStopping existing shadow-tls service...\033[0m"
    systemctl stop shadow-tls
    sleep 2
fi

# Download shadow-tls binary
echo -e "\033[1;35mDownloading shadow-tls binary for $ARCH...\033[0m"
# Remove old binary if exists
if [ -f /usr/local/bin/shadow-tls ]; then
    rm -f /usr/local/bin/shadow-tls
fi

wget "https://github.com/ihciah/shadow-tls/releases/latest/download/$SHADOW_TLS_BINARY" -O /usr/local/bin/shadow-tls -q

# Make shadow-tls executable
chmod +x /usr/local/bin/shadow-tls
echo -e "\033[1;32mShadow-TLS binary installed successfully\033[0m"

# Generate random password for shadow-tls
SHADOW_TLS_PASSWORD=$(openssl rand -base64 16)
echo -e "\033[1;33mGenerated shadow-tls password: $SHADOW_TLS_PASSWORD\033[0m"

# Create shadow-tls systemd service
echo -e "\033[1;36mCreating shadow-tls systemd service...\033[0m"
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

[Install]
WantedBy=multi-user.target
EOF

# Enable and start services
echo -e "\033[1;34mEnabling and starting services...\033[0m"
systemctl enable shadow-tls.service
systemctl daemon-reload

# Restart shadowsocks-libev to apply new configuration
systemctl restart shadowsocks-libev

# Start shadow-tls
systemctl start shadow-tls.service

# Get public IPv4 and IPv6 addresses
echo -e "\033[1;36mDetecting public IP addresses...\033[0m"
PUBLIC_IPV4=$(curl -4 -s ifconfig.me || echo "Not available")
PUBLIC_IPV6=$(curl -6 -s ifconfig.me || echo "Not available")

# Read passwords from configuration files
SS_PASSWORD=$(grep -o '"password":"[^"]*' /etc/shadowsocks-libev/config.json | cut -d'"' -f4)
SHADOW_TLS_PASSWORD=$(grep -o 'password [^[:space:]]*' /etc/systemd/system/shadow-tls.service | cut -d' ' -f2)

echo ""
echo -e "\033[1;32m=== Setup Complete ===\033[0m"
echo -e "\033[1;33mShadowsocks server is running on port 8388\033[0m"
echo -e "\033[1;33mShadow-TLS server is running on port 443\033[0m"
echo ""

# Output configuration in the requested format
echo -e "\033[1;34m=== Configuration Output ===\033[0m"
if [ "$PUBLIC_IPV4" != "Not available" ]; then
    echo -e "\033[1;36mSS-IPv4 = ss, $PUBLIC_IPV4, 443, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, shadow-tls-password=\"$SHADOW_TLS_PASSWORD\", shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3, udp-relay=true\033[0m"
fi

if [ "$PUBLIC_IPV6" != "Not available" ]; then
    echo -e "\033[1;36mSS-IPv6 = ss, $PUBLIC_IPV6, 443, encrypt-method=aes-128-gcm, password=$SS_PASSWORD, tfo=true, shadow-tls-password=\"$SHADOW_TLS_PASSWORD\", shadow-tls-sni=gateway.icloud.com, shadow-tls-version=3, udp-relay=true\033[0m"
fi

echo ""
echo -e "\033[1;35mService Status:\033[0m"
systemctl status shadowsocks-libev --no-pager -l | head -3
systemctl status shadow-tls --no-pager -l | head -3
