#!/bin/bash

# ============================================
# GRE Tunnel Setup Script v2.0 - Enhanced
# GitHub: netplas
# ============================================

# Colors for better output
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
RESET=$(tput sgr0)
BOLD=$(tput bold)

# Function to show header
show_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "============================================"
    echo "        GitHub: netplas"
    echo "   GRE Tunnel v2.0 - Enhanced Setup"
    echo "============================================"
    echo -e "${RESET}"
}

# Function to check root access
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] This script must be run as root${RESET}"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    local deps=("ip" "iptables" "sysctl" "ping")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v $dep &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Missing dependencies: ${missing[*]}${RESET}"
        echo "Installing required packages..."
        
        if command -v apt &> /dev/null; then
            apt update && apt install -y iproute2 iptables procps iputils-ping
        elif command -v yum &> /dev/null; then
            yum install -y iproute iptables procps-ng iputils
        elif command -v dnf &> /dev/null; then
            dnf install -y iproute iptables procps-ng iputils
        else
            echo -e "${RED}[!] Cannot install dependencies automatically${RESET}"
            exit 1
        fi
    fi
}

# Function to check internet connection
check_internet() {
    echo -n "[*] Checking internet connection... "
    if ping -c 2 -W 3 8.8.8.8 &> /dev/null; then
        echo -e "${GREEN}OK${RESET}"
    else
        echo -e "${YELLOW}Warning: No internet connection${RESET}"
    fi
}

# Function to setup IRAN server
setup_iran() {
    echo -e "${CYAN}[*] Configuring IRAN Server...${RESET}"
    
    # 1. Remove existing tunnel if exists
    echo "[1] Cleaning up existing tunnel..."
    ip link del netplas-m2 2>/dev/null
    
    # 2. Set MTU on main interface
    echo "[2] Setting MTU on main interface..."
    ip link set dev eth0 mtu 1500 2>/dev/null || echo "Warning: Could not set MTU on eth0"
    
    # 3. Create GRE tunnel
    echo "[3] Creating GRE tunnel..."
    ip tunnel add netplas-m2 mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create tunnel${RESET}"
        return 1
    fi
    
    # 4. Activate and configure tunnel IP
    echo "[4] Configuring tunnel interface..."
    ip link set netplas-m2 up mtu 1476
    ip addr add 132.168.30.2/30 dev netplas-m2
    ip route add 132.168.30.0/30 dev netplas-m2
    
    # 5. Sysctl settings
    echo "[5] Configuring kernel parameters..."
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.forwarding=1
    sysctl -w net.ipv4.conf.default.forwarding=1
    sysctl -w net.ipv4.gre.keepalive_probes=30
    sysctl -w net.ipv4.gre.keepalive_intvl=5
    sysctl -w net.ipv4.gre.keepalive_time=30
    sysctl -w net.ipv4.tcp_mtu_probing=2
    sysctl -w net.ipv4.tcp_sack=1
    sysctl -w net.ipv4.tcp_window_scaling=1
    
    # 6. Iptables configuration
    echo "[6] Configuring iptables rules..."
    
    # Clean previous rules
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F
    
    # Set MSS for tunnel
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o netplas-m2 -j TCPMSS --set-mss 1380
    
    # NAT Rules
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2
    iptables -t nat -A PREROUTING -i eth0 -d $IP_IRAN -j DNAT --to-destination 132.168.30.1
    
    # Route traffic from tunnel
    iptables -t nat -A POSTROUTING -o netplas-m2 -j MASQUERADE
    
    # Allow ICMP (for ping)
    iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
    
    # 7. QoS with tc
    echo "[7] Setting up QoS..."
    tc qdisc add dev netplas-m2 root fq 2>/dev/null || echo "tc not available, skipping QoS"
    
    echo -e "${GREEN}[+] IRAN server configuration completed${RESET}"
    return 0
}

# Function to setup FOREIGN server
setup_foreign() {
    echo -e "${CYAN}[*] Configuring FOREIGN Server...${RESET}"
    
    # 1. Remove existing tunnel
    echo "[1] Cleaning up existing tunnel..."
    ip link del netplas-m2 2>/dev/null
    
    # 2. Create GRE tunnel
    echo "[2] Creating GRE tunnel..."
    ip tunnel add netplas-m2 mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create tunnel${RESET}"
        return 1
    fi
    
    # 3. Activate and configure tunnel IP
    echo "[3] Configuring tunnel interface..."
    ip link set netplas-m2 up mtu 1476
    ip addr add 132.168.30.1/30 dev netplas-m2
    ip route add 132.168.30.0/30 dev netplas-m2
    
    # 4. Sysctl settings
    echo "[4] Configuring kernel parameters..."
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.forwarding=1
    sysctl -w net.ipv4.conf.default.forwarding=1
    sysctl -w net.ipv4.gre.keepalive_probes=30
    sysctl -w net.ipv4.gre.keepalive_intvl=5
    sysctl -w net.ipv4.gre.keepalive_time=30
    
    # 5. Iptables configuration
    echo "[5] Configuring iptables rules..."
    
    # Clean rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    
    # Block ICMP from outside (security)
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    # Set MSS for tunnel
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -o netplas-m2 -j TCPMSS --set-mss 1380
    
    # 6. QoS
    echo "[6] Setting up QoS..."
    tc qdisc add dev netplas-m2 root fq 2>/dev/null || echo "tc not available, skipping QoS"
    
    echo -e "${GREEN}[+] FOREIGN server configuration completed${RESET}"
    return 0
}

# Function to test tunnel
test_tunnel() {
    echo -e "${CYAN}[*] Testing tunnel connection...${RESET}"
    
    if [[ "$LOCATION" == "1" ]]; then
        # Test from IRAN side
        echo "[1] Testing connectivity to FOREIGN server..."
        if ping -c 3 -I netplas-m2 132.168.30.1 &> /dev/null; then
            echo -e "${GREEN}[+] Ping to FOREIGN (132.168.30.1): SUCCESS${RESET}"
        else
            echo -e "${RED}[!] Ping to FOREIGN: FAILED${RESET}"
            return 1
        fi
        
        echo "[2] Checking tunnel interface..."
        if ip link show netplas-m2 &> /dev/null; then
            echo -e "${GREEN}[+] Tunnel interface exists${RESET}"
        else
            echo -e "${RED}[!] Tunnel interface not found${RESET}"
            return 1
        fi
        
        echo "[3] Checking routing table..."
        ip route show | grep netplas-m2 && echo -e "${GREEN}[+] Route configured${RESET}" || echo -e "${YELLOW}[!] Route not found${RESET}"
        
    elif [[ "$LOCATION" == "2" ]]; then
        # Test from FOREIGN side
        echo "[1] Testing connectivity to IRAN server..."
        if ping -c 3 -I netplas-m2 132.168.30.2 &> /dev/null; then
            echo -e "${GREEN}[+] Ping to IRAN (132.168.30.2): SUCCESS${RESET}"
        else
            echo -e "${RED}[!] Ping to IRAN: FAILED${RESET}"
            return 1
        fi
        
        echo "[2] Checking ICMP blocking..."
        if ping -c 2 $IP_FOREIGN &> /dev/null; then
            echo -e "${YELLOW}[!] ICMP is NOT blocked on public IP${RESET}"
        else
            echo -e "${GREEN}[+] ICMP blocked on public IP (security)${RESET}"
        fi
    fi
    
    echo "[4] Testing tunnel MTU..."
    local if_mtu=$(ip link show netplas-m2 | grep -o 'mtu [0-9]*' | awk '{print $2}')
    if [[ "$if_mtu" == "1476" ]]; then
        echo -e "${GREEN}[+] Tunnel MTU is correctly set to 1476${RESET}"
    else
        echo -e "${YELLOW}[!] Tunnel MTU is $if_mtu (expected 1476)${RESET}"
    fi
    
    return 0
}

# Function to show tunnel status
show_status() {
    echo -e "${CYAN}${BOLD}"
    echo "============================================"
    echo "          TUNNEL STATUS REPORT"
    echo "============================================"
    echo -e "${RESET}"
    
    echo -e "${BOLD}Tunnel Interface:${RESET}"
    ip link show netplas-m2 2>/dev/null || echo "Tunnel not found"
    
    echo -e "\n${BOLD}IP Addresses:${RESET}"
    ip addr show netplas-m2 2>/dev/null | grep -E "inet|mtu"
    
    echo -e "\n${BOLD}Routing Table:${RESET}"
    ip route show | grep netplas-m2 || echo "No routes found for tunnel"
    
    echo -e "\n${BOLD}Kernel Parameters:${RESET}"
    sysctl -n net.ipv4.ip_forward
    sysctl -n net.ipv4.gre.keepalive_time
    
    echo -e "\n${BOLD}IPTables Rules:${RESET}"
    iptables -L -n -v | grep -E "Chain|netplas" | head -20
    
    echo -e "\n${BOLD}Traffic Statistics:${RESET}"
    ip -s link show netplas-m2 2>/dev/null | grep -A2 "RX\|TX"
}

# Function to create systemd service
create_service() {
    echo -e "${CYAN}[*] Creating systemd service...${RESET}"
    
    local service_file="/etc/systemd/system/gre-tunnel.service"
    
    cat > $service_file << EOF
[Unit]
Description=GRE Tunnel Service
After=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/gre-tunnel-start.sh
ExecStop=/usr/local/bin/gre-tunnel-stop.sh
ExecReload=/bin/kill -HUP \$MAINPID

[Install]
WantedBy=multi-user.target
EOF
    
    # Create start script
    cat > /usr/local/bin/gre-tunnel-start.sh << 'EOF'
#!/bin/bash
# This script has already run and configurations are applied
# Just check status
ip link show netplas-m2 &> /dev/null && echo "GRE tunnel is running"
EOF
    
    # Create stop script
    cat > /usr/local/bin/gre-tunnel-stop.sh << 'EOF'
#!/bin/bash
# Stop tunnel
ip link del netplas-m2 2>/dev/null && echo "GRE tunnel stopped"
EOF
    
    chmod +x /usr/local/bin/gre-tunnel-*.sh
    systemctl daemon-reload
    
    echo -e "${GREEN}[+] Systemd service created${RESET}"
    echo "To enable auto-start: systemctl enable gre-tunnel"
}

# Function to create monitoring script
create_monitor_script() {
    echo -e "${CYAN}[*] Creating monitoring script...${RESET}"
    
    cat > /usr/local/bin/monitor-gre.sh << 'EOF'
#!/bin/bash

TUNNEL_IP="132.168.30.1"
LOG_FILE="/var/log/gre-tunnel.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

# Check if tunnel exists
if ! ip link show netplas-m2 &> /dev/null; then
    log "ERROR: Tunnel interface not found!"
    exit 1
fi

# Ping test
if ping -c 3 -I netplas-m2 $TUNNEL_IP &> /dev/null; then
    log "Tunnel is UP - Ping successful"
    exit 0
else
    log "ERROR: Tunnel is DOWN - Ping failed"
    
    # Try to restart
    systemctl restart gre-tunnel 2>/dev/null
    log "Attempted to restart tunnel service"
    exit 1
fi
EOF
    
    chmod +x /usr/local/bin/monitor-gre.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/5 * * * * /usr/local/bin/monitor-gre.sh") | crontab -
    
    echo -e "${GREEN}[+] Monitoring script installed (runs every 5 minutes)${RESET}"
}

# Function to validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# Main function
main() {
    show_header
    check_root
    check_dependencies
    check_internet
    
    echo "Select server location:"
    echo "1 - IRAN"
    echo "2 - FOREIGN"
    read -p "Enter 1 or 2: " LOCATION
    
    if [[ "$LOCATION" != "1" && "$LOCATION" != "2" ]]; then
        echo -e "${RED}[!] Invalid selection. Please enter 1 or 2.${RESET}"
        exit 1
    fi
    
    read -p "Enter IRAN server IP: " IP_IRAN
    read -p "Enter FOREIGN server IP: " IP_FOREIGN
    
    # Validate IPs
    if ! validate_ip "$IP_IRAN"; then
        echo -e "${RED}[!] Invalid IRAN IP address${RESET}"
        exit 1
    fi
    
    if ! validate_ip "$IP_FOREIGN"; then
        echo -e "${RED}[!] Invalid FOREIGN IP address${RESET}"
        exit 1
    fi
    
    # Show configuration summary
    echo -e "${YELLOW}"
    echo "Configuration Summary:"
    echo "======================"
    echo "Server Location: $([ "$LOCATION" == "1" ] && echo "IRAN" || echo "FOREIGN")"
    echo "IRAN IP: $IP_IRAN"
    echo "FOREIGN IP: $IP_FOREIGN"
    echo "Tunnel Network: 132.168.30.0/30"
    echo "IRAN Tunnel IP: 132.168.30.2"
    echo "FOREIGN Tunnel IP: 132.168.30.1"
    echo -e "${RESET}"
    
    read -p "Continue with setup? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Setup cancelled."
        exit 0
    fi
    
    # Run setup based on location
    if [[ "$LOCATION" == "1" ]]; then
        setup_iran
    elif [[ "$LOCATION" == "2" ]]; then
        setup_foreign
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Setup failed${RESET}"
        exit 1
    fi
    
    # Test tunnel
    test_tunnel
    
    # Show status
    echo -e "\n"
    read -p "Show tunnel status? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        show_status
    fi
    
    # Ask to create services
    echo -e "\n"
    read -p "Create systemd service and monitoring? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_service
        create_monitor_script
    fi
    
    # Final instructions
    echo -e "${GREEN}${BOLD}"
    echo "============================================"
    echo "          SETUP COMPLETED SUCCESSFULLY"
    echo "============================================"
    echo -e "${RESET}"
    
    echo "Next steps:"
    echo "1. Test connectivity: ping -I netplas-m2 132.168.30.X"
    echo "2. Check tunnel status: ip link show netplas-m2"
    echo "3. View traffic: ip -s link show netplas-m2"
    echo "4. To enable auto-start: systemctl enable gre-tunnel"
    echo "5. Monitor logs: tail -f /var/log/gre-tunnel.log"
    
    echo -e "\n${YELLOW}Tunnel IPs:${RESET}"
    echo "IRAN: 132.168.30.2"
    echo "FOREIGN: 132.168.30.1"
}

# Run main function
main
