#!/bin/bash

# ============================================
# GRE Tunnel Setup Script v3.0 - Performance Optimized
# GitHub: netplas
# ============================================

# Colors for better output
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
GREEN=$(tput setaf 2)
RED=$(tput setaf 1)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)
BOLD=$(tput bold)

# Function to show header
show_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "============================================"
    echo "        GitHub: netplas"
    echo "   GRE Tunnel v3.0 - Performance Optimized"
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

# Function to check and install dependencies
install_dependencies() {
    echo -e "${CYAN}[*] Checking and installing dependencies...${RESET}"
    
    local pkgs=""
    
    if command -v apt &> /dev/null; then
        pkgs="iproute2 iptables iptables-persistent net-tools iputils-ping ethtool"
        apt update && apt install -y $pkgs
    elif command -v yum &> /dev/null; then
        pkgs="iproute iptables iptables-services net-tools iputils ethtool"
        yum install -y $pkgs
    elif command -v dnf &> /dev/null; then
        dnf install -y $pkgs
    fi
    
    # Check for BBR availability
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q bbr; then
        echo -e "${YELLOW}[!] BBR not available in kernel${RESET}"
    fi
}

# Function to optimize system for GRE tunnel
optimize_system() {
    echo -e "${CYAN}[*] Optimizing system parameters...${RESET}"
    
    # TCP Optimization
    cat >> /etc/sysctl.conf << EOF

# GRE Tunnel Optimizations
# TCP Settings
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# GRE Specific
net.ipv4.gre.flush = 1
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.route.flush = 1

# Forwarding
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.default.forwarding = 1
net.ipv6.conf.all.forwarding = 1
EOF

    # Apply immediately
    sysctl -p
}

# Function to calculate optimal MTU
calculate_mtu() {
    local public_iface=$(ip route | grep default | awk '{print $5}' | head -1)
    local base_mtu=$(ip link show $public_iface 2>/dev/null | grep mtu | awk '{print $5}')
    
    if [[ -z "$base_mtu" ]]; then
        echo "1476"  # Default if cannot detect
    else
        # GRE adds 24 bytes overhead, so subtract that
        local tunnel_mtu=$((base_mtu - 24))
        echo "$tunnel_mtu"
    fi
}

# Function to setup IRAN server
setup_iran() {
    echo -e "${CYAN}[*] Configuring IRAN Server (Performance Mode)...${RESET}"
    
    # Remove existing tunnel
    ip link del netplas-m2 2>/dev/null
    
    # Get optimal MTU
    local OPTIMAL_MTU=$(calculate_mtu)
    echo "[+] Using MTU: $OPTIMAL_MTU"
    
    # Create GRE tunnel with optimal parameters
    echo "[1] Creating optimized GRE tunnel..."
    ip tunnel add netplas-m2 mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255 tos inherit
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create tunnel${RESET}"
        return 1
    fi
    
    # Configure interface with performance settings
    echo "[2] Configuring tunnel interface..."
    ip link set netplas-m2 up mtu $OPTIMAL_MTU txqueuelen 1000
    ip addr add 132.168.30.2/30 dev netplas-m2
    ip route add 132.168.30.0/30 dev netplas-m2
    
    # Add default route through tunnel for specific traffic
    ip route add default via 132.168.30.1 dev netplas-m2 metric 100
    
    # Enable TCP BBR if available
    echo "[3] Enabling TCP optimizations..."
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || echo "BBR not available"
    sysctl -w net.ipv4.tcp_notsent_lowat=16384
    sysctl -w net.ipv4.tcp_mtu_probing=1
    
    # Configure iptables for performance
    echo "[4] Configuring iptables for performance..."
    
    # Flush existing rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    
    # MSS Clamping (CRITICAL for performance)
    iptables -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
    
    # Specific MSS for GRE tunnel
    local MSS_VALUE=$((OPTIMAL_MTU - 40))
    iptables -t mangle -A POSTROUTING -o netplas-m2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE
    
    # NAT Configuration
    iptables -t nat -A PREROUTING -p tcp --dport 22 -j DNAT --to-destination 132.168.30.2
    iptables -t nat -A PREROUTING -i eth0 -d $IP_IRAN -j DNAT --to-destination 132.168.30.1
    
    # Performance-focused MASQUERADE
    iptables -t nat -A POSTROUTING -o netplas-m2 -j MASQUERADE --random-fully
    
    # Connection tracking optimization
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Setup traffic shaping with tc (if available)
    echo "[5] Setting up traffic shaping..."
    if command -v tc &> /dev/null; then
        # Clean existing qdisc
        tc qdisc del dev netplas-m2 root 2>/dev/null
        
        # FQ_Codel for better latency under load
        tc qdisc add dev netplas-m2 root fq_codel quantum 300 limit 10240 flows 4096
        
        # If you know your bandwidth, you can add shaping:
        # tc qdisc add dev netplas-m2 root tbf rate 100mbit burst 256kbit latency 50ms
    else
        echo "tc not available, skipping traffic shaping"
    fi
    
    # Enable IRQ balancing for better CPU utilization
    if [ -f /proc/interrupts ] && command -v ethtool &> /dev/null; then
        echo "[6] Optimizing network interrupts..."
        ethtool -C eth0 rx-usecs 8 rx-frames 32 2>/dev/null || true
        ethtool -K eth0 gro on gso on tso on 2>/dev/null || true
    fi
    
    # Create persistent configuration
    create_persistent_config
    
    echo -e "${GREEN}[+] IRAN server configured for performance${RESET}"
    return 0
}

# Function to setup FOREIGN server
setup_foreign() {
    echo -e "${CYAN}[*] Configuring FOREIGN Server (Performance Mode)...${RESET}"
    
    # Remove existing tunnel
    ip link del netplas-m2 2>/dev/null
    
    # Get optimal MTU
    local OPTIMAL_MTU=$(calculate_mtu)
    echo "[+] Using MTU: $OPTIMAL_MTU"
    
    # Create GRE tunnel
    echo "[1] Creating optimized GRE tunnel..."
    ip tunnel add netplas-m2 mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255 tos inherit
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Failed to create tunnel${RESET}"
        return 1
    fi
    
    # Configure interface
    echo "[2] Configuring tunnel interface..."
    ip link set netplas-m2 up mtu $OPTIMAL_MTU txqueuelen 1000
    ip addr add 132.168.30.1/30 dev netplas-m2
    ip route add 132.168.30.0/30 dev netplas-m2
    
    # Enable TCP optimizations
    echo "[3] Enabling TCP optimizations..."
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || sysctl -w net.ipv4.tcp_congestion_control=cubic
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0
    sysctl -w net.ipv4.tcp_mtu_probing=1
    
    # Configure iptables
    echo "[4] Configuring iptables..."
    
    # Flush rules
    iptables -F
    iptables -t nat -F
    iptables -t mangle -F
    
    # MSS Clamping
    local MSS_VALUE=$((OPTIMAL_MTU - 40))
    iptables -t mangle -A POSTROUTING -o netplas-m2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss $MSS_VALUE
    
    # Security rules
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
    
    # Connection tracking
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Traffic shaping
    echo "[5] Setting up traffic shaping..."
    if command -v tc &> /dev/null; then
        tc qdisc del dev netplas-m2 root 2>/dev/null
        tc qdisc add dev netplas-m2 root fq_codel quantum 300 limit 10240 flows 4096
    fi
    
    # Create persistent configuration
    create_persistent_config
    
    echo -e "${GREEN}[+] FOREIGN server configured for performance${RESET}"
    return 0
}

# Function to create persistent configuration
create_persistent_config() {
    local config_file="/etc/network/interfaces.d/gre-tunnel"
    
    if [[ "$LOCATION" == "1" ]]; then
        cat > $config_file << EOF
# GRE Tunnel Configuration - IRAN Server
auto netplas-m2
iface netplas-m2 inet static
    pre-up ip tunnel add \$IFACE mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    address 132.168.30.2
    netmask 255.255.255.252
    mtu $(calculate_mtu)
    txqueuelen 1000
    post-up ip route add 132.168.30.0/30 dev \$IFACE
    post-up sysctl -w net.ipv4.conf.\$IFACE.rp_filter=2
    post-up iptables -t mangle -A POSTROUTING -o \$IFACE -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$(( $(calculate_mtu) - 40 ))
    pre-down ip tunnel del \$IFACE
EOF
    else
        cat > $config_file << EOF
# GRE Tunnel Configuration - FOREIGN Server
auto netplas-m2
iface netplas-m2 inet static
    pre-up ip tunnel add \$IFACE mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    address 132.168.30.1
    netmask 255.255.255.252
    mtu $(calculate_mtu)
    txqueuelen 1000
    post-up ip route add 132.168.30.0/30 dev \$IFACE
    post-up sysctl -w net.ipv4.conf.\$IFACE.rp_filter=2
    post-up iptables -t mangle -A POSTROUTING -o \$IFACE -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss \$(( $(calculate_mtu) - 40 ))
    pre-down ip tunnel del \$IFACE
EOF
    fi
    
    chmod 600 $config_file
    echo -e "${GREEN}[+] Persistent configuration created${RESET}"
}

# Function to test tunnel performance
test_tunnel_performance() {
    echo -e "${CYAN}[*] Testing tunnel performance...${RESET}"
    
    local target_ip=""
    if [[ "$LOCATION" == "1" ]]; then
        target_ip="132.168.30.1"
    else
        target_ip="132.168.30.2"
    fi
    
    echo "[1] Basic connectivity test..."
    ping -c 4 -I netplas-m2 $target_ip | tail -2
    
    echo "[2] Testing with different packet sizes..."
    for size in 64 128 512 1024 1472; do
        echo -n "  Packet size $size bytes: "
        ping -c 2 -s $size -I netplas-m2 $target_ip 2>/dev/null | grep "time=" | head -1 || echo "failed"
    done
    
    echo "[3] Checking interface statistics..."
    ip -s link show netplas-m2 | grep -A2 -E "RX|TX"
    
    echo "[4] Testing TCP performance (requires netcat on both sides)..."
    echo "    Run this on FOREIGN server: nc -l -p 5000 > /dev/null"
    echo "    Run this on IRAN server: dd if=/dev/zero bs=1M count=100 | nc 132.168.30.1 5000"
    
    echo "[5] Checking for packet loss..."
    ping -c 100 -i 0.1 -I netplas-m2 $target_ip 2>/dev/null | grep "packet loss"
}

# Function to diagnose performance issues
diagnose_performance() {
    echo -e "${CYAN}[*] Diagnosing performance issues...${RESET}"
    
    echo "[1] Checking MTU/MSS settings..."
    ip link show netplas-m2 | grep mtu
    iptables -t mangle -L -n -v | grep MSS
    
    echo "[2] Checking TCP parameters..."
    sysctl -a 2>/dev/null | grep -E "tcp_.*mem|tcp_congestion|rmem_max|wmem_max" | grep -v default
    
    echo "[3] Checking for buffer issues..."
    ethtool -g eth0 2>/dev/null | head -20 || echo "Cannot check ethtool"
    
    echo "[4] Checking interrupt coalescing..."
    ethtool -c eth0 2>/dev/null | head -15 || echo "Cannot check interrupt settings"
    
    echo "[5] Checking system load..."
    echo "CPU Load: $(uptime)"
    echo "Memory: $(free -h | grep Mem)"
    
    echo "[6] Checking for fragmentation..."
    cat /proc/net/snmp | grep -E "Ip:.*Frag" | tail -1
}

# Function to apply quick performance fixes
apply_performance_fixes() {
    echo -e "${CYAN}[*] Applying performance fixes...${RESET}"
    
    # Increase socket buffers
    echo "[1] Increasing socket buffers..."
    sysctl -w net.core.rmem_default=262144
    sysctl -w net.core.wmem_default=262144
    sysctl -w net.core.rmem_max=16777216
    sysctl -w net.core.wmem_max=16777216
    
    # Optimize TCP for long paths
    echo "[2] Optimizing TCP for long paths..."
    sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
    sysctl -w net.ipv4.tcp_mem="16777216 16777216 16777216"
    
    # Disable TCP slow start after idle
    sysctl -w net.ipv4.tcp_slow_start_after_idle=0
    
    # Enable TCP window scaling
    sysctl -w net.ipv4.tcp_window_scaling=1
    
    # Increase connection tracking table
    echo "[3] Increasing connection tracking..."
    sysctl -w net.netfilter.nf_conntrack_max=262144
    sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=86400
    
    # Optimize interface
    echo "[4] Optimizing tunnel interface..."
    ip link set netplas-m2 txqueuelen 2000 2>/dev/null || true
    
    # Apply FQ_Codel if tc is available
    if command -v tc &> /dev/null; then
        echo "[5] Applying FQ_Codel queuing discipline..."
        tc qdisc del dev netplas-m2 root 2>/dev/null
        tc qdisc add dev netplas-m2 root fq_codel quantum 300 limit 10240 flows 4096 noecn
    fi
    
    echo -e "${GREEN}[+] Performance fixes applied${RESET}"
}

# Main function
main() {
    show_header
    check_root
    
    echo -e "${YELLOW}This script will optimize GRE tunnel for maximum performance${RESET}"
    echo ""
    
    # Get configuration
    echo "Select server location:"
    echo "1 - IRAN"
    echo "2 - FOREIGN"
    read -p "Enter 1 or 2: " LOCATION
    
    if [[ "$LOCATION" != "1" && "$LOCATION" != "2" ]]; then
        echo -e "${RED}[!] Invalid selection${RESET}"
        exit 1
    fi
    
    read -p "Enter IRAN server IP: " IP_IRAN
    read -p "Enter FOREIGN server IP: " IP_FOREIGN
    
    # Validate IPs
    if ! [[ $IP_IRAN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[!] Invalid IRAN IP${RESET}"
        exit 1
    fi
    
    if ! [[ $IP_FOREIGN =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo -e "${RED}[!] Invalid FOREIGN IP${RESET}"
        exit 1
    fi
    
    # Summary
    echo -e "${BLUE}"
    echo "Configuration Summary:"
    echo "======================"
    echo "Location: $([ "$LOCATION" == "1" ] && echo "IRAN" || echo "FOREIGN")"
    echo "IRAN IP: $IP_IRAN"
    echo "FOREIGN IP: $IP_FOREIGN"
    echo -e "${RESET}"
    
    # Install dependencies
    install_dependencies
    
    # Optimize system
    optimize_system
    
    # Setup based on location
    if [[ "$LOCATION" == "1" ]]; then
        setup_iran
    else
        setup_foreign
    fi
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Setup failed${RESET}"
        exit 1
    fi
    
    # Apply performance fixes
    apply_performance_fixes
    
    # Test performance
    echo -e "\n"
    read -p "Run performance tests? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        test_tunnel_performance
    fi
    
    # Show diagnostics
    echo -e "\n"
    read -p "Show performance diagnostics? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        diagnose_performance
    fi
    
    # Final instructions
    echo -e "\n${GREEN}${BOLD}"
    echo "============================================"
    echo "       PERFORMANCE OPTIMIZATION COMPLETE"
    echo "============================================"
    echo -e "${RESET}"
    
    echo "Key optimizations applied:"
    echo "1. Automatic MTU detection and optimization"
    echo "2. TCP BBR congestion control (if available)"
    echo "3. Increased socket buffers"
    echo "4. FQ_Codel queuing discipline"
    echo "5. MSS clamping for GRE overhead"
    echo "6. Connection tracking optimizations"
    
    echo -e "\n${YELLOW}Next steps for troubleshooting slow speeds:${RESET}"
    echo "1. Check MTU: ip link show netplas-m2 | grep mtu"
    echo "2. Monitor traffic: ip -s link show netplas-m2"
    echo "3. Test with iperf3:"
    echo "   FOREIGN: iperf3 -s"
    echo "   IRAN: iperf3 -c 132.168.30.1 -t 30 -P 4"
    echo "4. Check for fragmentation: cat /proc/net/snmp | grep Frag"
    echo "5. Adjust MSS if needed:"
    echo "   iptables -t mangle -A POSTROUTING -o netplas-m2 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1300"
}

# Run main function
main
