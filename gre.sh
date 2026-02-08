#!/bin/bash
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)
echo -e "${CYAN}"
echo "===================================="
echo "        GitHub: netplas"
echo "   GRE Tunnel v1 Setup Script"
echo "===================================="
echo -e "${RESET}"

echo "Select server location:"
echo "1 - IRAN"
echo "2 - FOREIGN"
read -p "Enter 1 or 2: " LOCATION

read -p "Enter IRAN server IP: " IP_IRAN
read -p "Enter FOREIGN server IP: " IP_FOREIGN

# Optimize network settings
optimize_network() {
    echo "[*] Optimizing network settings..."
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.tcp_window_scaling=1
    sysctl -w net.ipv4.tcp_sack=1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432"
    sysctl -w net.core.rmem_max=33554432
    sysctl -w net.core.wmem_max=33554432
    sysctl -w net.ipv4.tcp_congestion_control=bbr
}

if [[ "$LOCATION" == "1" ]]; then
    echo "[*] Running config for IRAN server..."

    # Remove existing tunnel if any
    sudo ip link delete netplas-m2 2>/dev/null

    # Create GRE tunnel with optimized MTU
    sudo ip tunnel add netplas-m2 mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    sudo ip link set netplas-m2 mtu 1400
    sudo ip link set netplas-m2 up
    sudo ip addr add 132.168.30.2/30 dev netplas-m2
    
    # Optimize network
    optimize_network
    
    # Fix iptables rules - only NAT traffic going through tunnel
    sudo iptables -t nat -A POSTROUTING -o netplas-m2 -j MASQUERADE
    
    # Add QoS for better traffic management
    sudo tc qdisc add dev netplas-m2 root handle 1: htb default 10 2>/dev/null
    sudo tc class add dev netplas-m2 parent 1: classid 1:1 htb rate 100mbit burst 15k 2>/dev/null
    sudo tc class add dev netplas-m2 parent 1:1 classid 1:10 htb rate 80mbit ceil 100mbit burst 15k 2>/dev/null
    
    echo "[+] IRAN server configured with MTU 1400 and traffic optimization"

elif [[ "$LOCATION" == "2" ]]; then
    echo "[*] Running config for FOREIGN server..."

    # Remove existing tunnel if any
    sudo ip link delete netplas-m2 2>/dev/null

    # Create GRE tunnel with optimized MTU
    sudo ip tunnel add netplas-m2 mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    sudo ip link set netplas-m2 mtu 1400
    sudo ip link set netplas-m2 up
    sudo ip addr add 132.168.30.1/30 dev netplas-m2
    
    # Optimize network
    optimize_network
    
    # Better ICMP filtering (rate limiting instead of complete block)
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
    sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # Add QoS for better traffic management
    sudo tc qdisc add dev netplas-m2 root handle 1: htb default 10 2>/dev/null
    sudo tc class add dev netplas-m2 parent 1: classid 1:1 htb rate 500mbit burst 15k 2>/dev/null
    sudo tc class add dev netplas-m2 parent 1:1 classid 1:10 htb rate 400mbit ceil 500mbit burst 15k 2>/dev/null
    
    echo "[+] FOREIGN server configured with MTU 1400 and traffic optimization"

else
    echo "[!] Invalid selection. Please enter 1 or 2."
    exit 1
fi

# Test tunnel connectivity
echo "[*] Testing tunnel connection..."
if [[ "$LOCATION" == "1" ]]; then
    ping -c 2 -M do -s 1300 132.168.30.1 >/dev/null 2>&1 && echo "[+] Tunnel is working" || echo "[!] Tunnel test failed"
elif [[ "$LOCATION" == "2" ]]; then
    ping -c 2 -M do -s 1300 132.168.30.2 >/dev/null 2>&1 && echo "[+] Tunnel is working" || echo "[!] Tunnel test failed"
fi

echo "===================================="
echo "To remove tunnel: sudo ip link delete netplas-m2"
echo "===================================="
