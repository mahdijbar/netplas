#!/bin/bash
CYAN=$(tput setaf 6)
YELLOW=$(tput setaf 3)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
RESET=$(tput sgr0)

echo -e "${CYAN}"
echo "===================================="
echo "        GitHub: netplas"
echo "   GRE Tunnel v2 (Optimized)"
echo "===================================="
echo -e "${RESET}"

# بررسی root بودن کاربر
if [[ $EUID -ne 0 ]]; then
   echo "${RED}[!] این اسکریپت باید با دسترسی root اجرا شود${RESET}"
   exit 1
fi

echo "انتخاب موقعیت سرور:"
echo "1 - IRAN (سرور داخلی)"
echo "2 - FOREIGN (سرور خارجی)"
read -p "لطفا 1 یا 2 وارد کنید: " LOCATION

read -p "آی‌پی سرور ایران: " IP_IRAN
read -p "آی‌پی سرور خارج: " IP_FOREIGN

# تنظیمات مشترک برای بهینه‌سازی شبکه
optimize_network() {
    echo "${YELLOW}[*] در حال بهینه‌سازی تنظیمات شبکه...${RESET}"
    
    # تنظیمات TCP برای عملکرد بهتر
    sysctl -w net.ipv4.tcp_window_scaling=1
    sysctl -w net.ipv4.tcp_timestamps=1
    sysctl -w net.ipv4.tcp_sack=1
    sysctl -w net.ipv4.tcp_rmem="4096 87380 33554432"
    sysctl -w net.ipv4.tcp_wmem="4096 65536 33554432"
    sysctl -w net.core.rmem_max=33554432
    sysctl -w net.core.wmem_max=33554432
    sysctl -w net.ipv4.tcp_congestion_control=bbr
    sysctl -w net.core.default_qdisc=fq
    
    # فعال‌سازی IP Forwarding
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.conf.all.forwarding=1
    sysctl -w net.ipv6.conf.all.forwarding=1
}

if [[ "$LOCATION" == "1" ]]; then
    echo "${GREEN}[*] تنظیم سرور ایران...${RESET}"
    
    # حذف تانل قبلی اگر وجود دارد
    ip link delete netplas-m2 2>/dev/null
    
    # ایجاد تانل GRE
    ip tunnel add netplas-m2 mode gre local $IP_IRAN remote $IP_FOREIGN ttl 255
    ip link set netplas-m2 mtu 1400  # تنظیم MTU پایین‌تر برای جلوگیری از fragmentation
    ip link set netplas-m2 up
    
    # تنظیم IP
    ip addr add 132.168.30.2/30 dev netplas-m2
    
    # تنظیم route (فقط ترافیک خاص از طریق تانل برود)
    ip route add default via 132.168.30.1 dev netplas-m2 metric 100
    
    # تنظیمات شبکه
    optimize_network
    
    # 🔴 **قوانین iptables اصلاح شده و ایمن**:
    # 1. فقط NAT برای ترافیک خروجی از تانل
    iptables -t nat -A POSTROUTING -o netplas-m2 -j MASQUERADE
    
    # 2. باز کردن پورت SSH فقط برای IP خاص (اختیاری)
    # iptables -A INPUT -p tcp --dport 22 -s $IP_FOREIGN -j ACCEPT
    # iptables -A INPUT -p tcp --dport 22 -j DROP
    
    # 3. QoS برای تانل (با tc)
    echo "${YELLOW}[*] تنظیم QoS برای مدیریت ترافیک...${RESET}"
    tc qdisc add dev netplas-m2 root handle 1: htb default 10
    tc class add dev netplas-m2 parent 1: classid 1:1 htb rate 100mbit burst 15k
    tc class add dev netplas-m2 parent 1:1 classid 1:10 htb rate 80mbit ceil 100mbit burst 15k
    tc qdisc add dev netplas-m2 parent 1:10 sfq perturb 10
    
    echo "${GREEN}[✓] سرور ایران آماده است${RESET}"
    echo "${CYAN}MTU تانل: 1400${RESET}"
    echo "${CYAN}IP تانل: 132.168.30.2/30${RESET}"

elif [[ "$LOCATION" == "2" ]]; then
    echo "${GREEN}[*] تنظیم سرور خارج...${RESET}"
    
    # حذف تانل قبلی
    ip link delete netplas-m2 2>/dev/null
    
    # ایجاد تانل
    ip tunnel add netplas-m2 mode gre local $IP_FOREIGN remote $IP_IRAN ttl 255
    ip link set netplas-m2 mtu 1400
    ip link set netplas-m2 up
    
    # تنظیم IP
    ip addr add 132.168.30.1/30 dev netplas-m2
    
    # تنظیمات شبکه
    optimize_network
    
    # مسیریابی برای ترافیک بازگشتی
    # ip route add <شبکه ایران> via 132.168.30.2 dev netplas-m2
    
    # 🔴 **مسدودسازی ICMP اصلاح شده**:
    # فقط ICMP flood مسدود شود
    iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
    iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
    
    # QoS برای سرور خارج
    tc qdisc add dev netplas-m2 root handle 1: htb default 10
    tc class add dev netplas-m2 parent 1: classid 1:1 htb rate 500mbit burst 15k
    tc class add dev netplas-m2 parent 1:1 classid 1:10 htb rate 400mbit ceil 500mbit burst 15k
    tc qdisc add dev netplas-m2 parent 1:10 sfq perturb 10
    
    echo "${GREEN}[✓] سرور خارج آماده است${RESET}"
    echo "${CYAN}MTU تانل: 1400${RESET}"
    echo "${CYAN}IP تانل: 132.168.30.1/30${RESET}"

else
    echo "${RED}[!] انتخاب نامعتبر. لطفاً 1 یا 2 وارد کنید.${RESET}"
    exit 1
fi

# تست اتصال
echo "${YELLOW}[*] در حال تست تانل...${RESET}"
if [[ "$LOCATION" == "1" ]]; then
    ping -c 3 -M do -s 1300 132.168.30.1 2>/dev/null && echo "${GREEN}[✓] تانل فعال است${RESET}" || echo "${RED}[!] مشکل در تانل${RESET}"
elif [[ "$LOCATION" == "2" ]]; then
    ping -c 3 -M do -s 1300 132.168.30.2 2>/dev/null && echo "${GREEN}[✓] تانل فعال است${RESET}" || echo "${RED}[!] مشکل در تانل${RESET}"
fi

echo "${CYAN}====================================${RESET}"
echo "${GREEN}برای پاک‌کردن تنظیمات:${RESET}"
echo "ip link delete netplas-m2"
echo "iptables -t nat -F"
echo "${CYAN}====================================${RESET}"
