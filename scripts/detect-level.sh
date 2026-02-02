#!/bin/bash

# Colors
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; N='\033[0m'

IP="$1"
[[ -z "$IP" ]] && { echo "Usage: $0 <IP>"; exit 1; }

echo -e "${B}══════════════════════════════════════${N}"
echo -e "${B}   Filtering Level Detection v2.0     ${N}"
echo -e "${B}══════════════════════════════════════${N}\n"

# Results storage
declare -A RESULTS

# Test function
test_port() {
    timeout 3 nc -z "$IP" "$1" 2>/dev/null && echo "1" || echo "0"
}

# 1. ICMP Test
echo -e "${Y}[1/6]${N} ICMP Test..."
ping -c 2 -W 2 "$IP" &>/dev/null && RESULTS[icmp]=1 || RESULTS[icmp]=0

# 2. Port Tests
echo -e "${Y}[2/6]${N} Port Scan..."
RESULTS[p22]=$(test_port 22)
RESULTS[p80]=$(test_port 80)
RESULTS[p443]=$(test_port 443)
RESULTS[p8080]=$(test_port 8080)
RESULTS[p53]=$(test_port 53)

OPEN_PORTS=0
for p in p22 p80 p443 p8080 p53; do
    [[ ${RESULTS[$p]} -eq 1 ]] && ((OPEN_PORTS++))
done

# 3. TLS Test
echo -e "${Y}[3/6]${N} TLS Handshake..."
if timeout 5 openssl s_client -connect "$IP:443" </dev/null 2>/dev/null | grep -q "BEGIN CERT"; then
    RESULTS[tls]=1
else
    RESULTS[tls]=0
fi

# 4. HTTP Test
echo -e "${Y}[4/6]${N} HTTP Request..."
HTTP=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "http://$IP" 2>/dev/null)
[[ "$HTTP" != "000" ]] && RESULTS[http]=1 || RESULTS[http]=0

# 5. Long Connection Test (simplified)
echo -e "${Y}[5/6]${N} Connection Stability..."
if [[ ${RESULTS[p443]} -eq 1 ]]; then
    START=$(date +%s)
    timeout 10 nc "$IP" 443 </dev/null 2>/dev/null &
    PID=$!
    sleep 8
    if kill -0 $PID 2>/dev/null; then
        RESULTS[stable]=1
        kill $PID 2>/dev/null
    else
        RESULTS[stable]=0
    fi
else
    RESULTS[stable]=0
fi

# 6. DNS Test
echo -e "${Y}[6/6]${N} DNS Resolution..."
if timeout 3 nslookup google.com "$IP" &>/dev/null; then
    RESULTS[dns]=1
else
    RESULTS[dns]=0
fi

# Analysis
echo -e "\n${B}══════════════════════════════════════${N}"
echo -e "${B}              Results                  ${N}"
echo -e "${B}══════════════════════════════════════${N}\n"

# Display results
show() { [[ $2 -eq 1 ]] && echo -e "$1: ${G}✓${N}" || echo -e "$1: ${R}✗${N}"; }

show "ICMP (ping)" ${RESULTS[icmp]}
show "Port 22"     ${RESULTS[p22]}
show "Port 80"     ${RESULTS[p80]}
show "Port 443"    ${RESULTS[p443]}
show "Port 8080"   ${RESULTS[p8080]}
show "TLS"         ${RESULTS[tls]}
show "HTTP"        ${RESULTS[http]}
show "Conn Stable" ${RESULTS[stable]}

# Level Detection
echo -e "\n${B}══════════════════════════════════════${N}"
echo -e "${B}             Detection                 ${N}"
echo -e "${B}══════════════════════════════════════${N}\n"

if [[ $OPEN_PORTS -eq 0 ]]; then
    echo -e "${R}Level 3: IP Blacklisted${N}"
    echo -e "Solution: CDN / Relay / Change IP"
    
elif [[ ${RESULTS[icmp]} -eq 0 && $OPEN_PORTS -gt 0 ]]; then
    echo -e "${G}Level 1: ICMP Only${N}"
    echo -e "Solution: Any TCP tunnel works"
    
elif [[ $OPEN_PORTS -lt 3 ]]; then
    echo -e "${Y}Level 2: Port Filtering${N}"
    echo -e "Solution: Use port 443 or 80"
    
elif [[ ${RESULTS[stable]} -eq 0 && ${RESULTS[p443]} -eq 1 ]]; then
    echo -e "${Y}Level 4: Stateful Inspection${N}"
    echo -e "Solution: Mux / UDP protocols"
    
elif [[ ${RESULTS[tls]} -eq 0 && ${RESULTS[p443]} -eq 1 ]]; then
    echo -e "${R}Level 5: DPI Active${N}"
    echo -e "Solution: Reality / ShadowTLS / Hysteria2"
    
else
    echo -e "${G}Level 0-1: Minimal Filtering${N}"
    echo -e "Solution: Standard tunnels work"
fi

echo -e "\n${B}══════════════════════════════════════${N}"
