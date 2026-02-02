#!/bin/bash

SERVER_IP="$1"

if [ -z "$SERVER_IP" ]; then
    echo "Usage: $0 <server_ip>"
    exit 1
fi

echo "═══════════════════════════════════════════"
echo "    Filtering Level Detection Script"
echo "═══════════════════════════════════════════"
echo ""

# Test 1: ICMP
echo "[1] Testing ICMP (ping)..."
if ping -c 2 -W 3 $SERVER_IP &>/dev/null; then
    ICMP="OPEN"
else
    ICMP="BLOCKED"
fi
echo "    ICMP: $ICMP"

# Test 2: Common ports
echo ""
echo "[2] Testing common ports..."
for port in 22 80 443 8080 2053 2083; do
    if timeout 3 nc -z $SERVER_IP $port 2>/dev/null; then
        echo "    Port $port: OPEN"
        OPEN_PORTS="$OPEN_PORTS $port"
    else
        echo "    Port $port: BLOCKED/FILTERED"
    fi
done

# Test 3: TLS Handshake
echo ""
echo "[3] Testing TLS handshake on 443..."
if timeout 5 openssl s_client -connect $SERVER_IP:443 </dev/null 2>/dev/null | grep -q "CONNECTED"; then
    TLS="WORKING"
else
    TLS="BLOCKED"
fi
echo "    TLS: $TLS"

# Test 4: HTTP
echo ""
echo "[4] Testing HTTP..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 http://$SERVER_IP 2>/dev/null)
echo "    HTTP Status: $HTTP_CODE"

# Analysis
echo ""
echo "═══════════════════════════════════════════"
echo "                 Analysis"
echo "═══════════════════════════════════════════"

if [ "$ICMP" = "BLOCKED" ] && [ -n "$OPEN_PORTS" ]; then
    echo "Level 1: ICMP Blocking"
    echo "Recommendation: Use any TCP tunnel"
elif [ -z "$OPEN_PORTS" ]; then
    echo "Level 3: IP Blocking"
    echo "Recommendation: Use CDN or change IP"
elif [ "$TLS" = "BLOCKED" ]; then
    echo "Level 4-5: DPI Active"
    echo "Recommendation: Use Reality or ShadowTLS"
else
    echo "Level 2 or lower: Port-based filtering"
    echo "Recommendation: Use open ports with TLS"
fi
