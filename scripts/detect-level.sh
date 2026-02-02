#!/bin/bash

#══════════════════════════════════════════════════════════════════════════════
#  Filtering Level Detection Script v3.0
#  Comprehensive network filtering analysis tool
#══════════════════════════════════════════════════════════════════════════════

# Strict mode
set -euo pipefail

#──────────────────────────────────────────────────────────────────────────────
# Configuration
#──────────────────────────────────────────────────────────────────────────────

VERSION="3.0"
TIMEOUT_SHORT=3
TIMEOUT_MEDIUM=5
TIMEOUT_LONG=15
CONNECTION_TEST_DURATION=30
LOG_FILE="/tmp/filter_detect_$(date +%Y%m%d_%H%M%S).log"

# Ports to test
TCP_PORTS=(22 80 443 8080 8443 2053 2083 2087 2096 3389 5432)
UDP_PORTS=(53 443 1194 51820 4500)
COMMON_BLOCKED=(22 3389 5432 1194)
USUALLY_OPEN=(80 443 53)

#──────────────────────────────────────────────────────────────────────────────
# Colors & Formatting
#──────────────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    R='\033[0;31m'      # Red
    G='\033[0;32m'      # Green
    Y='\033[1;33m'      # Yellow
    B='\033[0;34m'      # Blue
    P='\033[0;35m'      # Purple
    C='\033[0;36m'      # Cyan
    W='\033[1;37m'      # White Bold
    N='\033[0m'         # Reset
    BOLD='\033[1m'
    DIM='\033[2m'
else
    R=''; G=''; Y=''; B=''; P=''; C=''; W=''; N=''; BOLD=''; DIM=''
fi

#──────────────────────────────────────────────────────────────────────────────
# Helper Functions
#──────────────────────────────────────────────────────────────────────────────

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

print_header() {
    echo -e "\n${B}╔══════════════════════════════════════════════════════════════╗${N}"
    echo -e "${B}║${W}  $1${N}"
    echo -e "${B}╚══════════════════════════════════════════════════════════════╝${N}"
}

print_section() {
    echo -e "\n${C}┌──────────────────────────────────────────────────────────────┐${N}"
    echo -e "${C}│${W} $1${N}"
    echo -e "${C}└──────────────────────────────────────────────────────────────┘${N}"
}

print_result() {
    local label="$1"
    local status="$2"
    local detail="${3:-}"
    
    printf "  %-25s" "$label"
    
    case "$status" in
        "pass"|"open"|"ok"|"yes"|"1")
            echo -e "${G}✓ PASS${N} ${DIM}${detail}${N}"
            ;;
        "fail"|"closed"|"blocked"|"no"|"0")
            echo -e "${R}✗ FAIL${N} ${DIM}${detail}${N}"
            ;;
        "warn"|"partial"|"slow")
            echo -e "${Y}⚠ WARN${N} ${DIM}${detail}${N}"
            ;;
        "info")
            echo -e "${C}ℹ INFO${N} ${DIM}${detail}${N}"
            ;;
        *)
            echo -e "${P}? $status${N} ${DIM}${detail}${N}"
            ;;
    esac
}

progress_bar() {
    local current=$1
    local total=$2
    local width=40
    local percent=$((current * 100 / total))
    local filled=$((current * width / total))
    local empty=$((width - filled))
    
    printf "\r  ${DIM}[${N}"
    printf "${G}%${filled}s${N}" | tr ' ' '█'
    printf "${DIM}%${empty}s${N}" | tr ' ' '░'
    printf "${DIM}]${N} ${W}%3d%%${N}" "$percent"
}

check_dependencies() {
    local deps=(nc curl ping timeout openssl nslookup traceroute awk grep)
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${Y}Missing dependencies: ${missing[*]}${N}"
        echo -e "${DIM}Install with: apt install netcat curl iputils-ping coreutils openssl dnsutils traceroute${N}"
        return 1
    fi
    return 0
}

spinner() {
    local pid=$1
    local msg="${2:-Processing}"
    local spinchars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}${spinchars:$i:1}${N} %s..." "$msg"
        i=$(( (i + 1) % ${#spinchars} ))
        sleep 0.1
    done
    printf "\r  %-50s\r" " "
}

#──────────────────────────────────────────────────────────────────────────────
# Test Functions
#──────────────────────────────────────────────────────────────────────────────

test_icmp() {
    local ip="$1"
    local count=5
    local result
    
    log "Testing ICMP to $ip"
    
    result=$(ping -c $count -W 2 "$ip" 2>/dev/null) || true
    
    local transmitted=$(echo "$result" | grep -oP '\d+(?= packets transmitted)' || echo "0")
    local received=$(echo "$result" | grep -oP '\d+(?= received)' || echo "0")
    local loss=$(echo "$result" | grep -oP '\d+(?=% packet loss)' || echo "100")
    local avg_rtt=$(echo "$result" | grep -oP 'rtt.*= [\d.]+/([\d.]+)' | grep -oP '[\d.]+' | sed -n '2p' || echo "N/A")
    
    echo "$received $loss $avg_rtt"
}

test_tcp_port() {
    local ip="$1"
    local port="$2"
    local timeout="${3:-$TIMEOUT_SHORT}"
    
    log "Testing TCP $ip:$port"
    
    local start=$(date +%s%N)
    if timeout "$timeout" nc -z -w "$timeout" "$ip" "$port" 2>/dev/null; then
        local end=$(date +%s%N)
        local latency=$(( (end - start) / 1000000 ))
        echo "open $latency"
    else
        echo "closed 0"
    fi
}

test_udp_port() {
    local ip="$1"
    local port="$2"
    
    log "Testing UDP $ip:$port"
    
    # UDP test is tricky - we check if we get ICMP unreachable
    if timeout "$TIMEOUT_SHORT" nc -zu -w "$TIMEOUT_SHORT" "$ip" "$port" 2>/dev/null; then
        echo "open"
    else
        echo "unknown"
    fi
}

test_tls_handshake() {
    local ip="$1"
    local port="${2:-443}"
    local sni="${3:-$ip}"
    
    log "Testing TLS handshake to $ip:$port with SNI $sni"
    
    local result
    local start=$(date +%s%N)
    
    result=$(timeout "$TIMEOUT_MEDIUM" openssl s_client \
        -connect "$ip:$port" \
        -servername "$sni" \
        -brief \
        </dev/null 2>&1) || true
    
    local end=$(date +%s%N)
    local latency=$(( (end - start) / 1000000 ))
    
    if echo "$result" | grep -qi "CONNECTION ESTABLISHED\|Protocol.*TLSv"; then
        local protocol=$(echo "$result" | grep -oP 'Protocol version: \K.*' || echo "unknown")
        local cipher=$(echo "$result" | grep -oP 'Ciphersuite: \K.*' || echo "unknown")
        echo "success $latency $protocol $cipher"
    elif echo "$result" | grep -qi "connection refused"; then
        echo "refused $latency"
    elif echo "$result" | grep -qi "connection reset"; then
        echo "reset $latency"
    elif echo "$result" | grep -qi "timed out\|timeout"; then
        echo "timeout $latency"
    else
        echo "failed $latency"
    fi
}

test_http_request() {
    local ip="$1"
    local port="${2:-80}"
    local protocol="${3:-http}"
    
    log "Testing HTTP request to $protocol://$ip:$port"
    
    local start=$(date +%s%N)
    local result
    
    result=$(timeout "$TIMEOUT_MEDIUM" curl -sS -o /dev/null \
        -w "%{http_code}|%{time_total}|%{ssl_verify_result}" \
        --connect-timeout "$TIMEOUT_SHORT" \
        -k \
        "$protocol://$ip:$port" 2>&1) || true
    
    local end=$(date +%s%N)
    
    if [[ "$result" =~ ^[0-9]{3}\| ]]; then
        local http_code=$(echo "$result" | cut -d'|' -f1)
        local time_total=$(echo "$result" | cut -d'|' -f2)
        echo "$http_code $time_total"
    else
        echo "000 0"
    fi
}

test_connection_stability() {
    local ip="$1"
    local port="${2:-443}"
    local duration="${3:-$CONNECTION_TEST_DURATION}"
    
    log "Testing connection stability to $ip:$port for ${duration}s"
    
    local temp_file=$(mktemp)
    local start=$(date +%s)
    
    # Start connection in background
    timeout "$duration" nc -w "$duration" "$ip" "$port" </dev/null >"$temp_file" 2>&1 &
    local pid=$!
    
    # Monitor connection
    local checks=0
    local alive=0
    
    while [[ $(($(date +%s) - start)) -lt $duration ]]; do
        ((checks++))
        if kill -0 "$pid" 2>/dev/null; then
            ((alive++))
        else
            break
        fi
        sleep 2
    done
    
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$temp_file"
    
    local actual_duration=$(($(date +%s) - start))
    local stability=$((alive * 100 / (checks > 0 ? checks : 1)))
    
    echo "$actual_duration $stability $checks"
}

test_dns_resolution() {
    local ip="$1"
    local domain="${2:-google.com}"
    
    log "Testing DNS resolution via $ip for $domain"
    
    local start=$(date +%s%N)
    local result
    
    result=$(timeout "$TIMEOUT_SHORT" nslookup "$domain" "$ip" 2>&1) || true
    
    local end=$(date +%s%N)
    local latency=$(( (end - start) / 1000000 ))
    
    if echo "$result" | grep -qi "Address.*[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+" | grep -v "$ip"; then
        echo "success $latency"
    else
        echo "failed $latency"
    fi
}

test_traceroute() {
    local ip="$1"
    local max_hops="${2:-15}"
    
    log "Running traceroute to $ip"
    
    local result
    result=$(timeout 30 traceroute -T -p 443 -m "$max_hops" -n "$ip" 2>&1) || true
    
    local hops=$(echo "$result" | grep -c "^ *[0-9]" || echo "0")
    local complete=$(echo "$result" | grep -q " $ip " && echo "yes" || echo "no")
    local last_responding=$(echo "$result" | grep -v '\* \* \*' | tail -1 | awk '{print $1}' || echo "0")
    
    echo "$hops $complete $last_responding"
}

test_mtu() {
    local ip="$1"
    local start_mtu=1500
    local min_mtu=500
    
    log "Testing MTU to $ip"
    
    for mtu in $(seq $start_mtu -100 $min_mtu); do
        local size=$((mtu - 28))  # IP header (20) + ICMP header (8)
        if ping -c 1 -M do -s "$size" -W 2 "$ip" &>/dev/null; then
            echo "$mtu"
            return
        fi
    done
    
    echo "unknown"
}

test_protocol_detection() {
    local ip="$1"
    local port="${2:-443}"
    
    log "Testing protocol detection/DPI on $ip:$port"
    
    local results=""
    
    # Test 1: Pure TLS
    local tls_result=$(test_tls_handshake "$ip" "$port")
    local tls_status=$(echo "$tls_result" | awk '{print $1}')
    
    # Test 2: Send random bytes (should trigger DPI if active)
    local random_test
    random_test=$(timeout "$TIMEOUT_SHORT" bash -c "head -c 32 /dev/urandom | nc -w 2 $ip $port" 2>&1) || true
    
    # Test 3: Send HTTP-like data on non-HTTP port
    local http_test
    http_test=$(timeout "$TIMEOUT_SHORT" bash -c "echo -e 'GET / HTTP/1.1\r\nHost: test\r\n\r\n' | nc -w 2 $ip $port" 2>&1) || true
    
    # Analysis
    if [[ "$tls_status" == "reset" ]]; then
        echo "dpi_active reset_on_tls"
    elif [[ "$tls_status" == "success" ]] && [[ -z "$http_test" ]]; then
        echo "possible_dpi selective"
    elif [[ "$tls_status" == "success" ]]; then
        echo "no_dpi clean"
    else
        echo "unknown $tls_status"
    fi
}

test_active_probing() {
    local ip="$1"
    local port="${2:-443}"
    
    log "Testing for active probing indicators on $ip:$port"
    
    # This is a heuristic - we make multiple connections and check for patterns
    local results=()
    
    for i in {1..5}; do
        local result=$(test_tcp_port "$ip" "$port" 2)
        results+=("$(echo "$result" | awk '{print $1}')")
        sleep 1
    done
    
    local open_count=0
    for r in "${results[@]}"; do
        [[ "$r" == "open" ]] && ((open_count++))
    done
    
    if [[ $open_count -eq 5 ]]; then
        echo "consistent open"
    elif [[ $open_count -eq 0 ]]; then
        echo "consistent closed"
    else
        echo "inconsistent $open_count/5"
    fi
}

#──────────────────────────────────────────────────────────────────────────────
# Level Detection Logic
#──────────────────────────────────────────────────────────────────────────────

analyze_results() {
    local -n res=$1
    
    # Level determination logic
    local level=0
    local confidence="low"
    local details=""
    
    # Check Level 1: ICMP Blocking
    if [[ "${res[icmp_received]}" == "0" ]] && [[ "${res[tcp_open_count]}" -gt 0 ]]; then
        level=1
        confidence="high"
        details="ICMP blocked, TCP working"
    fi
    
    # Check Level 2: Port Blocking
    if [[ "${res[tcp_open_count]}" -gt 0 ]] && [[ "${res[tcp_open_count]}" -lt "${res[tcp_tested_count]}" ]]; then
        local blocked_common=0
        for port in "${COMMON_BLOCKED[@]}"; do
            [[ "${res[tcp_$port]:-closed}" == "closed" ]] && ((blocked_common++))
        done
        
        if [[ $blocked_common -gt 2 ]]; then
            level=2
            confidence="high"
            details="Selective port blocking detected"
        fi
    fi
    
    # Check Level 3: IP Blocking
    if [[ "${res[tcp_open_count]}" -eq 0 ]]; then
        level=3
        confidence="high"
        details="All ports blocked - IP blacklisted"
    fi
    
    # Check Level 4: Stateful Inspection
    if [[ "${res[connection_stability]:-100}" -lt 80 ]] && [[ "${res[tcp_443]}" == "open" ]]; then
        level=4
        confidence="medium"
        details="Connection drops detected - SPI suspected"
    fi
    
    # Check Level 5: DPI
    if [[ "${res[dpi_status]}" == "dpi_active" ]] || [[ "${res[tls_443]}" == "reset" ]]; then
        level=5
        confidence="high"
        details="Protocol inspection detected"
    fi
    
    # Check Level 6: Whitelist
    if [[ "${res[tcp_443]}" == "closed" ]] && [[ "${res[tcp_80]}" == "closed" ]] && [[ "${res[dns_works]}" == "yes" ]]; then
        level=6
        confidence="medium"
        details="Possible whitelist - only DNS working"
    fi
    
    echo "$level $confidence $details"
}

#──────────────────────────────────────────────────────────────────────────────
# Main Execution
#──────────────────────────────────────────────────────────────────────────────

main() {
    local target_ip="${1:-}"
    
    # Validate input
    if [[ -z "$target_ip" ]]; then
        echo -e "${W}Filtering Level Detection Script v${VERSION}${N}"
        echo -e "${DIM}Comprehensive network filtering analysis tool${N}\n"
        echo -e "Usage: $0 <target_ip> [options]\n"
        echo -e "Options:"
        echo -e "  -f, --fast       Fast scan (fewer tests)"
        echo -e "  -v, --verbose    Verbose output"
        echo -e "  -o, --output     Save report to file"
        echo -e "  -h, --help       Show this help"
        exit 1
    fi
    
    # Check dependencies
    check_dependencies || exit 1
    
    # Initialize results
    declare -A RESULTS
    local total_tests=0
    local completed_tests=0
    
    # Calculate total tests
    total_tests=$((1 + ${#TCP_PORTS[@]} + ${#UDP_PORTS[@]} + 5))
    
    #──────────────────────────────────────────────────────────────────────────
    # Header
    #──────────────────────────────────────────────────────────────────────────
    
    clear
    echo -e "${B}╔══════════════════════════════════════════════════════════════════════╗${N}"
    echo -e "${B}║${N}      ${W}🔬 Filtering Level Detection Script v${VERSION}${N}                       ${B}║${N}"
    echo -e "${B}║${N}      ${DIM}Comprehensive Network Filtering Analysis${N}                          ${B}║${N}"
    echo -e "${B}╠══════════════════════════════════════════════════════════════════════╣${N}"
    echo -e "${B}║${N}  Target: ${W}${target_ip}${N}"
    echo -e "${B}║${N}  Time:   ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${N}"
    echo -e "${B}║${N}  Log:    ${DIM}${LOG_FILE}${N}"
    echo -e "${B}╚══════════════════════════════════════════════════════════════════════╝${N}"
    
    log "Starting scan of $target_ip"
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 1: ICMP
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "📡 Layer 3: ICMP Test"
    
    echo -e "  Testing ICMP connectivity..."
    local icmp_result=$(test_icmp "$target_ip")
    RESULTS[icmp_received]=$(echo "$icmp_result" | awk '{print $1}')
    RESULTS[icmp_loss]=$(echo "$icmp_result" | awk '{print $2}')
    RESULTS[icmp_rtt]=$(echo "$icmp_result" | awk '{print $3}')
    
    if [[ "${RESULTS[icmp_received]}" -gt 0 ]]; then
        print_result "ICMP (Ping)" "pass" "RTT: ${RESULTS[icmp_rtt]}ms, Loss: ${RESULTS[icmp_loss]}%"
    else
        print_result "ICMP (Ping)" "fail" "100% packet loss"
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 2: TCP Ports
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "🔌 Layer 4: TCP Port Scan"
    
    RESULTS[tcp_open_count]=0
    RESULTS[tcp_tested_count]=${#TCP_PORTS[@]}
    
    for port in "${TCP_PORTS[@]}"; do
        local result=$(test_tcp_port "$target_ip" "$port")
        local status=$(echo "$result" | awk '{print $1}')
        local latency=$(echo "$result" | awk '{print $2}')
        
        RESULTS[tcp_$port]="$status"
        
        if [[ "$status" == "open" ]]; then
            ((RESULTS[tcp_open_count]++))
            print_result "Port $port/TCP" "open" "${latency}ms"
        else
            print_result "Port $port/TCP" "closed" ""
        fi
        
        ((completed_tests++))
    done
    
    echo -e "\n  ${DIM}Summary: ${RESULTS[tcp_open_count]}/${RESULTS[tcp_tested_count]} ports open${N}"
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 3: UDP Ports
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "📦 Layer 4: UDP Port Scan"
    
    RESULTS[udp_open_count]=0
    
    for port in "${UDP_PORTS[@]}"; do
        local result=$(test_udp_port "$target_ip" "$port")
        RESULTS[udp_$port]="$result"
        
        if [[ "$result" == "open" ]]; then
            ((RESULTS[udp_open_count]++))
            print_result "Port $port/UDP" "open" ""
        else
            print_result "Port $port/UDP" "unknown" "(UDP state uncertain)"
        fi
        
        ((completed_tests++))
    done
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 4: TLS Handshake
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "🔐 Layer 5: TLS/SSL Analysis"
    
    if [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        local tls_result=$(test_tls_handshake "$target_ip" 443)
        RESULTS[tls_443]=$(echo "$tls_result" | awk '{print $1}')
        RESULTS[tls_latency]=$(echo "$tls_result" | awk '{print $2}')
        RESULTS[tls_protocol]=$(echo "$tls_result" | awk '{print $3}')
        RESULTS[tls_cipher]=$(echo "$tls_result" | awk '{print $4}')
        
        case "${RESULTS[tls_443]}" in
            "success")
                print_result "TLS Handshake" "pass" "${RESULTS[tls_protocol]}"
                print_result "TLS Latency" "info" "${RESULTS[tls_latency]}ms"
                ;;
            "reset")
                print_result "TLS Handshake" "fail" "Connection reset (DPI?)"
                ;;
            "timeout")
                print_result "TLS Handshake" "fail" "Timeout"
                ;;
            *)
                print_result "TLS Handshake" "fail" "${RESULTS[tls_443]}"
                ;;
        esac
        
        # Test with different SNI
        echo -e "\n  ${DIM}Testing SNI manipulation...${N}"
        
        local sni_google=$(test_tls_handshake "$target_ip" 443 "www.google.com")
        local sni_google_status=$(echo "$sni_google" | awk '{print $1}')
        
        if [[ "$sni_google_status" == "success" ]]; then
            print_result "SNI: google.com" "pass" ""
        else
            print_result "SNI: google.com" "fail" "$sni_google_status"
        fi
    else
        print_result "TLS Handshake" "fail" "Port 443 closed"
        RESULTS[tls_443]="port_closed"
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 5: HTTP/HTTPS
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "🌐 Layer 7: HTTP/HTTPS Test"
    
    if [[ "${RESULTS[tcp_80]}" == "open" ]]; then
        local http_result=$(test_http_request "$target_ip" 80 "http")
        local http_code=$(echo "$http_result" | awk '{print $1}')
        local http_time=$(echo "$http_result" | awk '{print $2}')
        
        RESULTS[http_code]="$http_code"
        
        if [[ "$http_code" != "000" ]]; then
            print_result "HTTP (80)" "pass" "Status: $http_code, Time: ${http_time}s"
        else
            print_result "HTTP (80)" "fail" "No response"
        fi
    else
        print_result "HTTP (80)" "fail" "Port closed"
        RESULTS[http_code]="port_closed"
    fi
    
    if [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        local https_result=$(test_http_request "$target_ip" 443 "https")
        local https_code=$(echo "$https_result" | awk '{print $1}')
        local https_time=$(echo "$https_result" | awk '{print $2}')
        
        RESULTS[https_code]="$https_code"
        
        if [[ "$https_code" != "000" ]]; then
            print_result "HTTPS (443)" "pass" "Status: $https_code, Time: ${https_time}s"
        else
            print_result "HTTPS (443)" "fail" "No response"
        fi
    else
        print_result "HTTPS (443)" "fail" "Port closed"
        RESULTS[https_code]="port_closed"
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 6: Connection Stability
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "⏱️ Connection Stability Test"
    
    if [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        echo -e "  ${DIM}Testing connection stability (${CONNECTION_TEST_DURATION}s)...${N}"
        
        local stability_result=$(test_connection_stability "$target_ip" 443 "$CONNECTION_TEST_DURATION")
        RESULTS[connection_duration]=$(echo "$stability_result" | awk '{print $1}')
        RESULTS[connection_stability]=$(echo "$stability_result" | awk '{print $2}')
        
        if [[ "${RESULTS[connection_stability]}" -ge 90 ]]; then
            print_result "Stability" "pass" "${RESULTS[connection_stability]}% stable for ${RESULTS[connection_duration]}s"
        elif [[ "${RESULTS[connection_stability]}" -ge 50 ]]; then
            print_result "Stability" "warn" "${RESULTS[connection_stability]}% - Intermittent drops"
        else
            print_result "Stability" "fail" "${RESULTS[connection_stability]}% - Unstable (SPI?)"
        fi
    else
        print_result "Stability" "fail" "Port 443 closed"
        RESULTS[connection_stability]=0
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 7: DPI Detection
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "🔍 Deep Packet Inspection (DPI) Detection"
    
    if [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        local dpi_result=$(test_protocol_detection "$target_ip" 443)
        RESULTS[dpi_status]=$(echo "$dpi_result" | awk '{print $1}')
        RESULTS[dpi_detail]=$(echo "$dpi_result" | awk '{print $2}')
        
        case "${RESULTS[dpi_status]}" in
            "dpi_active")
                print_result "DPI Detection" "fail" "Active DPI detected!"
                ;;
            "possible_dpi")
                print_result "DPI Detection" "warn" "Possible DPI"
                ;;
            "no_dpi")
                print_result "DPI Detection" "pass" "No DPI detected"
                ;;
            *)
                print_result "DPI Detection" "info" "Inconclusive"
                ;;
        esac
        
        # Active probing detection
        local probe_result=$(test_active_probing "$target_ip" 443)
        local probe_status=$(echo "$probe_result" | awk '{print $1}')
        
        if [[ "$probe_status" == "inconsistent" ]]; then
            print_result "Active Probing" "warn" "Possible active probing detected"
        else
            print_result "Active Probing" "pass" "Connection consistent"
        fi
    else
        print_result "DPI Detection" "info" "Cannot test - port closed"
        RESULTS[dpi_status]="unknown"
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 8: DNS
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "📛 DNS Analysis"
    
    # Test if target can be used as DNS
    if [[ "${RESULTS[udp_53]}" == "open" ]]; then
        local dns_result=$(test_dns_resolution "$target_ip" "google.com")
        local dns_status=$(echo "$dns_result" | awk '{print $1}')
        
        if [[ "$dns_status" == "success" ]]; then
            print_result "DNS Resolution" "pass" ""
            RESULTS[dns_works]="yes"
        else
            print_result "DNS Resolution" "fail" ""
            RESULTS[dns_works]="no"
        fi
    else
        print_result "DNS (UDP 53)" "info" "Port closed"
        RESULTS[dns_works]="no"
    fi
    
    # Test DNS tunnel possibility
    echo -e "\n  ${DIM}DNS Tunnel Viability:${N}"
    local public_dns=$(test_dns_resolution "8.8.8.8" "google.com")
    if [[ $(echo "$public_dns" | awk '{print $1}') == "success" ]]; then
        print_result "Public DNS Access" "pass" "DNS tunneling possible"
        RESULTS[dns_tunnel_viable]="yes"
    else
        print_result "Public DNS Access" "fail" ""
        RESULTS[dns_tunnel_viable]="no"
    fi
    
    ((completed_tests++))
    
    #──────────────────────────────────────────────────────────────────────────
    # Test 9: Traceroute
    #──────────────────────────────────────────────────────────────────────────
    
    print_section "🛤️ Network Path Analysis"
    
    echo -e "  ${DIM}Running TCP traceroute...${N}"
    local trace_result=$(test_traceroute "$target_ip" 15)
    RESULTS[trace_hops]=$(echo "$trace_result" | awk '{print $1}')
    RESULTS[trace_complete]=$(echo "$trace_result" | awk '{print $2}')
    RESULTS[trace_last_hop]=$(echo "$trace_result" | awk '{print $3}')
    
    print_result "Total Hops" "info" "${RESULTS[trace_hops]}"
    
    if [[ "${RESULTS[trace_complete]}" == "yes" ]]; then
        print_result "Route Complete" "pass" "Target reached"
    else
        print_result "Route Complete" "warn" "Blocked at hop ${RESULTS[trace_last_hop]}"
    fi
    
    ((completed_tests++))
    
    #══════════════════════════════════════════════════════════════════════════
    # Final Analysis
    #══════════════════════════════════════════════════════════════════════════
    
    print_header "📊 ANALYSIS RESULTS"
    
    # Determine filtering level
    local level=0
    local level_name=""
    local confidence=""
    local solution=""
    
    # Level detection logic
    if [[ "${RESULTS[tcp_open_count]}" -eq 0 ]]; then
        level=3
        level_name="IP Blacklist"
        confidence="HIGH"
        solution="CDN (Cloudflare) / Relay Server / Change IP"
    elif [[ "${RESULTS[icmp_received]}" -eq 0 ]] && [[ "${RESULTS[tcp_open_count]}" -gt 0 ]]; then
        level=1
        level_name="ICMP Block"
        confidence="HIGH"
        solution="Any TCP/UDP tunnel works"
    elif [[ "${RESULTS[tcp_open_count]}" -lt 4 ]] && [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        level=2
        level_name="Port Filtering"
        confidence="MEDIUM"
        solution="Use port 443/80/53"
    elif [[ "${RESULTS[connection_stability]}" -lt 70 ]] && [[ "${RESULTS[tcp_443]}" == "open" ]]; then
        level=4
        level_name="Stateful Inspection"
        confidence="MEDIUM"
        solution="Mux / UDP protocols (WireGuard, QUIC)"
    elif [[ "${RESULTS[dpi_status]}" == "dpi_active" ]] || [[ "${RESULTS[tls_443]}" == "reset" ]]; then
        level=5
        level_name="DPI Active"
        confidence="HIGH"
        solution="Reality / ShadowTLS / Hysteria2"
    elif [[ "${RESULTS[tcp_443]}" == "closed" ]] && [[ "${RESULTS[tcp_80]}" == "closed" ]] && [[ "${RESULTS[dns_works]}" == "yes" ]]; then
        level=6
        level_name="Whitelist Mode"
        confidence="MEDIUM"
        solution="DNS Tunnel (dnstt) / Domain Fronting"
    else
        level=0
        level_name="Minimal/None"
        confidence="HIGH"
        solution="Standard tunnels work"
    fi
    
    # Display level indicator
    echo -e "\n"
    echo -e "  ${W}Detected Filtering Level:${N}"
    echo -e ""
    echo -e "  ┌─────────────────────────────────────────────────────────────┐"
    echo -e "  │                                                             │"
    
    local level_bar=""
    for i in {0..6}; do
        if [[ $i -lt $level ]]; then
            level_bar+="█"
        elif [[ $i -eq $level ]]; then
            level_bar+="█"
        else
            level_bar+="░"
        fi
    done
    
    local level_color="$G"
    [[ $level -ge 3 ]] && level_color="$Y"
    [[ $level -ge 5 ]] && level_color="$R"
    
    echo -e "  │    Level: ${level_color}${BOLD}$level - $level_name${N}"
    echo -e "  │                                                             │"
    echo -e "  │    ${DIM}0    1    2    3    4    5    6${N}                         │"
    echo -e "  │    ${level_color}$level_bar${N}                                   │"
    echo -e "  │    ${DIM}None ICMP Port IP   SPI  DPI  WL${N}                        │"
    echo -e "  │                                                             │"
    echo -e "  │    Confidence: ${W}$confidence${N}"
    echo -e "  │                                                             │"
    echo -e "  └─────────────────────────────────────────────────────────────┘"
    
    # Solution
    echo -e "\n"
    echo -e "  ${W}Recommended Solution:${N}"
    echo -e "  ${G}→ $solution${N}"
    
    # Quick stats
    print_section "📈 Quick Stats"
    
    echo -e "  ┌─────────────────────┬───────────────────────────────────────┐"
    echo -e "  │ ICMP                │ ${RESULTS[icmp_received]}/5 received, ${RESULTS[icmp_loss]}% loss"
    echo -e "  │ TCP Ports Open      │ ${RESULTS[tcp_open_count]}/${RESULTS[tcp_tested_count]}"
    echo -e "  │ TLS Status          │ ${RESULTS[tls_443]:-N/A}"
    echo -e "  │ Connection Stability│ ${RESULTS[connection_stability]:-N/A}%"
    echo -e "  │ DPI Status          │ ${RESULTS[dpi_status]:-N/A}"
    echo -e "  │ DNS Tunnel Viable   │ ${RESULTS[dns_tunnel_viable]:-N/A}"
    echo -e "  └─────────────────────┴───────────────────────────────────────┘"
    
    # Tunnel recommendations
    print_section "🚀 Tunnel Recommendations"
    
    case $level in
        0|1)
            echo -e "  ${G}▸${N} iptables NAT forward"
            echo -e "  ${G}▸${N} Socat / GOST"
            echo -e "  ${G}▸${N} SSH Tunnel"
            echo -e "  ${G}▸${N} WireGuard"
            echo -e "  ${G}▸${N} Any standard tunnel"
            ;;
        2)
            echo -e "  ${G}▸${N} Use port 443 (HTTPS port)"
            echo -e "  ${G}▸${N} GOST on port 443"
            echo -e "  ${G}▸${N} SSH on port 443"
            echo -e "  ${Y}▸${N} Consider: TLS-based protocols"
            ;;
        3)
            echo -e "  ${G}▸${N} Cloudflare CDN + WebSocket"
            echo -e "  ${G}▸${N} Relay server (Iran → Clean IP → Kharej)"
            echo -e "  ${Y}▸${N} Change server IP"
            echo -e "  ${Y}▸${N} Use different datacenter"
            ;;
        4)
            echo -e "  ${G}▸${N} Enable Mux (multiplexing)"
            echo -e "  ${G}▸${N} WireGuard / QUIC-based"
            echo -e "  ${G}▸${N} Hysteria2"
            echo -e "  ${Y}▸${N} Periodic reconnection"
            ;;
        5)
            echo -e "  ${G}▸${N} VLESS + Reality"
            echo -e "  ${G}▸${N} ShadowTLS v3"
            echo -e "  ${G}▸${N} Hysteria2"
            echo -e "  ${G}▸${N} TUIC v5"
            echo -e "  ${G}▸${N} WebSocket + TLS + CDN"
            echo -e "  ${Y}▸${N} Use uTLS for fingerprint"
            ;;
        6)
            echo -e "  ${G}▸${N} DNS Tunnel (dnstt)"
            echo -e "  ${G}▸${N} Iodine"
            echo -e "  ${Y}▸${N} Domain Fronting (if available)"
            echo -e "  ${Y}▸${N} Meek (Tor)"
            echo -e "  ${R}▸${N} Very limited options"
            ;;
    esac
    
    # Footer
    echo -e "\n${B}══════════════════════════════════════════════════════════════════════${N}"
    echo -e "${DIM}Log saved to: $LOG_FILE${N}"
    echo -e "${DIM}Scan completed at: $(date '+%Y-%m-%d %H:%M:%S')${N}"
    echo -e "${B}══════════════════════════════════════════════════════════════════════${N}\n"
    
    log "Scan completed. Level: $level ($level_name)"
    
    return $level
}

#──────────────────────────────────────────────────────────────────────────────
# Entry Point
#──────────────────────────────────────────────────────────────────────────────

main "$@"
