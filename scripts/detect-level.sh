#!/bin/bash
#══════════════════════════════════════════════════════════════════════════════
# Filtering Level Detection Script v3.1 (Fixed)
# Comprehensive Network Filtering Analysis
# Fixed: Robust parsing, proper error handling, cleanup traps
#══════════════════════════════════════════════════════════════════════════════

#──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
#──────────────────────────────────────────────────────────────────────────────

# Don't use strict mode globally - handle errors manually for robustness
set +e

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m'
readonly BOLD='\033[1m'

# Timeouts (reduced for reliability)
readonly ICMP_TIMEOUT=3
readonly TCP_TIMEOUT=5
readonly TLS_TIMEOUT=8
readonly HTTP_TIMEOUT=8
readonly STABILITY_DURATION=15
readonly UDP_TIMEOUT=3

# Test ports
readonly TCP_PORTS=(22 80 443 8080 8443 2053 2083 2087 2096)
readonly UDP_PORTS=(53 443 51820 1194)

# Results associative array
declare -A RESULTS
declare -A DETAILS

# Logging
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="/tmp/filter_detect_${TIMESTAMP}_$$.log"

# Cleanup trap
cleanup() {
    # Kill any background jobs
    jobs -p 2>/dev/null | xargs -r kill 2>/dev/null
    # Remove temp files if any
    rm -f /tmp/filter_test_$$.* 2>/dev/null
}
trap cleanup EXIT INT TERM

#──────────────────────────────────────────────────────────────────────────────
# UTILITY FUNCTIONS
#──────────────────────────────────────────────────────────────────────────────

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}

print_header() {
    echo -e "\n${BLUE}┌──────────────────────────────────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} $1"
    echo -e "${BLUE}└──────────────────────────────────────────────────────────────┘${NC}"
}

print_result() {
    local test_name="$1"
    local status="$2"
    local details="${3:-}"
    
    if [[ "$status" == "PASS" || "$status" == "1" ]]; then
        echo -e "  ${GREEN}✓${NC} ${test_name}: ${GREEN}PASS${NC} ${details}"
    elif [[ "$status" == "FAIL" || "$status" == "0" ]]; then
        echo -e "  ${RED}✗${NC} ${test_name}: ${RED}FAIL${NC} ${details}"
    else
        echo -e "  ${YELLOW}?${NC} ${test_name}: ${YELLOW}${status}${NC} ${details}"
    fi
}

validate_ip() {
    local ip="$1"
    
    # Check for valid IPv4
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    
    # Check for valid hostname
    if [[ $ip =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$ ]]; then
        return 0
    fi
    
    return 1
}

check_dependencies() {
    local missing=()
    local deps=(ping nc curl openssl awk grep sed timeout)
    local optional_deps=(traceroute nmap dig nslookup)
    
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo -e "${RED}Error: Missing required dependencies: ${missing[*]}${NC}"
        echo "Install with: apt install netcat-openbsd curl openssl"
        exit 1
    fi
    
    # Check optional
    for cmd in "${optional_deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            log "Optional dependency missing: $cmd"
        fi
    done
}

#──────────────────────────────────────────────────────────────────────────────
# TEST FUNCTIONS (Robust Error Handling)
#──────────────────────────────────────────────────────────────────────────────

test_icmp() {
    local ip="$1"
    local count=4
    
    log "Testing ICMP to $ip"
    
    # Run ping and capture output
    local result
    result=$(ping -c "$count" -W "$ICMP_TIMEOUT" "$ip" 2>&1) || true
    
    # Robust parsing with awk and fallbacks
    local transmitted received loss avg_rtt
    
    # Parse transmitted packets
    transmitted=$(echo "$result" | awk '/packets transmitted/ {print $1}' 2>/dev/null) || true
    [[ -z "$transmitted" ]] && transmitted=0
    
    # Parse received packets  
    received=$(echo "$result" | awk '/packets transmitted/ {
        for(i=1; i<=NF; i++) {
            if($i == "received" || $i == "received,") {
                print $(i-1)
                exit
            }
        }
    }' 2>/dev/null) || true
    [[ -z "$received" ]] && received=0
    
    # Parse packet loss
    loss=$(echo "$result" | awk -F'[% ]' '/packet loss/ {
        for(i=1; i<=NF; i++) {
            if($(i+1) == "packet" || $i ~ /loss/) {
                gsub(/[^0-9]/,"",$i)
                if($i != "") print $i
                exit
            }
        }
    }' 2>/dev/null) || true
    
    # Fallback: calculate loss if parsing failed
    if [[ -z "$loss" ]]; then
        if [[ "$transmitted" -gt 0 ]]; then
            loss=$(( (transmitted - received) * 100 / transmitted ))
        else
            loss=100
        fi
    fi
    
    # Parse RTT
    avg_rtt=$(echo "$result" | awk -F'[/= ]' '/rtt|round-trip/ {
        for(i=1; i<=NF; i++) {
            if($i ~ /^[0-9]+\.[0-9]+$/) {
                print $i
                exit
            }
        }
    }' 2>/dev/null) || true
    [[ -z "$avg_rtt" ]] && avg_rtt="N/A"
    
    # Store results
    RESULTS[icmp]=$( [[ "$received" -gt 0 ]] && echo 1 || echo 0 )
    DETAILS[icmp]="tx:$transmitted rx:$received loss:${loss}% rtt:${avg_rtt}ms"
    
    log "ICMP Result: ${RESULTS[icmp]} - ${DETAILS[icmp]}"
    
    return 0
}

test_tcp_port() {
    local ip="$1"
    local port="$2"
    
    log "Testing TCP $ip:$port"
    
    # Use timeout + nc for reliable testing
    if timeout "$TCP_TIMEOUT" nc -z -w "$TCP_TIMEOUT" "$ip" "$port" 2>/dev/null; then
        log "TCP $port: OPEN"
        return 0
    else
        log "TCP $port: CLOSED/FILTERED"
        return 1
    fi
}

test_udp_port() {
    local ip="$1"
    local port="$2"
    
    log "Testing UDP $ip:$port"
    
    # UDP testing is inherently unreliable
    # For DNS (53), we can do a real test
    if [[ "$port" == "53" ]]; then
        # Try actual DNS query
        local dns_result
        dns_result=$(timeout "$UDP_TIMEOUT" dig +short +time=2 +tries=1 @"$ip" google.com A 2>/dev/null) || true
        
        if [[ -n "$dns_result" ]]; then
            log "UDP 53 (DNS): OPEN (got response)"
            return 0
        fi
    fi
    
    # For other UDP ports, use nc -zu but mark as heuristic
    if timeout "$UDP_TIMEOUT" nc -zu -w "$UDP_TIMEOUT" "$ip" "$port" 2>/dev/null; then
        log "UDP $port: POSSIBLY OPEN (heuristic)"
        return 0
    fi
    
    log "UDP $port: CLOSED/FILTERED/UNKNOWN"
    return 1
}

test_tls_handshake() {
    local ip="$1"
    local port="${2:-443}"
    local sni="${3:-$ip}"
    
    log "Testing TLS handshake to $ip:$port with SNI=$sni"
    
    local result
    result=$(timeout "$TLS_TIMEOUT" openssl s_client \
        -connect "$ip:$port" \
        -servername "$sni" \
        -verify_return_error \
        </dev/null 2>&1) || true
    
    local status=0
    local protocol=""
    local cipher=""
    local verify=""
    
    # Check for successful connection (multiple indicators)
    if echo "$result" | grep -qiE "(CONNECTED|SSL-Session:|New,|Protocol.*:)"; then
        status=1
        
        # Extract protocol version
        protocol=$(echo "$result" | awk -F': ' '/Protocol/ {print $2; exit}' 2>/dev/null) || true
        [[ -z "$protocol" ]] && protocol=$(echo "$result" | grep -oE 'TLSv[0-9.]+' | head -1) || true
        
        # Extract cipher
        cipher=$(echo "$result" | awk -F': ' '/Cipher/ {print $2; exit}' 2>/dev/null) || true
        
        # Check verification
        if echo "$result" | grep -q "Verify return code: 0"; then
            verify="verified"
        else
            verify="unverified"
        fi
    fi
    
    RESULTS[tls]=$status
    DETAILS[tls]="proto:${protocol:-N/A} cipher:${cipher:-N/A} ${verify:-}"
    
    log "TLS Result: $status - ${DETAILS[tls]}"
    
    return 0
}

test_http() {
    local ip="$1"
    local port="${2:-80}"
    local proto="http"
    [[ "$port" == "443" ]] && proto="https"
    
    log "Testing HTTP to $proto://$ip:$port"
    
    local http_code
    local response_time
    
    # Use curl with all relevant options
    local curl_result
    curl_result=$(curl -sS -o /dev/null \
        -w "%{http_code}|%{time_total}|%{ssl_verify_result}" \
        --connect-timeout "$HTTP_TIMEOUT" \
        --max-time "$HTTP_TIMEOUT" \
        -k \
        "$proto://$ip:$port/" 2>&1) || true
    
    http_code=$(echo "$curl_result" | cut -d'|' -f1)
    response_time=$(echo "$curl_result" | cut -d'|' -f2)
    
    # Validate http_code
    if [[ ! "$http_code" =~ ^[0-9]+$ ]]; then
        http_code="000"
    fi
    
    local status=0
    if [[ "$http_code" != "000" ]]; then
        status=1
    fi
    
    RESULTS[http]=$status
    DETAILS[http]="code:$http_code time:${response_time:-N/A}s"
    
    log "HTTP Result: $status - ${DETAILS[http]}"
    
    return 0
}

test_connection_stability() {
    local ip="$1"
    local port="${2:-443}"
    local duration="${3:-$STABILITY_DURATION}"
    
    log "Testing connection stability to $ip:$port for ${duration}s"
    
    # Only test if port is open
    if ! test_tcp_port "$ip" "$port"; then
        RESULTS[stability]=0
        DETAILS[stability]="port closed"
        return 0
    fi
    
    local temp_file="/tmp/filter_test_$$.stability"
    local start_time=$(date +%s)
    local checks=0
    local successful=0
    
    # Start background connection
    timeout "$duration" nc "$ip" "$port" </dev/null >"$temp_file" 2>&1 &
    local nc_pid=$!
    
    # Check connection periodically
    local check_interval=2
    while [[ $(($(date +%s) - start_time)) -lt $duration ]]; do
        sleep "$check_interval"
        ((checks++))
        
        if kill -0 "$nc_pid" 2>/dev/null; then
            ((successful++))
        else
            break
        fi
    done
    
    # Cleanup
    kill "$nc_pid" 2>/dev/null || true
    wait "$nc_pid" 2>/dev/null || true
    rm -f "$temp_file"
    
    local stability_pct=0
    if [[ $checks -gt 0 ]]; then
        stability_pct=$((successful * 100 / checks))
    fi
    
    RESULTS[stability]=$( [[ $stability_pct -ge 80 ]] && echo 1 || echo 0 )
    DETAILS[stability]="${stability_pct}% (${successful}/${checks} checks)"
    
    log "Stability Result: ${RESULTS[stability]} - ${DETAILS[stability]}"
    
    return 0
}

test_active_probe_resistance() {
    local ip="$1"
    local port="${2:-443}"
    
    log "Testing active probe resistance on $ip:$port"
    
    # Send invalid data and check response
    local response
    response=$(echo "INVALID_PROBE_TEST_12345" | \
        timeout 3 nc -w 2 "$ip" "$port" 2>/dev/null) || true
    
    local status=0
    if [[ -z "$response" ]]; then
        # No response to invalid probe = potentially protected
        status=1
        DETAILS[probe_resist]="no response to invalid probe"
    else
        DETAILS[probe_resist]="responded to invalid probe"
    fi
    
    RESULTS[probe_resist]=$status
    
    log "Probe Resistance: $status - ${DETAILS[probe_resist]}"
    
    return 0
}

test_entropy_detection() {
    local ip="$1"
    local port="${2:-443}"
    
    log "Testing entropy-based filtering on $ip:$port"
    
    # Test with high entropy (random) data
    local high_entropy_result
    dd if=/dev/urandom bs=100 count=1 2>/dev/null | \
        timeout 3 nc -w 2 "$ip" "$port" >/dev/null 2>&1
    high_entropy_result=$?
    
    # Test with low entropy (text) data
    local low_entropy_result
    echo "GET / HTTP/1.1\r\nHost: test.com\r\n\r\n" | \
        timeout 3 nc -w 2 "$ip" "$port" >/dev/null 2>&1
    low_entropy_result=$?
    
    local status="unknown"
    if [[ $high_entropy_result -ne 0 && $low_entropy_result -eq 0 ]]; then
        status="entropy_filtered"
        RESULTS[entropy]=0
    elif [[ $high_entropy_result -eq 0 && $low_entropy_result -eq 0 ]]; then
        status="no_filtering"
        RESULTS[entropy]=1
    else
        status="inconclusive"
        RESULTS[entropy]=1
    fi
    
    DETAILS[entropy]="$status"
    log "Entropy Detection: ${RESULTS[entropy]} - $status"
    
    return 0
}

test_mtu() {
    local ip="$1"
    
    log "Testing MTU path discovery to $ip"
    
    # Only run if ICMP works
    if [[ "${RESULTS[icmp]:-0}" != "1" ]]; then
        RESULTS[mtu]="unknown"
        DETAILS[mtu]="ICMP blocked, cannot test"
        return 0
    fi
    
    local working_mtu=0
    
    for size in 1500 1400 1300 1200 1100 1000 800 576 500; do
        if ping -c 1 -W 2 -M do -s $((size - 28)) "$ip" &>/dev/null; then
            working_mtu=$size
            break
        fi
    done
    
    if [[ $working_mtu -gt 0 ]]; then
        RESULTS[mtu]=1
        DETAILS[mtu]="max MTU: ${working_mtu}"
    else
        RESULTS[mtu]=0
        DETAILS[mtu]="MTU discovery failed"
    fi
    
    log "MTU Result: ${RESULTS[mtu]} - ${DETAILS[mtu]}"
    
    return 0
}

#──────────────────────────────────────────────────────────────────────────────
# ANALYSIS FUNCTIONS
#──────────────────────────────────────────────────────────────────────────────

analyze_results() {
    local open_tcp_ports=0
    local open_udp_ports=0
    
    # Count open ports
    for port in "${TCP_PORTS[@]}"; do
        [[ "${RESULTS[tcp_$port]:-0}" == "1" ]] && ((open_tcp_ports++))
    done
    
    for port in "${UDP_PORTS[@]}"; do
        [[ "${RESULTS[udp_$port]:-0}" == "1" ]] && ((open_udp_ports++))
    done
    
    RESULTS[open_tcp]=$open_tcp_ports
    RESULTS[open_udp]=$open_udp_ports
    
    # Determine filtering level
    local level=0
    local level_name=""
    local solution=""
    
    if [[ $open_tcp_ports -eq 0 ]]; then
        level=3
        level_name="IP Blacklist"
        solution="Use CDN (Cloudflare) / Relay server / Change IP"
        
    elif [[ "${RESULTS[icmp]:-0}" == "0" && $open_tcp_ports -gt 0 ]]; then
        level=1
        level_name="ICMP Block Only"
        solution="Any TCP-based tunnel will work"
        
    elif [[ $open_tcp_ports -lt 3 ]]; then
        level=2
        level_name="Port Filtering"
        solution="Use port 443 or 80"
        
    elif [[ "${RESULTS[stability]:-1}" == "0" && "${RESULTS[tcp_443]:-0}" == "1" ]]; then
        level=4
        level_name="Stateful Inspection (SPI)"
        solution="Use Mux / UDP protocols (Hysteria2, TUIC)"
        
    elif [[ "${RESULTS[tls]:-1}" == "0" && "${RESULTS[tcp_443]:-0}" == "1" ]]; then
        level=5
        level_name="Deep Packet Inspection (DPI)"
        solution="Use Reality / ShadowTLS v3 / Hysteria2"
        
    elif [[ "${RESULTS[entropy]:-1}" == "0" ]]; then
        level=5
        level_name="DPI with Entropy Analysis"
        solution="Use Reality / ShadowTLS v3 (mimic real TLS)"
        
    else
        level=1
        level_name="Minimal/No Filtering"
        solution="Standard tunnels should work"
    fi
    
    RESULTS[level]=$level
    RESULTS[level_name]="$level_name"
    RESULTS[solution]="$solution"
}

print_analysis_report() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}                    FILTERING ANALYSIS REPORT                       ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  Target:        ${WHITE}$TARGET_IP${NC}"
    echo -e "${BLUE}║${NC}  Test Time:     $(date)"
    echo -e "${BLUE}║${NC}  Log File:      $LOGFILE"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}Test Results:${NC}"
    echo -e "${BLUE}║${NC}"
    
    # Layer results
    echo -e "${BLUE}║${NC}  ${CYAN}Layer 3 (Network):${NC}"
    print_result "    ICMP" "${RESULTS[icmp]:-0}" "${DETAILS[icmp]:-}"
    [[ -n "${RESULTS[mtu]:-}" ]] && print_result "    MTU" "${RESULTS[mtu]}" "${DETAILS[mtu]:-}"
    
    echo -e "${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Layer 4 (Transport):${NC}"
    echo -e "${BLUE}║${NC}    TCP Ports Open: ${RESULTS[open_tcp]:-0}/${#TCP_PORTS[@]}"
    for port in "${TCP_PORTS[@]}"; do
        [[ -n "${RESULTS[tcp_$port]:-}" ]] && \
            print_result "      Port $port" "${RESULTS[tcp_$port]}"
    done
    echo -e "${BLUE}║${NC}    UDP Ports Open: ${RESULTS[open_udp]:-0}/${#UDP_PORTS[@]} (heuristic)"
    
    echo -e "${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Layer 5-7 (Application):${NC}"
    print_result "    TLS Handshake" "${RESULTS[tls]:-0}" "${DETAILS[tls]:-}"
    print_result "    HTTP Response" "${RESULTS[http]:-0}" "${DETAILS[http]:-}"
    
    echo -e "${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${CYAN}Advanced Tests:${NC}"
    print_result "    Connection Stability" "${RESULTS[stability]:-0}" "${DETAILS[stability]:-}"
    print_result "    Probe Resistance" "${RESULTS[probe_resist]:-0}" "${DETAILS[probe_resist]:-}"
    print_result "    Entropy Filter" "${RESULTS[entropy]:-1}" "${DETAILS[entropy]:-}"
    
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}DETECTION RESULT:${NC}"
    echo -e "${BLUE}║${NC}"
    
    local level_color=$GREEN
    [[ ${RESULTS[level]:-0} -ge 3 ]] && level_color=$YELLOW
    [[ ${RESULTS[level]:-0} -ge 5 ]] && level_color=$RED
    
    echo -e "${BLUE}║${NC}  ${level_color}██████████████████████████████████████████████████████████████${NC}"
    echo -e "${BLUE}║${NC}  ${level_color}█                                                            █${NC}"
    echo -e "${BLUE}║${NC}  ${level_color}█   Level ${RESULTS[level]:-?}: ${RESULTS[level_name]:-Unknown}${NC}"
    echo -e "${BLUE}║${NC}  ${level_color}█                                                            █${NC}"
    echo -e "${BLUE}║${NC}  ${level_color}██████████████████████████████████████████████████████████████${NC}"
    echo -e "${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  ${BOLD}Recommended Solution:${NC}"
    echo -e "${BLUE}║${NC}  ${WHITE}${RESULTS[solution]:-Unknown}${NC}"
    echo -e "${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
}

#──────────────────────────────────────────────────────────────────────────────
# MAIN FUNCTION
#──────────────────────────────────────────────────────────────────────────────

main() {
    # Check arguments
    if [[ $# -lt 1 ]]; then
        echo -e "${RED}Usage: $0 <IP or hostname> [--fast]${NC}"
        echo "  --fast: Skip stability and MTU tests"
        exit 1
    fi
    
    TARGET_IP="$1"
    FAST_MODE=0
    [[ "${2:-}" == "--fast" ]] && FAST_MODE=1
    
    # Validate IP
    if ! validate_ip "$TARGET_IP"; then
        echo -e "${RED}Error: Invalid IP address or hostname: $TARGET_IP${NC}"
        exit 1
    fi
    
    # Check dependencies
    check_dependencies
    
    # Print header
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC} ${BOLD}🔬 Filtering Level Detection Script v3.1 (Fixed)${NC}                    ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}    Comprehensive Network Filtering Analysis                         ${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  Target: ${WHITE}$TARGET_IP${NC}"
    echo -e "${BLUE}║${NC}  Time:   $(date)"
    echo -e "${BLUE}║${NC}  Log:    $LOGFILE"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════════╝${NC}"
    
    log "========== Starting analysis of $TARGET_IP =========="
    
    # ═══════════════════════════════════════════════════════════════════════
    # Layer 3: ICMP
    # ═══════════════════════════════════════════════════════════════════════
    print_header "📡 Layer 3: ICMP Test"
    echo "Testing ICMP connectivity..."
    test_icmp "$TARGET_IP"
    print_result "ICMP (Ping)" "${RESULTS[icmp]}" "${DETAILS[icmp]}"
    
    # MTU test (only if ICMP works and not fast mode)
    if [[ "$FAST_MODE" != "1" ]]; then
        echo "Testing MTU..."
        test_mtu "$TARGET_IP"
        [[ -n "${RESULTS[mtu]:-}" ]] && print_result "MTU Path" "${RESULTS[mtu]}" "${DETAILS[mtu]}"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════
    # Layer 4: TCP Ports
    # ═══════════════════════════════════════════════════════════════════════
    print_header "🔌 Layer 4: TCP Port Scan"
    echo "Scanning ${#TCP_PORTS[@]} TCP ports..."
    
    for port in "${TCP_PORTS[@]}"; do
        if test_tcp_port "$TARGET_IP" "$port"; then
            RESULTS[tcp_$port]=1
        else
            RESULTS[tcp_$port]=0
        fi
        print_result "TCP $port" "${RESULTS[tcp_$port]}"
    done
    
    # ═══════════════════════════════════════════════════════════════════════
    # Layer 4: UDP Ports
    # ═══════════════════════════════════════════════════════════════════════
    print_header "📨 Layer 4: UDP Port Scan (Heuristic)"
    echo "Scanning ${#UDP_PORTS[@]} UDP ports..."
    
    for port in "${UDP_PORTS[@]}"; do
        if test_udp_port "$TARGET_IP" "$port"; then
            RESULTS[udp_$port]=1
        else
            RESULTS[udp_$port]=0
        fi
        print_result "UDP $port" "${RESULTS[udp_$port]}" "(heuristic)"
    done
    
    # ═══════════════════════════════════════════════════════════════════════
    # Layer 5-7: TLS & HTTP
    # ═══════════════════════════════════════════════════════════════════════
    print_header "🔒 Layer 5-7: TLS & HTTP Tests"
    
    echo "Testing TLS handshake..."
    test_tls_handshake "$TARGET_IP" 443
    print_result "TLS Handshake" "${RESULTS[tls]}" "${DETAILS[tls]}"
    
    echo "Testing HTTP response..."
    test_http "$TARGET_IP" 80
    print_result "HTTP" "${RESULTS[http]}" "${DETAILS[http]}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # Advanced Tests
    # ═══════════════════════════════════════════════════════════════════════
    print_header "🧪 Advanced Filtering Tests"
    
    if [[ "$FAST_MODE" != "1" ]]; then
        echo "Testing connection stability (${STABILITY_DURATION}s)..."
        test_connection_stability "$TARGET_IP" 443 "$STABILITY_DURATION"
        print_result "Connection Stability" "${RESULTS[stability]}" "${DETAILS[stability]}"
    else
        RESULTS[stability]=1
        DETAILS[stability]="skipped (fast mode)"
        print_result "Connection Stability" "SKIPPED" "(fast mode)"
    fi
    
    echo "Testing active probe resistance..."
    test_active_probe_resistance "$TARGET_IP" 443
    print_result "Probe Resistance" "${RESULTS[probe_resist]}" "${DETAILS[probe_resist]}"
    
    echo "Testing entropy-based filtering..."
    test_entropy_detection "$TARGET_IP" 443
    print_result "Entropy Filter" "${RESULTS[entropy]}" "${DETAILS[entropy]}"
    
    # ═══════════════════════════════════════════════════════════════════════
    # Analysis
    # ═══════════════════════════════════════════════════════════════════════
    analyze_results
    print_analysis_report
    
    log "========== Analysis complete =========="
    
    echo -e "\n${GREEN}Full log saved to: $LOGFILE${NC}\n"
}

# Run main
main "$@"
