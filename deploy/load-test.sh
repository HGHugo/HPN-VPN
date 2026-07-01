#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN Server Load Testing Toolkit
# =============================================================================
#
# Tests a live HPN VPN server: flood resistance, throughput, stability.
# Works with the metrics endpoint (/health + /metrics) — no admin API needed.
#
# Usage:
#   ./deploy/load-test.sh <server_ip> [options]
#
# Examples:
#   # Basic test via SSH tunnel:
#   ssh -L 9100:127.0.0.1:9100 user@server &
#   ./deploy/load-test.sh 1.2.3.4 --metrics-host 127.0.0.1
#
#   # Full test (connected to VPN + iperf3 on server):
#   ./deploy/load-test.sh 1.2.3.4 --metrics-host 127.0.0.1
#
#   # Quick test (no iperf, no endurance):
#   ./deploy/load-test.sh 1.2.3.4 --metrics-host 127.0.0.1 --skip-throughput --skip-endurance

# ── Defaults ─────────────────────────────────────────────────────────────────

SERVER_IP="${1:-}"
VPN_PORT="${VPN_PORT:-51820}"
METRICS_HOST="${METRICS_HOST:-}"
METRICS_PORT="${METRICS_PORT:-9100}"
IPERF_PORT="${IPERF_PORT:-5201}"
TUNNEL_IP="${TUNNEL_IP:-10.99.0.1}"
NUM_CLIENTS="${NUM_CLIENTS:-50}"
DURATION="${DURATION:-60}"
SKIP_THROUGHPUT="${SKIP_THROUGHPUT:-0}"
SKIP_ENDURANCE="${SKIP_ENDURANCE:-0}"
REPORT_FILE="${REPORT_FILE:-load-test-report.txt}"

# Parse named args
shift 1 2>/dev/null || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)            VPN_PORT="$2"; shift 2 ;;
        --metrics-host)    METRICS_HOST="$2"; shift 2 ;;
        --metrics-port)    METRICS_PORT="$2"; shift 2 ;;
        --iperf-port)      IPERF_PORT="$2"; shift 2 ;;
        --tunnel-ip)       TUNNEL_IP="$2"; shift 2 ;;
        --clients)         NUM_CLIENTS="$2"; shift 2 ;;
        --duration)        DURATION="$2"; shift 2 ;;
        --skip-throughput) SKIP_THROUGHPUT=1; shift ;;
        --skip-endurance)  SKIP_ENDURANCE=1; shift ;;
        --report)          REPORT_FILE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [ -z "$SERVER_IP" ]; then
    echo "Usage: $0 <server_ip> [options]"
    echo ""
    echo "Examples:"
    echo "  ssh -L 9100:127.0.0.1:9100 user@server &"
    echo "  $0 1.2.3.4 --metrics-host 127.0.0.1"
    echo ""
    echo "Options:"
    echo "  --port PORT          VPN UDP port (default: 51820)"
    echo "  --metrics-host HOST  Metrics endpoint host (default: server_ip)"
    echo "  --metrics-port PORT  Metrics endpoint port (default: 9100)"
    echo "  --iperf-port PORT    iperf3 port on server (default: 5201)"
    echo "  --tunnel-ip IP       Server tunnel IP (default: 10.99.0.1)"
    echo "  --clients N          Concurrent flood clients (default: 50)"
    echo "  --duration SECS      Test duration (default: 60)"
    echo "  --skip-throughput    Skip iperf tests"
    echo "  --skip-endurance     Skip endurance test"
    echo "  --report FILE        Output report file"
    exit 1
fi

METRICS_HOST="${METRICS_HOST:-$SERVER_IP}"
METRICS_URL="http://${METRICS_HOST}:${METRICS_PORT}"
PASS=0
FAIL=0
WARN=0
RESULTS=()

# ── Helpers ──────────────────────────────────────────────────────────────────

log()  { echo "[$(date +%H:%M:%S)] $*"; }
pass() { log "  PASS: $*"; PASS=$((PASS + 1)); RESULTS+=("PASS: $*"); }
fail() { log "  FAIL: $*"; FAIL=$((FAIL + 1)); RESULTS+=("FAIL: $*"); }
warn() { log "  WARN: $*"; WARN=$((WARN + 1)); RESULTS+=("WARN: $*"); }
info() { log "  INFO: $*"; RESULTS+=("INFO: $*"); }

# Fetch a single Prometheus metric value by name.
prom_value() {
    local metric_name="$1"
    curl -sf --connect-timeout 3 "${METRICS_URL}/metrics" 2>/dev/null \
        | grep "^${metric_name} " | awk '{print $2}' | head -1
}

# Health check (returns 0 if OK).
health_ok() {
    local resp
    resp=$(curl -sf --connect-timeout 3 "${METRICS_URL}/health" 2>/dev/null || echo "")
    [ "$resp" = "OK" ]
}

# ── Pre-flight checks ───────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  HPN VPN SERVER LOAD TEST"
echo "============================================================"
echo ""
echo "  Server:     ${SERVER_IP}:${VPN_PORT}"
echo "  Metrics:    ${METRICS_URL}"
echo "  Tunnel IP:  ${TUNNEL_IP}"
echo "  Clients:    ${NUM_CLIENTS}"
echo "  Duration:   ${DURATION}s"
echo "  Report:     ${REPORT_FILE}"
echo ""

log "=== Pre-flight checks ==="

# Check metrics endpoint reachable
if health_ok; then
    UPTIME=$(prom_value "hpn_uptime_seconds")
    pass "Server reachable — /health OK (uptime: ${UPTIME:-?}s)"
else
    fail "Server not reachable at ${METRICS_URL}/health"
    echo "ERROR: Cannot reach metrics endpoint."
    echo "  If the server binds on 127.0.0.1, use an SSH tunnel:"
    echo "    ssh -L ${METRICS_PORT}:127.0.0.1:${METRICS_PORT} user@${SERVER_IP}"
    echo "  Then: $0 ${SERVER_IP} --metrics-host 127.0.0.1"
    exit 1
fi

# Check Prometheus metrics available
PROM_LINES=$(curl -sf "${METRICS_URL}/metrics" 2>/dev/null | wc -l | tr -d ' ')
if [ "${PROM_LINES:-0}" -gt 5 ]; then
    pass "Prometheus metrics available (${PROM_LINES} lines)"
else
    fail "Prometheus metrics not available at ${METRICS_URL}/metrics"
    exit 1
fi

# Check UDP port reachable
if nc -zu -w2 "$SERVER_IP" "$VPN_PORT" 2>/dev/null; then
    pass "VPN UDP port ${VPN_PORT} open"
else
    warn "Cannot verify UDP port ${VPN_PORT} (nc probe failed — may still work)"
fi

# Check iperf3 available locally
if command -v iperf3 &>/dev/null; then
    HAS_IPERF=1
    pass "iperf3 available locally"
else
    HAS_IPERF=0
    SKIP_THROUGHPUT=1
    warn "iperf3 not installed — throughput tests will be skipped"
fi

# Baseline snapshot
B_SESSIONS=$(prom_value "hpn_sessions_active")
B_TOTAL=$(prom_value "hpn_sessions_total")
B_HS_OK=$(prom_value "hpn_handshakes_success_total")
B_HS_FAIL=$(prom_value "hpn_handshakes_failed_total")
B_PKT_DROP=$(prom_value "hpn_packets_dropped_total")
B_PKT_RECV=$(prom_value "hpn_packets_received_total")
B_TX=$(prom_value "hpn_bytes_sent_total")
B_RX=$(prom_value "hpn_bytes_received_total")

info "Baseline: sessions=${B_SESSIONS:-0} active, ${B_TOTAL:-0} total"
info "Baseline: handshakes=${B_HS_OK:-0} ok / ${B_HS_FAIL:-0} fail"
info "Baseline: packets recv=${B_PKT_RECV:-0}, dropped=${B_PKT_DROP:-0}"

# ═════════════════════════════════════════════════════════════════════════════
# TEST 1: UDP Packet Flood (DoS resistance)
# ═════════════════════════════════════════════════════════════════════════════

log ""
log "=== TEST 1: UDP Packet Flood (${NUM_CLIENTS} clients x 100 packets) ==="

FLOOD_START=$(date +%s%N)
FLOOD_PIDS=()

for i in $(seq 1 "$NUM_CLIENTS"); do
    (
        for _ in $(seq 1 100); do
            # 64-byte random payload — looks like a malformed handshake
            head -c 64 /dev/urandom | nc -u -w0 "$SERVER_IP" "$VPN_PORT" 2>/dev/null || true
        done
    ) &
    FLOOD_PIDS+=($!)
done

for pid in "${FLOOD_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

FLOOD_END=$(date +%s%N)
FLOOD_MS=$(( (FLOOD_END - FLOOD_START) / 1000000 ))

sleep 2  # Let server process remaining packets

# Server still alive?
if health_ok; then
    pass "Server survived flood (${NUM_CLIENTS}x100 = $((NUM_CLIENTS * 100)) packets in ${FLOOD_MS}ms)"
else
    fail "Server unresponsive after flood"
fi

# No sessions created from garbage?
A_SESSIONS=$(prom_value "hpn_sessions_active")
if [ "${A_SESSIONS:-0}" = "${B_SESSIONS:-0}" ]; then
    pass "No sessions created from random data (still ${A_SESSIONS})"
else
    warn "Session count changed: ${B_SESSIONS} -> ${A_SESSIONS}"
fi

# Check handshake failures increased (expected — random data)
A_HS_FAIL=$(prom_value "hpn_handshakes_failed_total")
A_PKT_DROP=$(prom_value "hpn_packets_dropped_total")
NEW_DROPS=$(( ${A_PKT_DROP:-0} - ${B_PKT_DROP:-0} ))
NEW_HS_FAIL=$(( ${A_HS_FAIL:-0} - ${B_HS_FAIL:-0} ))
info "New drops: ${NEW_DROPS}, new handshake failures: ${NEW_HS_FAIL}"

# ═════════════════════════════════════════════════════════════════════════════
# TEST 2: Metrics Endpoint Stress (100 concurrent HTTP requests)
# ═════════════════════════════════════════════════════════════════════════════

log ""
log "=== TEST 2: Metrics Endpoint Stress (100 concurrent) ==="

STRESS_START=$(date +%s)
STRESS_OK=0
STRESS_FAIL_COUNT=0
STRESS_PIDS=()

for i in $(seq 1 100); do
    (
        RESP=$(curl -sf -o /dev/null -w "%{http_code}" --connect-timeout 3 "${METRICS_URL}/metrics" 2>/dev/null || echo "000")
        [ "$RESP" = "200" ]
    ) &
    STRESS_PIDS+=($!)
done

for pid in "${STRESS_PIDS[@]}"; do
    if wait "$pid" 2>/dev/null; then
        STRESS_OK=$((STRESS_OK + 1))
    else
        STRESS_FAIL_COUNT=$((STRESS_FAIL_COUNT + 1))
    fi
done

STRESS_END=$(date +%s)
STRESS_DUR=$((STRESS_END - STRESS_START))

if [ "$STRESS_FAIL_COUNT" -le 5 ]; then
    pass "Metrics stress: ${STRESS_OK}/100 OK in ${STRESS_DUR}s"
else
    warn "Metrics stress: ${STRESS_FAIL_COUNT}/100 failed"
fi

# ═════════════════════════════════════════════════════════════════════════════
# TEST 3: Throughput Benchmark (iperf3 through VPN tunnel)
# ═════════════════════════════════════════════════════════════════════════════

if [ "$SKIP_THROUGHPUT" = "0" ] && [ "$HAS_IPERF" = "1" ]; then
    log ""
    log "=== TEST 3: Throughput Benchmark (iperf3 → ${TUNNEL_IP}:${IPERF_PORT}) ==="
    log "  Requires: VPN connected + iperf3 -s -p ${IPERF_PORT} -D on server"

    # ── TCP Download ──
    log "  [3a] TCP download (server → client, ${DURATION}s)..."
    TCP_DOWN=$(iperf3 -c "$TUNNEL_IP" -p "$IPERF_PORT" -t "$DURATION" -R -J 2>/dev/null || echo '{}')
    TCP_DOWN_BPS=$(echo "$TCP_DOWN" | jq -r '.end.sum_received.bits_per_second // 0' 2>/dev/null || echo "0")
    TCP_DOWN_MBPS=$(echo "scale=1; ${TCP_DOWN_BPS:-0} / 1000000" | bc 2>/dev/null || echo "0")

    if [ "${TCP_DOWN_BPS:-0}" != "0" ]; then
        if (( $(echo "$TCP_DOWN_MBPS > 100" | bc -l 2>/dev/null || echo 0) )); then
            pass "TCP download: ${TCP_DOWN_MBPS} Mbps"
        elif (( $(echo "$TCP_DOWN_MBPS > 50" | bc -l 2>/dev/null || echo 0) )); then
            warn "TCP download: ${TCP_DOWN_MBPS} Mbps (moderate)"
        else
            warn "TCP download: ${TCP_DOWN_MBPS} Mbps (low)"
        fi
    else
        warn "TCP download failed — is iperf3 running on server?"
    fi

    # ── TCP Upload ──
    log "  [3b] TCP upload (client → server, ${DURATION}s)..."
    TCP_UP=$(iperf3 -c "$TUNNEL_IP" -p "$IPERF_PORT" -t "$DURATION" -J 2>/dev/null || echo '{}')
    TCP_UP_BPS=$(echo "$TCP_UP" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
    TCP_UP_MBPS=$(echo "scale=1; ${TCP_UP_BPS:-0} / 1000000" | bc 2>/dev/null || echo "0")

    if [ "${TCP_UP_BPS:-0}" != "0" ]; then
        if (( $(echo "$TCP_UP_MBPS > 100" | bc -l 2>/dev/null || echo 0) )); then
            pass "TCP upload: ${TCP_UP_MBPS} Mbps"
        elif (( $(echo "$TCP_UP_MBPS > 50" | bc -l 2>/dev/null || echo 0) )); then
            warn "TCP upload: ${TCP_UP_MBPS} Mbps (moderate)"
        else
            warn "TCP upload: ${TCP_UP_MBPS} Mbps (low)"
        fi
    else
        warn "TCP upload failed"
    fi

    # ── UDP 100 Mbps target ──
    log "  [3c] UDP throughput (100 Mbps target, ${DURATION}s)..."
    UDP_RES=$(iperf3 -c "$TUNNEL_IP" -p "$IPERF_PORT" -u -b 100M -t "$DURATION" -J 2>/dev/null || echo '{}')
    UDP_BPS=$(echo "$UDP_RES" | jq -r '.end.sum.bits_per_second // 0' 2>/dev/null || echo "0")
    UDP_MBPS=$(echo "scale=1; ${UDP_BPS:-0} / 1000000" | bc 2>/dev/null || echo "0")
    UDP_LOSS=$(echo "$UDP_RES" | jq -r '.end.sum.lost_percent // 0' 2>/dev/null || echo "?")

    if [ "${UDP_BPS:-0}" != "0" ]; then
        info "UDP: ${UDP_MBPS} Mbps, loss ${UDP_LOSS}%"
        if (( $(echo "${UDP_LOSS:-100} < 1" | bc -l 2>/dev/null || echo 0) )); then
            pass "UDP loss < 1%"
        else
            warn "UDP loss ${UDP_LOSS}% (>= 1%)"
        fi
    else
        warn "UDP throughput test failed"
    fi

    # ── Parallel 10-stream ──
    log "  [3d] Parallel (10 streams, 30s)..."
    PAR_RES=$(iperf3 -c "$TUNNEL_IP" -p "$IPERF_PORT" -t 30 -P 10 -J 2>/dev/null || echo '{}')
    PAR_BPS=$(echo "$PAR_RES" | jq -r '.end.sum_sent.bits_per_second // 0' 2>/dev/null || echo "0")
    PAR_MBPS=$(echo "scale=1; ${PAR_BPS:-0} / 1000000" | bc 2>/dev/null || echo "0")

    if [ "${PAR_BPS:-0}" != "0" ]; then
        info "Parallel (10 streams): ${PAR_MBPS} Mbps"
    else
        warn "Parallel test failed"
    fi

    # Server-side traffic stats delta
    T_TX=$(prom_value "hpn_bytes_sent_total")
    T_RX=$(prom_value "hpn_bytes_received_total")
    DELTA_TX=$(( ${T_TX:-0} - ${B_TX:-0} ))
    DELTA_RX=$(( ${T_RX:-0} - ${B_RX:-0} ))
    DELTA_TX_MB=$(echo "scale=1; $DELTA_TX / 1048576" | bc 2>/dev/null || echo "?")
    DELTA_RX_MB=$(echo "scale=1; $DELTA_RX / 1048576" | bc 2>/dev/null || echo "?")
    info "Server-side traffic delta: TX=${DELTA_TX_MB} MB, RX=${DELTA_RX_MB} MB"

else
    log ""
    log "=== TEST 3: Throughput SKIPPED ==="
    info "Skipped (--skip-throughput or no iperf3)"
fi

# ═════════════════════════════════════════════════════════════════════════════
# TEST 4: Live Metrics Snapshot
# ═════════════════════════════════════════════════════════════════════════════

log ""
log "=== TEST 4: Live Metrics Snapshot ==="

M_UPTIME=$(prom_value "hpn_uptime_seconds")
M_ACTIVE=$(prom_value "hpn_sessions_active")
M_TOTAL=$(prom_value "hpn_sessions_total")
M_HS_OK=$(prom_value "hpn_handshakes_success_total")
M_HS_FAIL=$(prom_value "hpn_handshakes_failed_total")
M_TX=$(prom_value "hpn_bytes_sent_total")
M_RX=$(prom_value "hpn_bytes_received_total")
M_PKT_S=$(prom_value "hpn_packets_sent_total")
M_PKT_R=$(prom_value "hpn_packets_received_total")
M_PKT_D=$(prom_value "hpn_packets_dropped_total")
M_TX_MB=$(echo "scale=2; ${M_TX:-0} / 1048576" | bc 2>/dev/null || echo "?")
M_RX_MB=$(echo "scale=2; ${M_RX:-0} / 1048576" | bc 2>/dev/null || echo "?")

info "Uptime:     ${M_UPTIME:-?}s"
info "Sessions:   ${M_ACTIVE:-0} active / ${M_TOTAL:-0} total"
info "Handshakes: ${M_HS_OK:-0} ok / ${M_HS_FAIL:-0} fail"
info "Traffic:    TX=${M_TX_MB} MB  RX=${M_RX_MB} MB"
info "Packets:    sent=${M_PKT_S:-0}  recv=${M_PKT_R:-0}  drop=${M_PKT_D:-0}"

if [ "${M_PKT_R:-0}" -gt 0 ] && [ "${M_PKT_D:-0}" -gt 0 ]; then
    DROP_PCT=$(echo "scale=4; ${M_PKT_D} / ${M_PKT_R} * 100" | bc 2>/dev/null || echo "?")
    if (( $(echo "${DROP_PCT:-100} > 5" | bc -l 2>/dev/null || echo 0) )); then
        warn "Overall drop rate: ${DROP_PCT}%"
    else
        pass "Overall drop rate: ${DROP_PCT}%"
    fi
fi

pass "Metrics snapshot collected"

# ═════════════════════════════════════════════════════════════════════════════
# TEST 5: Endurance (repeated health checks)
# ═════════════════════════════════════════════════════════════════════════════

if [ "$SKIP_ENDURANCE" = "0" ]; then
    log ""
    log "=== TEST 5: Endurance (${DURATION}s, health every 5s) ==="

    END_START=$(date +%s)
    END_OK=0
    END_FAIL_CNT=0

    while true; do
        NOW=$(date +%s)
        [ $((NOW - END_START)) -ge "$DURATION" ] && break

        if health_ok; then
            END_OK=$((END_OK + 1))
        else
            END_FAIL_CNT=$((END_FAIL_CNT + 1))
            log "    Health FAIL at +$((NOW - END_START))s"
        fi
        sleep 5
    done

    TOTAL_CHK=$((END_OK + END_FAIL_CNT))
    if [ "$END_FAIL_CNT" -eq 0 ]; then
        pass "Endurance: ${TOTAL_CHK}/${TOTAL_CHK} checks OK over ${DURATION}s"
    else
        fail "Endurance: ${END_FAIL_CNT}/${TOTAL_CHK} checks FAILED"
    fi
else
    log ""
    log "=== TEST 5: Endurance SKIPPED ==="
fi

# ═════════════════════════════════════════════════════════════════════════════
# TEST 6: Post-test resource check
# ═════════════════════════════════════════════════════════════════════════════

log ""
log "=== TEST 6: Post-Test Resource Check ==="

if health_ok; then
    FINAL_UP=$(prom_value "hpn_uptime_seconds")
    pass "Server alive (uptime: ${FINAL_UP:-?}s)"
else
    fail "Server not responding at end of tests"
fi

FINAL_SESS=$(prom_value "hpn_sessions_active")
if [ "${FINAL_SESS:-0}" = "${B_SESSIONS:-0}" ]; then
    pass "No orphan sessions (${FINAL_SESS})"
else
    DELTA=$(( ${FINAL_SESS:-0} - ${B_SESSIONS:-0} ))
    if [ "$DELTA" -le 0 ]; then
        pass "Session count stable/decreased: ${B_SESSIONS} -> ${FINAL_SESS}"
    else
        warn "Session count +${DELTA}: ${B_SESSIONS} -> ${FINAL_SESS}"
    fi
fi

# ═════════════════════════════════════════════════════════════════════════════
# REPORT
# ═════════════════════════════════════════════════════════════════════════════

echo ""
echo "============================================================"
echo "  LOAD TEST REPORT"
echo "============================================================"
echo ""
echo "  Server:   ${SERVER_IP}:${VPN_PORT}"
echo "  Date:     $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Duration: ${DURATION}s"
echo "  Clients:  ${NUM_CLIENTS}"
echo ""
echo "  PASS: ${PASS}"
echo "  FAIL: ${FAIL}"
echo "  WARN: ${WARN}"
echo ""

for r in "${RESULTS[@]}"; do
    echo "    $r"
done

echo ""
if [ "$FAIL" -eq 0 ]; then
    echo "  VERDICT: READY FOR PRODUCTION"
else
    echo "  VERDICT: ${FAIL} FAILURES — REVIEW BEFORE PRODUCTION"
fi
echo ""
echo "============================================================"

# Write file
{
    echo "HPN VPN Load Test Report"
    echo "========================"
    echo "Server:   ${SERVER_IP}:${VPN_PORT}"
    echo "Date:     $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Duration: ${DURATION}s"
    echo "Clients:  ${NUM_CLIENTS}"
    echo ""
    echo "PASS: ${PASS}  FAIL: ${FAIL}  WARN: ${WARN}"
    echo ""
    for r in "${RESULTS[@]}"; do echo "$r"; done
    echo ""
    [ "$FAIL" -eq 0 ] && echo "VERDICT: READY FOR PRODUCTION" || echo "VERDICT: ${FAIL} FAILURES"
} > "$REPORT_FILE"

echo "Report: ${REPORT_FILE}"
[ "$FAIL" -eq 0 ]
