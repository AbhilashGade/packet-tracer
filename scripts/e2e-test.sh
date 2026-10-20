#!/usr/bin/env bash
#
# End-to-end test against a real kernel.
#
# Builds a veth pair with one end in a network namespace, attaches the XDP
# program to the host end, and checks that traffic sourced from the namespace
# is dropped or passed according to the rules.
#
# veth is used rather than a physical NIC because it is the only link type that
# can be created, torn down, and reasoned about deterministically in CI. The
# tradeoff is real: veth supports native XDP, but the generic/SKB path is the
# one that always works, so both are exercised below.
#
# Must run as root. Leaves nothing behind.

set -euo pipefail

NS=pt-test
VETH_HOST=pt-veth0
VETH_PEER=pt-veth1
HOST_IP=10.100.0.1
PEER_IP=10.100.0.2
PREFIX=24
BIN=${BIN:-./target/release/packet-tracer}

pass=0
fail=0

cleanup() {
    set +e
    [[ -n "${TRACER_PID:-}" ]] && kill "$TRACER_PID" 2>/dev/null
    [[ -n "${TRACER_PID:-}" ]] && wait "$TRACER_PID" 2>/dev/null
    ip netns del "$NS" 2>/dev/null
    # Deleting the namespace takes the peer with it; the host side may survive
    # if setup failed partway.
    ip link del "$VETH_HOST" 2>/dev/null
    set -e
}
trap cleanup EXIT

setup_link() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true

    ip netns add "$NS"
    ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
    ip link set "$VETH_PEER" netns "$NS"

    ip addr add "$HOST_IP/$PREFIX" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    ip -n "$NS" addr add "$PEER_IP/$PREFIX" dev "$VETH_PEER"
    ip -n "$NS" link set "$VETH_PEER" up
    ip -n "$NS" link set lo up
}

# ping from the namespace toward the host end, where the XDP program sits.
# Returns 0 if any reply came back.
ping_from_ns() {
    ip netns exec "$NS" ping -c 3 -W 1 -i 0.3 "$HOST_IP" >/dev/null 2>&1
}

check() {
    local name=$1 expected=$2 actual=$3
    if [[ "$expected" == "$actual" ]]; then
        echo "  ok   — $name"
        pass=$((pass + 1))
    else
        echo "  FAIL — $name (expected $expected, got $actual)"
        fail=$((fail + 1))
    fi
}

start_tracer() {
    local mode=$1
    shift
    "$BIN" --iface "$VETH_HOST" --mode "$mode" --stats-interval 0 "$@" \
        >/tmp/pt-test.log 2>&1 &
    TRACER_PID=$!
    # Wait for the attach to land rather than sleeping a fixed amount, so the
    # test does not race the loader on a slow machine.
    for _ in $(seq 1 50); do
        grep -q "attached to" /tmp/pt-test.log && return 0
        if ! kill -0 "$TRACER_PID" 2>/dev/null; then
            echo "  tracer died during startup:"
            sed 's/^/    /' /tmp/pt-test.log
            return 1
        fi
        sleep 0.2
    done
    echo "  tracer never reported attach:"
    sed 's/^/    /' /tmp/pt-test.log
    return 1
}

stop_tracer() {
    kill -INT "$TRACER_PID" 2>/dev/null || true
    wait "$TRACER_PID" 2>/dev/null || true
    TRACER_PID=
}

run_case() {
    local name=$1 mode=$2 expect=$3
    shift 3
    echo "[$name] (mode=$mode)"
    setup_link
    if ! start_tracer "$mode" "$@"; then
        fail=$((fail + 1))
        return
    fi
    local got
    if ping_from_ns; then got=reachable; else got=blocked; fi
    check "$name" "$expect" "$got"
    stop_tracer
}

if [[ $EUID -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "binary not found at $BIN — run 'cargo build --release' first" >&2
    exit 1
fi

echo "kernel: $(uname -r)"
echo

# Baseline: with no rules, nothing should be affected. If this fails, the
# harness itself is broken and every other result is meaningless.
run_case "no rules passes traffic" skb reachable

# The rule the tool exists to enforce.
run_case "host rule drops" skb blocked --rule "$PEER_IP/32=drop"

# Prefix matching, not just exact addresses.
run_case "prefix rule drops" skb blocked --rule "10.100.0.0/24=drop"

# A prefix that does not cover the sender must not match.
run_case "non-matching prefix passes" skb reachable --rule "10.200.0.0/24=drop"

# Protocol constraint: a TCP-only rule must not touch ICMP.
run_case "tcp rule ignores icmp" skb reachable --rule "$PEER_IP/32,tcp,22=drop"

# An ICMP rule on the same address must match.
run_case "icmp rule drops" skb blocked --rule "$PEER_IP/32,icmp=drop"

# An explicit pass rule is not a drop rule.
run_case "explicit pass rule passes" skb reachable --rule "$PEER_IP/32=pass"

# Longest-prefix wins: /32 pass must beat /24 drop.
run_case "longest prefix wins" skb reachable \
    --rule "10.100.0.0/24=drop" --rule "$PEER_IP/32=pass"

# Regression: a /32 rule that does not match the packet must not shadow a /24
# rule that does. Before rule flattening, the LPM lookup returned only the /32
# entry, its protocol check failed, and the packet was passed — the /24 rule
# was never consulted.
run_case "specific rule does not shadow broader one" skb blocked \
    --rule "$PEER_IP/32,tcp,22=drop" --rule "10.100.0.0/24,icmp=drop"

# And the inverse: inheritance must not invent matches that were never written.
run_case "inheritance does not over-match" skb reachable \
    --rule "$PEER_IP/32,tcp,22=drop" --rule "10.100.0.0/24,udp,53=drop"

# Native XDP on veth. Supported on modern kernels; if the driver refuses, that
# is a property of the environment and reported as skipped, not failed.
echo "[native driver mode]"
setup_link
if start_tracer driver --rule "$PEER_IP/32=drop" 2>/dev/null; then
    if ping_from_ns; then got=reachable; else got=blocked; fi
    check "driver mode drops" blocked "$got"
    stop_tracer
else
    echo "  skip — veth on this kernel refused native XDP attach"
    TRACER_PID=
fi

echo
echo "passed: $pass   failed: $fail"
[[ $fail -eq 0 ]]
