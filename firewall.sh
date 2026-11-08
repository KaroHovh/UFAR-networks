#!/usr/bin/env bash
# Install reversible NFQUEUE + NOTRACK rules on either inline gateway.
# Designed ONLY for an isolated test lab. Does not flush pre-existing rules.
set -euo pipefail
if (( EUID != 0 )); then echo 'Run as root.' >&2; exit 1; fi
ACTION="${1:-install}"
PC1="${PC1:-10.1.0.2}"
PC2="${PC2:-10.2.0.2}"
PORT="${PORT:-5000}"
QUEUE="${QUEUE:-10}"
CHAIN="STCP_LAB"

case "$ACTION" in
  install)
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN"
    # Block noninitial fragments before ports are inspected. First fragments
    # with MF=1 are rejected in the packet processor itself.
    iptables -A "$CHAIN" -p tcp -s "$PC1" -d "$PC2" -f -j DROP
    iptables -A "$CHAIN" -p tcp -s "$PC2" -d "$PC1" -f -j DROP
    iptables -A "$CHAIN" -p tcp -s "$PC1" -d "$PC2" --dport "$PORT" -j NFQUEUE --queue-num "$QUEUE"
    iptables -A "$CHAIN" -p tcp -s "$PC1" -d "$PC2" --dport "$PORT" -j ACCEPT
    iptables -A "$CHAIN" -p tcp -s "$PC2" -d "$PC1" --sport "$PORT" -j NFQUEUE --queue-num "$QUEUE"
    iptables -A "$CHAIN" -p tcp -s "$PC2" -d "$PC1" --sport "$PORT" -j ACCEPT
    iptables -A "$CHAIN" -j RETURN
    iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
    # Linux conntrack cannot track inflated/encrypted TCP segment lengths.
    # Mark both directions UNTRACKED before conntrack has a chance to inspect.
    iptables -t raw -C PREROUTING -p tcp -s "$PC1" -d "$PC2" -j CT --notrack 2>/dev/null || \
      iptables -t raw -I PREROUTING -p tcp -s "$PC1" -d "$PC2" -j CT --notrack
    iptables -t raw -C PREROUTING -p tcp -s "$PC2" -d "$PC1" -j CT --notrack 2>/dev/null || \
      iptables -t raw -I PREROUTING -p tcp -s "$PC2" -d "$PC1" -j CT --notrack
    echo "Installed STCP_LAB rules for $PC1 <-> $PC2 on TCP/$PORT, NFQUEUE $QUEUE."
    echo 'IMPORTANT: no --queue-bypass, so selected packets are dropped if the processor is unavailable.'
    echo 'Existing FORWARD firewall policies must permit these UNTRACKED flows.'
    ;;
  remove)
    iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    iptables -t raw -D PREROUTING -p tcp -s "$PC1" -d "$PC2" -j CT --notrack 2>/dev/null || true
    iptables -t raw -D PREROUTING -p tcp -s "$PC2" -d "$PC1" -j CT --notrack 2>/dev/null || true
    echo 'Removed lab forwarding rules.'
    ;;
  *) echo 'Usage: firewall.sh install|remove' >&2; exit 2 ;;
esac
