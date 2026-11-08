#!/usr/bin/env bash
# Optional local topology: four Linux network namespaces on one test machine.
# Depends on iproute2, iptables, ethtool and CAP_NET_ADMIN.
set -euo pipefail
if (( EUID != 0 )); then echo 'Run as root.' >&2; exit 1; fi
ACTION="${1:-up}"
NAMES=(s_pc1 s_d1 s_d2 s_pc2)

cleanup() {
  for ns in "${NAMES[@]}"; do ip netns del "$ns" 2>/dev/null || true; done
}

case "$ACTION" in
  down) cleanup; echo 'Lab namespaces removed'; exit 0 ;;
  up) ;;
  *) echo "Usage: $0 up|down" >&2; exit 2 ;;
esac
for ns in "${NAMES[@]}"; do
  if ip netns list | grep -q "^$ns "; then
    echo "Namespace $ns already exists; run $0 down first" >&2; exit 1
  fi
done
for ns in "${NAMES[@]}"; do ip netns add "$ns"; ip -n "$ns" link set lo up; done
ip link add p1eth type veth peer name d1lan
ip link add d1wan type veth peer name d2wan
ip link add d2lan type veth peer name p2eth
ip link set p1eth netns s_pc1
ip link set d1lan netns s_d1
ip link set d1wan netns s_d1
ip link set d2wan netns s_d2
ip link set d2lan netns s_d2
ip link set p2eth netns s_pc2
ip -n s_pc1 addr add 10.1.0.2/24 dev p1eth
ip -n s_d1 addr add 10.1.0.1/24 dev d1lan
ip -n s_d1 addr add 10.12.0.1/30 dev d1wan
ip -n s_d2 addr add 10.12.0.2/30 dev d2wan
ip -n s_d2 addr add 10.2.0.1/24 dev d2lan
ip -n s_pc2 addr add 10.2.0.2/24 dev p2eth
for spec in 's_pc1 p1eth' 's_d1 d1lan' 's_d1 d1wan' 's_d2 d2wan' 's_d2 d2lan' 's_pc2 p2eth'; do
  read -r ns dev <<< "$spec"
  ip -n "$ns" link set "$dev" up
  ip netns exec "$ns" ethtool -K "$dev" gro off gso off tso off tx off rx off 2>/dev/null || true
done
ip -n s_pc1 route add 10.2.0.0/24 via 10.1.0.1 advmss 1200
ip -n s_pc2 route add 10.1.0.0/24 via 10.2.0.1 advmss 1200
ip -n s_d1 route add 10.2.0.0/24 via 10.12.0.2
ip -n s_d2 route add 10.1.0.0/24 via 10.12.0.1
for ns in s_d1 s_d2; do
  ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
  ip netns exec "$ns" bash "$(dirname "$0")/firewall.sh" install
done
printf '\nNamespaces ready. Start gateway executables in s_d1 and s_d2.\n'
printf 'Run scripts/netns_lab.sh down for cleanup.\n'
