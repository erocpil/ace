#!/bin/sh

# dev1="veth-ns1"
# dev2="veth-ns2"
dev1="ens2f1"
dev2="ens2f2"

ip netns add ns1
ip netns add ns2
ip link add veth-ns1 type veth peer name veth-ns2
ip link set $dev1 netns ns1
ip link set $dev2 netns ns2
ip -n ns1 addr add local 1.1.1.1/8 dev $dev1
ip -n ns2 addr add local 2.2.2.2/8 dev $dev2
ip -n ns1 link set $dev1 up
ip -n ns2 link set $dev2 up
ip netns exec ns1 ip route add default via 1.1.1.1 dev $dev1
ip netns exec ns2 ip route add default via 2.2.2.2 dev $dev2

# ip -all netns delete
