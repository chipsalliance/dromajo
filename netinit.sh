#!/bin/sh
#
# RISCVEMU Ethernet bridge and NAT configuration (run with sudo)
#
# Copyright (c) 2017 Fabrice Bellard
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

# host network interface connected to Internet (change it)
internet_ifname="enp0s20f0u1"

# setup bridge interface
ip link add br0 type bridge
# create and add tap0 interface to bridge
ip tuntap add dev tap0 mode tap user $USER
ip link set tap0 master br0

ip link set dev br0 up
ip link set dev tap0 up
ifconfig br0 192.168.3.1

# setup NAT to access to Internet
echo 1 > /proc/sys/net/ipv4/ip_forward
# delete forwarding reject rule if present
#iptables -D FORWARD 1
iptables -t nat -A POSTROUTING -o $internet_ifname -j MASQUERADE 
