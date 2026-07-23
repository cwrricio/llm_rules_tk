#!/bin/sh
# usage: entrypoint.sh <target_ip> <target_port> <num_packets> <payload_size>
#
# Positional arguments (the Attack Agent fills the first two from the fixed
# destination in config; num_packets/payload_size are evasion knobs it may vary):
#   target_ip     destination IP of the XRCE-DDS Agent  (FIXED — never mutated)
#   target_port   destination UDP port                  (FIXED — never mutated)
#   num_packets   how many ping datagrams to send in the burst
#   payload_size  size in bytes of each datagram payload
exec python3 /app/attack_udp_dos.py "$@"
