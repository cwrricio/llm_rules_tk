# xrce-dds-udp-dos

> UDP flood against the XRCE-DDS Agent (port 8888) using RTPS/XRCE ping datagrams from a single source, saturating the Agent's UDP port. Base vector of variacoes/refinamento_xrce-dds-udp-dos.md.

The container floods the target with RTPS-fingerprinted ping datagrams. In the
self-contained pipeline it writes the crafted packets to `/out/attack.pcap` (mounted
by the harness) instead of transmitting them, so the real Snort engine can replay
them in read-file mode — the bytes on the wire are identical.

## Run

```bash
docker run --rm -v "$PWD/out:/out" iotedu-attack-xrce-dds-udp-dos:latest "172.17.0.2" "8888" "80" "64"
```

Positional arguments: `<target_ip> <target_port> <num_packets> <payload_size>`.
`target_ip`/`target_port` are the fixed XRCE-DDS destination (never mutated by the
Attack Agent). `num_packets` and `payload_size` are evasion knobs the agent may vary;
deeper evasions edit `attack_udp_dos.py` directly (the `MUTABLE PARAMETERS` block) and
rebuild the image.
