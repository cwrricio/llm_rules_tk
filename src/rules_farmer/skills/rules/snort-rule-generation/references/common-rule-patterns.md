# Common Snort 3.9.7.0 Rule Patterns

Worked examples by attack class. Adapt the IP, port, and msg to the operator intent before emitting.

## UDP Flood / DoS (rate-based)

Intent: detect a UDP flood targeting host:port.

```
alert udp any any -> 172.17.0.2 8888 (msg:"Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888"; detection_filter:track by_src, count 100, seconds 1; sid:0; rev:1;)
```

Key points:

- `flow` is omitted (UDP, rate-based).
- `detection_filter` distinguishes a flood from legitimate traffic.

## TCP SYN Scan

Intent: detect TCP SYN scan against target.

```
alert tcp any any -> 172.17.0.2 any (msg:"Detect TCP SYN scan against 172.17.0.2"; flags:S; detection_filter:track by_src, count 20, seconds 10; sid:0; rev:1;)
```

## Payload Match (binary signature)

Intent: detect packet containing RTPS magic bytes.

```
alert udp any any -> 172.17.0.2 8888 (msg:"Detect RTPS magic in payload"; content:"|52 54 50 53|",offset 0,depth 4; sid:0; rev:1;)
```

## Payload Match (ASCII)

Intent: detect packet containing the literal string "exploit".

```
alert tcp any any -> 172.17.0.2 any (msg:"Detect 'exploit' literal"; content:"exploit",nocase; sid:0; rev:1;)
```

## HTTP-Aware Match

Intent: detect HTTP GET to a specific URI.

```
alert tcp any any -> 172.17.0.2 80 (msg:"Detect GET /admin"; http_method:"GET"; http_uri:"/admin"; sid:0; rev:1;)
```

## Large Packet (dsize)

Intent: detect oversized packets to a UDP service.

```
alert udp any any -> 172.17.0.2 8888 (msg:"Detect oversized UDP packets"; dsize:>1400; sid:0; rev:1;)
```

## Fragmented Packets

```
alert ip any any -> 172.17.0.2 any (msg:"Detect IP fragments"; fragbits:M; sid:0; rev:1;)
```

## Notes on Refinement

When a rule does NOT fire and you must regenerate:

- If `container_exit_code == 0` and the rule did not fire, the matcher is too narrow — broaden the matching options, drop overly specific content matches, or relax the detection_filter threshold.
- If `container_exit_code != 0`, the attack container errored before producing the expected traffic — the issue is at the attacker layer, not the rule. Look at `container_stderr` and report the diagnosis instead of looping on rule changes.
- If `validation_error` says the syntax is wrong, fix syntax per `snort3-syntax-cheatsheet.md` and bump `rev`.
