# Snort 3.9.7.0 Syntax Cheatsheet

This is the authoritative grammar reference for rule generation in this project. Do NOT emit Snort 2 syntax.

## Rule Structure

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

- `action`: alert, log, pass, drop, reject (use `alert` unless you have a reason).
- `proto`: tcp, udp, icmp, ip.
- `direction`: `->` (one-way), `<>` (bidirectional).
- Every full rule option ends with a semicolon inside the parentheses.

## Content Modifier Syntax (Snort 3)

Modifiers go INSIDE the same `content` option, comma-separated.

Correct:

```
content:"RTPS",nocase;
content:"|52 54 50 53|",offset 0,depth 4;
content:"RTPS",offset 0,depth 4,nocase;
```

Wrong (Snort 2 style — REJECTED):

```
content:"RTPS"; nocase;
content:"RTPS"; offset:0; depth:4;
```

Never emit `nocase`, `offset`, `depth`, `within`, or `distance` as standalone options.

## Raw Packet Data

- `rawbytes` is Snort 2 syntax and is FORBIDDEN.
- In Snort 3 use `raw_data;` when raw packet bytes are required.
- Most UDP payload rules do not need `raw_data` unless the testbed explicitly requires it.

## Detection Filter

Use:

```
detection_filter:track by_src, count N, seconds S;
```

`threshold` is forbidden — use `detection_filter`.

## Forbidden Keywords

These are Snort 2 only and will be rejected:

- `rawbytes`
- `threshold`
- `uricontent`
- `resp`
- `react`
- `tag`

## Flow Combinations

- `flow:stateless` cannot be combined with any other `flow` option.
- For UDP, usually omit `flow` entirely.
- When stateless is needed: `flow:stateless;` (and nothing else).

## Valid Common Options

```
flow, content, pcre, detection_filter, classtype, priority, metadata,
reference, service, flags, seq, ack, window, ttl, tos, id, ipopts,
fragbits, fragoffset, dsize, offset, depth, within, distance,
raw_data, pkt_data, nocase, isdataat, byte_test, byte_jump, byte_extract,
file_data, base64_decode, base64_data,
http_client_body, http_cookie, http_header, http_method,
http_raw_uri, http_stat_code, http_uri,
ssl_state, ssl_version, tls_cert_subject, tls_cert_issuer,
sid, rev, msg, gid
```

`nocase`, `offset`, `depth`, `within`, and `distance` are valid CONCEPTS but must be emitted as content modifiers (comma-separated inside `content:"..."`), not as standalone options.

## SID and Revision

- Always emit `sid:0;` as placeholder. The `assign_sid` tool replaces it with a real numeric SID before deployment.
- Always emit `rev:1;` on first generation. Bump to `rev:2;`, `rev:3;`, … on each regeneration of the same logical rule.

## Message Field

The `msg` field MUST contain the operator intent verbatim. Example:

Intent: `Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888`

Resulting `msg`: `msg:"Detect XRCE-DDS UDP DoS against 172.17.0.2 port 8888";`
