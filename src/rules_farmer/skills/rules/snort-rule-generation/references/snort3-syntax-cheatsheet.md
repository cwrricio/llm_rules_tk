# Snort 3.9.7.0 Syntax Cheatsheet

This is the authoritative grammar reference for rule generation in this project. Do NOT emit Snort 2 syntax.

## Rule Structure

```
action proto src_ip src_port direction dst_ip dst_port (options;)
```

- `action`: alert, log, pass, drop, reject (use `alert` unless you have a reason).
- `proto`: tcp, udp, icmp, ip.
- `direction`: `->` (one-way), `<>` (bidirectional). **Always use `->`, never `<>` unless explicitly required — bidirectional catches server responses and causes false positives.**
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

## dsize Semantics — CRITICAL

`dsize:X<>Y` matches packets where the payload size IS between X and Y (INCLUSIVE of both bounds).

```
dsize:100<>400   → matches packets with payload 100 ≤ size ≤ 400
dsize:<100       → matches packets with payload size < 100 bytes
dsize:>400       → matches packets with payload size > 400 bytes
dsize:100        → matches packets with payload size == 100 bytes exactly
```

**Common mistake**: `dsize:100<>400` does NOT mean "not between 100 and 400". It means "between 100 and 400".

To match packets OUTSIDE a range you need two separate rules, or use `dsize:<X` / `dsize:>Y` in separate passes.

## Protocol Fingerprints

### XRCE-DDS (XRCE over UDP, port 8888)
- microXRCE-DDS library packets begin with a session header (4 bytes: session_id + stream_id + seq_num_lo + seq_num_hi) followed by submessage headers.
- CREATE_CLIENT (session init) contains a GUID prefix identifying the client library.
- PING submessage: very small (8–24 bytes total payload) with a known submessage ID.
- WRITE_DATA submessage: variable size, carries serialized CDR payload.
- Safe fingerprint bytes for CREATE_CLIENT: `|00 00 00 00|` at offset 0 (new session_id), followed by session-init submessage type `|01|`.

### RTPS (DDS native, multicast / unicast)
- Magic bytes: `|52 54 50 53|` ("RTPS") at byte 0 of the UDP payload.
- Version bytes follow: `|02 03|` or `|02 04|`.
- Use `content:"|52 54 50 53|",offset 0,depth 4;` to anchor.

### MQTT (port 1883)
- CONNECT: first byte `|10|`, followed by the protocol name `MQIsdp` or `MQTT`.
- PUBLISH: first byte `|30|` to `|3F|` (high nibble = 3, low nibble = QoS/retain/dup bits).
- Use `content:"|10|",offset 0,depth 1;` for CONNECT fingerprint.

## Raw Packet Data

- `rawbytes` is Snort 2 syntax and is FORBIDDEN.
- In Snort 3 use `raw_data;` when raw packet bytes are required.
- Most UDP payload rules do not need `raw_data` unless the testbed explicitly requires it.

## Detection Filter

Use:

```
detection_filter:track by_src, count N, seconds S;
```

- **Always track `by_src`** (per originating IP). Never `by_dst` — that aggregates all clients together.
- Calibrate `count` to be ABOVE the maximum a legitimate single client would send. For a flood attack, count 50 in 10 seconds is aggressive; count 5 in 30 seconds is conservative. Err on the side of higher count to avoid false positives.
- `detection_filter` alone is NOT sufficient — always combine with a payload match.

`threshold` is forbidden — use `detection_filter`.

## False-Positive Prevention Checklist

Before submitting any rule, verify:

1. **Direction**: Is the rule using `->` (not `<>`)? Bidirectional rules catch server responses.
2. **Content anchor**: Does the rule contain at least one protocol-specific content/pcre/byte_test that only attack packets would match?
3. **dsize range**: Would the dsize range also match legitimate protocol traffic (e.g., normal handshake messages, keepalive pings)?
4. **Rate threshold**: Would a normal client (single connection, 1 operation per minute) trigger the detection_filter?
5. **Protocol specificity**: Is the content match broad (e.g., `content:"xml"` matches almost all XRCE-DDS XML-mode packets) or narrow (e.g., a specific submessage byte sequence)?

If any answer is "yes", tighten the rule before submitting.

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
