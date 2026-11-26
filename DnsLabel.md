# DnsLabel — DNS Wire-Format Name Parser

`DnsLabel` (`src/core/packets.rs`) parses domain names from DNS wire format (RFC 1035 Section 4.1.4).

## Structure

```rust
pub struct DnsLabel<'a> {
    pub name: LabelVec<'a>,   // ArrayVec<&str, 40> — parsed label segments
    pub offset: Option<u16>,  // compression pointer target, if present
}
```

`name` holds the literal label segments read from the wire (e.g. `["www", "example", "com"]`). `offset` is set when the label sequence ends with a compression pointer instead of a zero terminator.

`LabelVec` is `ArrayVec<&'a str, 40>` — stack-allocated, max 40 segments (enough for IPv6 reverse DNS which needs 34).

## Wire Format

A DNS name is a sequence of **labels**, each prefixed by a length byte. The sequence ends with either:

- A **zero byte** (`0x00`) — end of name
- A **compression pointer** — two bytes where the top 2 bits are `11`

### Length byte encoding (top 2 bits)

| Bits 7-6 | Meaning | Action |
|----------|---------|--------|
| `00` | Label length (0–63) | Read `len` bytes as label text |
| `11` | Compression pointer | Combine with next byte as 14-bit offset |
| `01` | **Invalid** | Reject — return `None` |
| `10` | **Invalid** | Reject — return `None` |

### Examples

```
\x03www\x07example\x03com\x00          → ["www", "example", "com"], offset=None
\x03www\xc0\x0c                         → ["www"], offset=0x0c
\xc0\x0c                                → [], offset=0x0c
\x00                                    → [], offset=None (root ".")
```

## `parse(buf: &mut SliceBuf) -> Option<DnsLabel>`

Zero-copy parser — borrows label strings directly from the input buffer.

### Algorithm

1. Save buffer position for rollback on failure.
2. Loop: read one byte (`len`).
   - `len == 0` → end of name, break.
   - `len & 0xc0 == 0xc0` → compression pointer. Read second byte, compute 14-bit offset, break.
   - `len & 0xc0 != 0` → **invalid** top-2 bits (`01` or `10`). Rollback, return `None`.
   - Otherwise → label length (guaranteed ≤ 63). Read `len` bytes as a `&str` segment.
3. If the `LabelVec` is full (40 segments), rollback, return `None`.
4. Return `Some(DnsLabel { name, offset })`.

On any failure (truncated data, invalid bits, too many segments), the buffer position is restored to where it was before `parse` was called.

### Rejection cases

| Condition | Behavior |
|-----------|----------|
| Truncated: no bytes left for length byte | `None`, position restored |
| Truncated: length byte says N but < N bytes remain | `None`, position restored |
| Truncated: compression pointer first byte present but second missing | `None`, position restored |
| Invalid top-2 bits (`0x40..0x7f` or `0x80..0xbf`) | `None`, position restored |
| Too many labels (> 40 segments) | `None`, position restored |

### Hardening history

The original parser treated any non-zero top-2 bits as a compression pointer (`if len & 0xc0 > 0`). This meant bytes like `0x40` or `0x80` were misinterpreted as valid pointers rather than rejected. The fix splits the check into:

1. Exact match `len & 0xc0 == 0xc0` for compression pointers.
2. Explicit rejection of `len & 0xc0 != 0` for the remaining invalid bit patterns.

This prevents malformed DNS packets from producing garbage offsets and causing downstream panics (e.g. `DnsLabel::parse().unwrap()` in CNAME/PTR/NS processing — those call sites now use `.ok_or(ARES_EBADRESP)?`).

## `build_string(main_buf: &[u8]) -> Option<String>`

Resolves a `DnsLabel` into a fully-qualified domain name string by:

1. Joining the literal `name` segments with `.` (escaping embedded `.` and `\` characters).
2. If `offset` is set, following the compression pointer chain through `main_buf`.

### Compression pointer resolution

- Reads labels at the pointed-to offset in `main_buf` using the same length-byte rules.
- Follows chains of pointers (pointer → pointer → labels → zero).
- Detects loops via a `HashSet<u16>` of visited offsets — returns `None` on a cycle.
- Applies the same validation: rejects `01`/`10` top-2 bits and labels > 63 bytes.

## Test Coverage

```
test_parse_dns_label                  — basic labels, compression, truncated, max-offset
test_parse_dns_label_invalid_bits     — 0x40, 0x80, 0x7f rejection; valid-then-invalid
test_parse_dns_label_truncated_compression — lone 0xc0 byte
test_parse_dns_label_truncated_label_data  — length exceeds available data
```
