# packet-tracer

An XDP packet classifier in Rust, built on [aya](https://aya-rs.dev).

Filters inbound traffic by source prefix at the earliest point in the Linux
receive path — in the driver, before `sk_buff` allocation — and streams what it
sees to userspace over a BPF ring buffer.

```
$ sudo packet-tracer --iface eth0 \
    --rule '10.77.0.2/32,icmp=drop' \
    --rule '10.77.0.0/24,udp,9999=drop'

[INFO] attached to eth0 (Driver mode), 2 rule(s) installed
DROP icmp   10.77.0.2 -> 10.77.0.1 98 bytes
DROP udp    10.77.0.2:38355 -> 10.77.0.1:9999 44 bytes
[INFO] total=11 pass=8 drop=3 malformed=0 v4=2 v6=5 non-ip=1 lost=0
```

## Layout

| Crate | Target | Role |
| --- | --- | --- |
| `packet-tracer-ebpf` | `bpfel-unknown-none` | The XDP program. `no_std`, nightly, built with `-Z build-std`. |
| `packet-tracer` | host | Loader, CLI, rule compiler, ring buffer consumer. |
| `packet-tracer-common` | both | `repr(C)` types shared across the kernel/userspace boundary. |
| `xtask` | host | Build driver, so the two toolchains stay separate. |

## Build

```sh
cargo install bpf-linker
cargo xtask build-ebpf --release   # nightly, cross-compiles anywhere
cargo build --release              # Linux only — aya links against Linux libc
```

The eBPF object cross-compiles on macOS; the loader does not, because `aya`
needs `SYS_bpf` and netlink from Linux's libc. Development on a Mac means
building the object locally and the loader in a VM.

## Rule syntax

```
<cidr>[,<proto>][,<port>]=<drop|pass>
```

The field separator is a comma, not a colon, because IPv6 literals are full of
colons. A bare address is a host route (`/32` or `/128`). `proto` and `port`
may be given in either order; a port requires a protocol, since the datapath
only reads ports for TCP and UDP.

```
10.0.0.0/8=drop
192.168.1.5/32,tcp,22=drop
2001:db8::/32,udp=drop
```

## Design notes

**Every packet read is bounds-checked.** XDP hands you a raw pointer to a DMA
buffer and the verifier rejects the program unless it can prove statically that
each load lies inside `[data, data_end)`. All frame access goes through one
`ptr_at` helper that performs that comparison; the verifier pattern-matches on
it to mark the pointer safe. The addition is checked as `start + offset + len >
end` rather than `end - len`, because `data_end` can be smaller than `len` for a
runt frame and the subtraction would wrap.

**LPM keys are in network byte order.** The kernel's LPM trie compares keys
most-significant-byte first, and network byte order is already MSB-first, so
address bytes go into the key exactly as they appear on the wire. Storing a
host-order `u32` instead would match correctly on a big-endian machine and
silently match the wrong prefixes on a little-endian one.

**Overlapping prefixes are flattened at load time.** This was a real bug, caught
by running the thing rather than by reading it. An LPM lookup returns only the
*longest* matching prefix, so given

```
--rule '10.77.0.2/32,icmp=drop' --rule '10.77.0.0/24,udp,9999=drop'
```

a UDP packet from `10.77.0.2` matched the `/32` entry, failed its protocol
check, and was passed — the `/24` rule was never consulted. The datapath cannot
walk multiple prefixes, so userspace resolves it instead: each prefix inherits
the rules of every shorter prefix containing it, ordered longest-first, and the
datapath scans that bounded list first-match-wins. One lookup, most-specific
semantics, no extra per-packet cost. Covered by
`specific_prefix_inherits_rules_from_broader_ones` and an e2e regression case.

**Counters are per-CPU.** At XDP rates a contended atomic add across cores costs
more than the parse itself, so each CPU keeps its own `Stats` and userspace sums
them.

**The parser fails open.** A frame that fails a bounds check is counted as
malformed and passed, not dropped. Dropping it would make a parser bug
indistinguishable from a policy decision and turn one bad assumption into an
outage.

**A full ring buffer never blocks the datapath.** If userspace is not draining
fast enough, `reserve` fails, the event is counted in `ringbuf_full`, and the
packet is still classified. Visible as `lost=` in the stats line.

## Limitations

These are design boundaries, not bugs:

- **Source address only.** Rules match on source prefix. Destination matching
  would need a second trie and a policy for combining the two.
- **No IPv6 extension headers.** If one is present, `next_hdr` is the
  extension's number rather than TCP or UDP, so the packet is classified with
  no ports rather than having the extension misread as a port.
- **Fragments after the first have no ports.** Only the first fragment carries
  the L4 header; later ones are matched on address and protocol alone.
- **At most 8 rules per prefix** (`MAX_RULES_PER_PREFIX`), counting inherited
  ones. Exceeding it is a load-time error rather than a silent truncation.
- **Rules are fixed at load time.** The maps support update, but no control
  socket is wired up, so changing policy means a restart. `--trace-all` is the
  one knob that is runtime-writable, via the `CONFIG` array.
- **Tested on veth, not on a physical NIC.** veth is what can be created and
  torn down deterministically. Both the generic/SKB path and native driver XDP
  are exercised, but behaviour on a real driver's XDP implementation is
  untested.

## Testing

```sh
cargo test --release           # parser, rule flattening, struct layout
sudo ./scripts/e2e-test.sh     # against a real kernel
```

The e2e script builds a veth pair with one end in a network namespace, attaches
the program to the host end, and asserts reachability for each policy. It
covers the baseline (no rules passes traffic — if that fails every other result
is meaningless), prefix and host matching, protocol constraints, longest-prefix
precedence, the shadowing regression above, and native driver mode.

Last run, Ubuntu 24.04, kernel 6.8.0-45-generic, aarch64:

```
passed: 11   failed: 0
```

Unit tests: 16 passed.

## Dependency pinning

`aya` is pinned to a released version rather than tracking git HEAD. The crate
renamed `Bpf` to `Ebpf` in 0.13 and `XdpFlags` to `XdpMode` by 0.14; a floating
git dependency turns each of those into a build break at an arbitrary time.
