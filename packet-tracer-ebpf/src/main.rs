#![no_std]
#![no_main]

//! An XDP packet classifier.
//!
//! Runs at the earliest point in the receive path — before `sk_buff`
//! allocation — so everything here is a raw pointer walk over the DMA'd frame
//! with no kernel help. The verifier will reject the program unless it can
//! prove statically that every single load lies inside `[data, data_end)`,
//! which is what [`ptr_at`] exists to establish.

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LpmTrie, PerCpuArray, RingBuf, lpm_trie::Key},
    programs::XdpContext,
};
use packet_tracer_common::{
    ACTION_DROP, ACTION_PASS, Config, Event, MAX_RULES_PER_PREFIX, PORT_ANY, PROTO_ANY, Rule,
    RuleSet, Stats,
};

// --- wire format -----------------------------------------------------------
//
// Hand-rolled rather than pulled from a crate: these layouts have been stable
// since the 1980s, and writing them out keeps the offset arithmetic below
// auditable against the RFCs instead of against someone else's generated
// bindings.

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[repr(C)]
struct EthHdr {
    dst: [u8; 6],
    src: [u8; 6],
    ether_type: u16, // big-endian
}

/// An 802.1Q/802.1ad tag as it appears *after* the ethertype that introduced
/// it: 2 bytes of TCI followed by the next ethertype. Four bytes total.
#[repr(C)]
struct VlanHdr {
    tci: u16,
    ether_type: u16, // big-endian
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16, // big-endian; low 13 bits are the fragment offset
    ttl: u8,
    proto: u8,
    check: u16,
    saddr: [u8; 4],
    daddr: [u8; 4],
}

#[repr(C)]
struct Ipv6Hdr {
    version_tc_flow: u32,
    payload_len: u16,
    next_hdr: u8,
    hop_limit: u8,
    saddr: [u8; 16],
    daddr: [u8; 16],
}

/// TCP and UDP both begin with source port then destination port, so four
/// bytes is all we need and one struct covers both.
#[repr(C)]
struct L4Ports {
    source: u16, // big-endian
    dest: u16,   // big-endian
}

/// Bound on stacked VLAN tags. The verifier needs every loop to terminate in a
/// provable number of steps; at `opt-level = 3` LLVM fully unrolls this, so the
/// emitted bytecode contains no backward branch at all.
const MAX_VLAN_DEPTH: usize = 2;

// --- maps ------------------------------------------------------------------

/// Source-prefix rules for IPv4. The key is the raw 4-byte address straight
/// out of the header; the value is every rule that can apply to that prefix,
/// already flattened by userspace. See [`RuleSet`].
#[map]
static RULES_V4: LpmTrie<[u8; 4], RuleSet> = LpmTrie::with_max_entries(1024, 0);

/// Source-prefix rules for IPv6.
#[map]
static RULES_V6: LpmTrie<[u8; 16], RuleSet> = LpmTrie::with_max_entries(1024, 0);

/// Single-entry config, writable from userspace at runtime.
#[map]
static CONFIG: Array<Config> = Array::with_max_entries(1, 0);

/// Per-CPU counters — no atomics on the datapath.
#[map]
static STATS: PerCpuArray<Stats> = PerCpuArray::with_max_entries(1, 0);

/// Trace events to userspace. 256 KiB: a power-of-two multiple of the page
/// size, as the kernel requires.
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// --- helpers ---------------------------------------------------------------

/// Return a pointer to a `T` at `offset` bytes into the frame, having proven
/// to the verifier that the whole `T` fits before `data_end`.
///
/// This is the only way any byte of packet memory is read. The comparison is
/// what the verifier pattern-matches on to mark the pointer safe; remove it and
/// the program is rejected at load time with "invalid access to packet".
///
/// The addition is done in `usize` and checked against `end` rather than
/// computing `end - len`, because `data_end` can legitimately be less than
/// `len` for a runt frame and the subtraction would wrap.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

/// Load a `T` from the frame. Same contract as [`ptr_at`].
#[inline(always)]
unsafe fn load_at<T>(ctx: &XdpContext, offset: usize) -> Option<T> {
    ptr_at::<T>(ctx, offset).map(|p| p.read_unaligned())
}

#[inline(always)]
fn stats_mut() -> Option<&'static mut Stats> {
    // SAFETY: single-entry per-CPU map, and XDP programs on a given CPU do not
    // preempt one another, so this &mut is not aliased.
    unsafe { STATS.get_ptr_mut(0).map(|p| &mut *p) }
}

/// Apply a rule's non-address constraints.
#[inline(always)]
fn rule_matches(rule: &Rule, proto: u8, dst_port: u16) -> bool {
    (rule.proto == PROTO_ANY || rule.proto == proto)
        && (rule.port == PORT_ANY || rule.port == dst_port)
}

/// Scan a prefix's rules in priority order and return the first verdict.
///
/// Userspace guarantees the ordering: rules written for this exact prefix
/// first, then those inherited from shorter prefixes, longest-first. So "first
/// match wins" here yields "most specific rule wins" overall.
///
/// The loop bound is a compile-time constant and `len` is checked against it,
/// which is what lets the verifier accept the indexing. At `opt-level = 3`
/// LLVM unrolls it completely.
#[inline(always)]
fn first_match(set: &RuleSet, proto: u8, dst_port: u16) -> u8 {
    let len = set.len as usize;
    for i in 0..MAX_RULES_PER_PREFIX {
        if i >= len {
            break;
        }
        let rule = &set.rules[i];
        if rule_matches(rule, proto, dst_port) {
            return rule.action;
        }
    }
    ACTION_PASS
}

// --- parse -----------------------------------------------------------------

/// What the parser extracted from one frame.
struct Parsed {
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    proto: u8,
    is_ipv6: bool,
    vlan_depth: u8,
}

enum Verdict {
    /// Not IP at all — ARP, LLDP, and friends.
    NonIp,
    /// Truncated, or the ethertype lied.
    Malformed,
    Ip(Parsed),
}

#[inline(always)]
fn parse(ctx: &XdpContext) -> Verdict {
    let eth: EthHdr = match unsafe { load_at(ctx, 0) } {
        Some(h) => h,
        None => return Verdict::Malformed,
    };

    let mut ether_type = u16::from_be(eth.ether_type);
    let mut l3_off = mem::size_of::<EthHdr>();
    let mut vlan_depth: u8 = 0;

    // Walk off any stacked VLAN tags to find the real ethertype.
    for _ in 0..MAX_VLAN_DEPTH {
        if ether_type != ETH_P_8021Q && ether_type != ETH_P_8021AD {
            break;
        }
        let vlan: VlanHdr = match unsafe { load_at(ctx, l3_off) } {
            Some(v) => v,
            None => return Verdict::Malformed,
        };
        ether_type = u16::from_be(vlan.ether_type);
        l3_off += mem::size_of::<VlanHdr>();
        vlan_depth += 1;
    }

    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    let proto;
    let l4_off;
    let is_ipv6;
    // True when the L4 header is not in this frame and ports are unavailable.
    let mut ports_absent = false;

    match ether_type {
        ETH_P_IP => {
            let ip: Ipv4Hdr = match unsafe { load_at(ctx, l3_off) } {
                Some(h) => h,
                None => return Verdict::Malformed,
            };

            // IHL is in 32-bit words and includes the fixed 20 bytes, so
            // anything below 5 is a malformed header. Bounding it above by 15
            // (the field is 4 bits, but say so explicitly) keeps the offset
            // arithmetic in a range the verifier can track.
            let ihl = (ip.version_ihl & 0x0f) as usize;
            if !(5..=15).contains(&ihl) {
                return Verdict::Malformed;
            }

            // Only the first fragment carries the L4 header. Later fragments
            // have a non-zero offset in the low 13 bits and must not have
            // their payload read as ports.
            if u16::from_be(ip.frag_off) & 0x1fff != 0 {
                ports_absent = true;
            }

            src[..4].copy_from_slice(&ip.saddr);
            dst[..4].copy_from_slice(&ip.daddr);
            proto = ip.proto;
            l4_off = l3_off + ihl * 4;
            is_ipv6 = false;
        }
        ETH_P_IPV6 => {
            let ip: Ipv6Hdr = match unsafe { load_at(ctx, l3_off) } {
                Some(h) => h,
                None => return Verdict::Malformed,
            };

            src.copy_from_slice(&ip.saddr);
            dst.copy_from_slice(&ip.daddr);
            // Extension headers are not walked: if one is present, `next_hdr`
            // is the extension's number rather than TCP/UDP, so the port read
            // below is simply skipped. Treating that as "no ports" is honest;
            // silently reading the extension header as a port would not be.
            proto = ip.next_hdr;
            l4_off = l3_off + mem::size_of::<Ipv6Hdr>();
            is_ipv6 = true;
        }
        _ => return Verdict::NonIp,
    }

    let (src_port, dst_port) = if !ports_absent && (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
        match unsafe { load_at::<L4Ports>(ctx, l4_off) } {
            Some(p) => (u16::from_be(p.source), u16::from_be(p.dest)),
            // The IP header claimed TCP/UDP but the frame is too short to hold
            // the ports. That is a malformed packet, not a portless one.
            None => return Verdict::Malformed,
        }
    } else {
        (0, 0)
    };

    Verdict::Ip(Parsed {
        src,
        dst,
        src_port,
        dst_port,
        proto,
        is_ipv6,
        vlan_depth,
    })
}

// --- entry point -----------------------------------------------------------

#[xdp]
pub fn packet_tracer(ctx: XdpContext) -> u32 {
    let stats = match stats_mut() {
        Some(s) => s,
        // The stats map is statically sized at 1 entry, so index 0 is always
        // present and this is unreachable in practice. Pass rather than abort:
        // a counter failure is not a reason to start eating traffic.
        None => return xdp_action::XDP_PASS,
    };

    stats.total += 1;

    let parsed = match parse(&ctx) {
        Verdict::NonIp => {
            stats.non_ip += 1;
            stats.passed += 1;
            return xdp_action::XDP_PASS;
        }
        Verdict::Malformed => {
            stats.malformed += 1;
            // Fail open. Dropping anything we failed to parse would make a
            // parser bug indistinguishable from a policy decision, and would
            // turn one bad assumption into an outage.
            stats.passed += 1;
            return xdp_action::XDP_PASS;
        }
        Verdict::Ip(p) => p,
    };

    if parsed.is_ipv6 {
        stats.ipv6 += 1;
    } else {
        stats.ipv4 += 1;
    }

    // Longest-prefix match on the source address.
    //
    // The address bytes go into the key exactly as they appear on the wire.
    // The kernel's LPM trie compares keys MSB-first, and network byte order is
    // already MSB-first, so a /8 of 10.0.0.0 matches on the first byte as
    // intended. Storing a host-order u32 here would work on a big-endian box
    // and silently match the wrong prefixes on a little-endian one.
    // Queried at full length; the trie returns the longest prefix that
    // matches. Userspace has already folded shorter overlapping prefixes into
    // that entry, so a single lookup is sufficient.
    let hit = if parsed.is_ipv6 {
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&parsed.src);
        RULES_V6.get(&Key::new(128, addr)).copied()
    } else {
        let mut addr = [0u8; 4];
        addr.copy_from_slice(&parsed.src[..4]);
        RULES_V4.get(&Key::new(32, addr)).copied()
    };

    let action = match hit {
        Some(set) => first_match(&set, parsed.proto, parsed.dst_port),
        None => ACTION_PASS,
    };

    if action == ACTION_DROP {
        stats.dropped += 1;
    } else {
        stats.passed += 1;
    }

    let trace_all = CONFIG.get(0).map(|c| c.trace_all != 0).unwrap_or(false);
    if action == ACTION_DROP || trace_all {
        emit(&ctx, &parsed, action, stats);
    }

    if action == ACTION_DROP {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    }
}

/// Push a trace event, reserving in place so the event is never built on the
/// stack first. eBPF gives us 512 bytes of stack total and `Event` is 48 of
/// them; reserving avoids spending that budget twice.
#[inline(always)]
fn emit(ctx: &XdpContext, parsed: &Parsed, action: u8, stats: &mut Stats) {
    let mut entry = match EVENTS.reserve::<Event>(0) {
        Some(e) => e,
        None => {
            // Ring buffer full: userspace is not draining fast enough. Count it
            // and move on — the datapath must not block on a consumer.
            stats.ringbuf_full += 1;
            return;
        }
    };

    let len = (ctx.data_end() - ctx.data()) as u16;

    entry.write(Event {
        src: parsed.src,
        dst: parsed.dst,
        src_port: parsed.src_port,
        dst_port: parsed.dst_port,
        len,
        proto: parsed.proto,
        action,
        is_ipv6: parsed.is_ipv6 as u8,
        vlan_depth: parsed.vlan_depth,
        _pad: [0; 2],
    });
    entry.submit(0);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // Unreachable: this crate is `no_std` with `panic = "abort"`, and the
    // verifier rejects any program containing a real panic path. `loop {}` is
    // the conventional terminator and costs nothing, since no call site exists.
    loop {}
}
