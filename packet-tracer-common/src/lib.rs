#![no_std]

//! Types shared between the XDP program and the userspace loader.
//!
//! Every type here crosses the kernel/userspace boundary through a BPF map, so
//! each one is `#[repr(C)]` with explicit padding. The kernel copies these
//! structs by value and does not know or care about Rust's layout rules, so a
//! `#[repr(Rust)]` type here would be a silent corruption bug the first time
//! rustc decided to reorder a field.

pub const ACTION_PASS: u8 = 0;
pub const ACTION_DROP: u8 = 1;

/// Wildcard for [`Rule::proto`] — match any L4 protocol.
pub const PROTO_ANY: u8 = 0;
/// Wildcard for [`Rule::port`] — match any destination port.
pub const PORT_ANY: u16 = 0;

/// A match rule, stored as the value of an LPM trie keyed on source address.
///
/// The trie handles the address prefix; `proto` and `port` are additional
/// constraints applied after the longest-prefix hit. A rule only fires when
/// all three match, so `10.0.0.0/8` + `tcp` + `22` means "SSH from the 10 net",
/// not "anything from the 10 net".
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Rule {
    /// [`ACTION_PASS`] or [`ACTION_DROP`].
    pub action: u8,
    /// IANA protocol number, or [`PROTO_ANY`].
    pub proto: u8,
    /// Destination port in host byte order, or [`PORT_ANY`].
    pub port: u16,
    /// Explicit tail padding to 8 bytes. Named rather than implicit so that
    /// userspace and kernel agree byte-for-byte, and so `Pod` is sound.
    pub _pad: u32,
}

impl Rule {
    pub const fn new(action: u8, proto: u8, port: u16) -> Self {
        Self {
            action,
            proto,
            port,
            _pad: 0,
        }
    }
}

/// Maximum rules attached to a single prefix.
///
/// Bounds the datapath scan so the verifier can unroll it. Eight is a
/// judgement call: large enough for realistic per-host policies, small enough
/// that the worst-case scan stays cheap at line rate.
pub const MAX_RULES_PER_PREFIX: usize = 8;

/// All rules that apply to one prefix, in priority order.
///
/// An LPM trie yields only the single longest matching prefix, so a `/32`
/// entry would otherwise shadow every `/24` rule covering the same address.
/// Rather than walk multiple prefixes on the datapath — which LPM cannot do —
/// userspace flattens the overlap at load time: each prefix carries its own
/// rules followed by the rules of every shorter prefix that contains it,
/// longest-first. One lookup then sees everything that could match.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleSet {
    /// Number of valid entries in `rules`.
    pub len: u32,
    pub rules: [Rule; MAX_RULES_PER_PREFIX],
}

impl RuleSet {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            rules: [Rule::new(ACTION_PASS, PROTO_ANY, PORT_ANY); MAX_RULES_PER_PREFIX],
        }
    }

    /// Append a rule. Returns `false` if the set is full.
    pub fn push(&mut self, rule: Rule) -> bool {
        if (self.len as usize) >= MAX_RULES_PER_PREFIX {
            return false;
        }
        self.rules[self.len as usize] = rule;
        self.len += 1;
        true
    }
}

impl Default for RuleSet {
    fn default() -> Self {
        Self::empty()
    }
}

/// Runtime knobs, held in a single-entry array map so userspace can change
/// behaviour without detaching and reloading the program.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Config {
    /// When non-zero, emit a trace event for passed packets too, not just drops.
    pub trace_all: u8,
    pub _pad: [u8; 7],
}

/// One parsed packet, pushed to userspace over a ring buffer.
///
/// Addresses are always carried as 16 bytes; IPv4 occupies the first 4 and
/// `is_ipv6` says how to read them. A union would save 12 bytes per event but
/// buys nothing: the ring buffer reserves in 8-byte-aligned chunks anyway, and
/// a fixed layout is far easier to get right on both sides of the boundary.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct Event {
    /// Source address in network byte order.
    pub src: [u8; 16],
    /// Destination address in network byte order.
    pub dst: [u8; 16],
    /// Source port, host byte order. Zero for non-TCP/UDP.
    pub src_port: u16,
    /// Destination port, host byte order. Zero for non-TCP/UDP.
    pub dst_port: u16,
    /// Total frame length on the wire.
    pub len: u16,
    /// IANA protocol number from the IP header.
    pub proto: u8,
    /// The verdict this program returned.
    pub action: u8,
    /// 1 if `src`/`dst` are IPv6, 0 if IPv4.
    pub is_ipv6: u8,
    /// Number of VLAN tags stripped while parsing.
    pub vlan_depth: u8,
    pub _pad: [u8; 2],
}

/// Per-CPU counters. Summed across CPUs by userspace before display.
///
/// Per-CPU rather than a shared counter specifically to avoid atomics on the
/// datapath: at XDP speeds a contended `__sync_fetch_and_add` across cores
/// costs more than the parse itself.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Stats {
    pub total: u64,
    pub passed: u64,
    pub dropped: u64,
    /// Frames that failed a bounds check — truncated, or not what the
    /// ethertype claimed.
    pub malformed: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    /// Frames that were neither IPv4 nor IPv6 (ARP, LLDP, ...).
    pub non_ip: u64,
    /// Events dropped because the ring buffer was full.
    pub ringbuf_full: u64,
}

#[cfg(feature = "user")]
mod user {
    use super::{Config, Event, Rule, RuleSet, Stats};

    // SAFETY: all five are `#[repr(C)]`, contain no padding that is not an
    // explicit named field, have no pointers, and are valid for any bit
    // pattern. That is exactly aya's `Pod` contract.
    unsafe impl aya::Pod for Rule {}
    unsafe impl aya::Pod for RuleSet {}
    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for Event {}
    unsafe impl aya::Pod for Stats {}
}
